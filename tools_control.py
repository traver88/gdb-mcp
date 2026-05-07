"""Register, breakpoint, and run-control MCP tools."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from config import DEFAULT_TIMEOUT, MAX_STEP_COUNT
from models import make_result
from safety import assess_gdb_command, assess_register_action, assess_run_control
from server_runtime import (
    command_result_to_tool_result,
    context_summary,
    controller,
    ensure_mutation_allowed,
    exec_cli_internal,
    mcp,
    risk_gate,
)
from utils import gdb_quote
from tools_remote import gdb_context


@mcp.tool()
def gdb_register(
    action: str,
    name: str | None = None,
    value: str | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """Read all registers, read one register, or write one register."""

    try:
        action_l = action.lower()
        if action_l == "write":
            blocked = ensure_mutation_allowed("gdb_register", action_l)
            if blocked:
                return blocked
        assessment = assess_register_action(action_l)
        gated = risk_gate(tool="gdb_register", action=action_l, command=f"register {action_l} {name or ''}", assessment=assessment, confirm=confirm)
        if gated:
            return gated
        if action_l == "read_all":
            res = exec_cli_internal("info registers", parse=True)
            return command_result_to_tool_result(tool="gdb_register", action=action_l, command="info registers", result=res, assessment=assessment, confirmed=confirm)
        if action_l == "read":
            if not name:
                return make_result(ok=False, tool="gdb_register", action=action_l, error="name is required")
            command = f"p/x ${name}"
            res = exec_cli_internal(command, parse=False)
            return command_result_to_tool_result(tool="gdb_register", action=action_l, command=command, result=res, assessment=assessment, confirmed=confirm)
        if action_l == "write":
            if not name or value is None:
                return make_result(ok=False, tool="gdb_register", action=action_l, error="name and value are required")
            before = gdb_register(action="read", name=name)
            command = f"set ${name}={value}"
            res = exec_cli_internal(command, parse=False)
            after = gdb_register(action="read", name=name)
            res.data = {"before": before.get("stdout"), "after": after.get("stdout")}
            return command_result_to_tool_result(tool="gdb_register", action=action_l, command=command, result=res, assessment=assessment, confirmed=confirm)
        return make_result(ok=False, tool="gdb_register", action=action_l, error=f"unsupported action: {action}")
    except Exception as exc:
        return make_result(ok=False, tool="gdb_register", action=action, error=str(exc))


@mcp.tool()
def gdb_breakpoint(
    action: str,
    location: str | None = None,
    number: int | None = None,
    condition: str | None = None,
    temporary: bool = False,
    hardware: bool = False,
    watch_expr: str | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """Add, delete, enable, disable, list, condition, or clear breakpoints/watchpoints."""

    try:
        action_l = action.lower()
        if action_l in {"add", "delete", "enable", "disable", "condition", "clear", "watch", "rwatch", "awatch"}:
            blocked = ensure_mutation_allowed("gdb_breakpoint", action_l)
            if blocked:
                return blocked
        if action_l == "list":
            command = "info breakpoints"
        elif action_l == "add":
            if not location:
                return make_result(ok=False, tool="gdb_breakpoint", action=action_l, error="location is required")
            if location.startswith(("watch ", "rwatch ", "awatch ")):
                command = location
            elif location.startswith(("watch:", "rwatch:", "awatch:")):
                kind, expr = location.split(":", 1)
                command = f"{kind} {expr}"
            else:
                command = ("hbreak" if hardware else "tbreak" if temporary else "break") + f" {location}"
            if condition:
                command += f" if {condition}"
        elif action_l in {"watch", "rwatch", "awatch"}:
            expr = watch_expr or location
            if not expr:
                return make_result(ok=False, tool="gdb_breakpoint", action=action_l, error="watch_expr or location is required")
            command = f"{action_l} {expr}"
            if condition:
                command += f" if {condition}"
        elif action_l in {"delete", "enable", "disable"}:
            if number is None:
                return make_result(ok=False, tool="gdb_breakpoint", action=action_l, error="number is required")
            command = f"{action_l} {number}"
        elif action_l == "condition":
            if number is None or condition is None:
                return make_result(ok=False, tool="gdb_breakpoint", action=action_l, error="number and condition are required")
            command = f"condition {number} {condition}"
        elif action_l == "clear":
            command = f"clear {location}" if location else f"delete {number}" if number is not None else "delete"
        else:
            return make_result(ok=False, tool="gdb_breakpoint", action=action_l, error=f"unsupported action: {action}")
        assessment = assess_gdb_command(command)
        gated = risk_gate(tool="gdb_breakpoint", action=action_l, command=command, assessment=assessment, confirm=confirm)
        if gated:
            return gated
        res = exec_cli_internal(command, parse=True)
        return command_result_to_tool_result(tool="gdb_breakpoint", action=action_l, command=command, result=res, assessment=assessment, confirmed=confirm)
    except Exception as exc:
        return make_result(ok=False, tool="gdb_breakpoint", action=action, error=str(exc))


@mcp.tool()
def gdb_run_control(
    action: str,
    count: int = 1,
    args: list[str] | None = None,
    stdin: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    confirm: bool = False,
) -> dict[str, Any]:
    """Run, continue, step, next, stepi, nexti, finish, until, interrupt, kill, or restart."""

    try:
        action_l = action.lower()
        count = int(count)
        if action_l in {"run", "continue", "step", "next", "stepi", "nexti", "finish", "until", "kill", "restart"}:
            blocked = ensure_mutation_allowed("gdb_run_control", action_l)
            if blocked:
                return blocked
        assessment = assess_run_control(action_l, count)
        gated = risk_gate(
            tool="gdb_run_control",
            action=action_l,
            command=f"run_control {action_l} count={count}",
            assessment=assessment,
            confirm=confirm,
            suggested_extra={"action": action_l, "count": count},
        )
        if gated:
            return gated
        if count > MAX_STEP_COUNT and not confirm:
            count = MAX_STEP_COUNT

        if args is not None:
            exec_cli_internal("set args " + " ".join(gdb_quote(str(arg)) for arg in args), parse=False)

        remote = controller.remote_status()
        if remote.get("connected") and action_l == "run" and remote.get("mode") == "remote":
            return make_result(
                ok=False,
                tool="gdb_run_control",
                action=action_l,
                data={"remote_status": remote},
                error="run is usually unavailable with target remote; use continue or extended-remote with remote_binary",
            )
        if remote.get("connected") and action_l == "run" and remote.get("mode") == "extended-remote" and not remote.get("remote_binary"):
            return make_result(
                ok=False,
                tool="gdb_run_control",
                action=action_l,
                data={"remote_status": remote},
                error="extended-remote run requires remote_binary / set remote exec-file",
            )

        command_map = {
            "run": "run",
            "continue": "continue",
            "step": "step",
            "next": "next",
            "stepi": "stepi",
            "nexti": "nexti",
            "finish": "finish",
            "until": "until",
            "interrupt": "interrupt",
            "kill": "kill",
        }
        outputs: list[dict[str, Any]] = []
        temp_stdin_path: str | None = None
        if action_l == "restart":
            for command in ("kill", "run"):
                res = exec_cli_internal(command, timeout=timeout, parse=True)
                outputs.append({"command": res.command, "ok": res.ok, "stdout": res.stdout, "stderr": res.stderr, "error": res.error, "timeout": res.timeout})
        else:
            command = command_map.get(action_l)
            if not command:
                return make_result(ok=False, tool="gdb_run_control", action=action_l, error=f"unsupported action: {action}")
            if action_l == "run" and stdin is not None:
                fd, stdin_path = tempfile.mkstemp(prefix="gdb_mcp_stdin_", text=True)
                temp_stdin_path = stdin_path
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(stdin)
                command = f"run < {gdb_quote(stdin_path)}"
            repeat = max(1, count if action_l in {"step", "next", "stepi", "nexti"} else 1)
            for _ in range(repeat):
                res = exec_cli_internal(command, timeout=timeout, parse=True)
                outputs.append({"command": res.command, "ok": res.ok, "stdout": res.stdout, "stderr": res.stderr, "error": res.error, "timeout": res.timeout})
                if not res.ok:
                    break
        if temp_stdin_path:
            try:
                Path(temp_stdin_path).unlink(missing_ok=True)
            except Exception:
                pass
        context = gdb_context(depth=12)
        ok = all(item["ok"] for item in outputs)
        return make_result(
            ok=ok,
            tool="gdb_run_control",
            action=action_l,
            risk_level=assessment.level,
            executed_with_risk=assessment.requires_confirmation and confirm,
            warning=assessment.warning if assessment.requires_confirmation and confirm else None,
            data={"executed": outputs, "context_summary": context_summary(context)},
            error=None if ok else "one or more run-control commands failed",
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_run_control", action=action, error=str(exc))
