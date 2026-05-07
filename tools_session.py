"""Session-level MCP tools."""

from __future__ import annotations

from typing import Any

from config import DEFAULT_TIMEOUT, GDB_PATH
from models import make_result
from server_runtime import brief_command_result, controller, exec_cli_internal, mcp
from utils import gdb_quote, parse_info_files, resolve_path


@mcp.tool()
def gdb_session(
    action: str,
    gdb_path: str | None = None,
    workdir: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Start, stop, restart, or inspect the current GDB session."""

    try:
        action_l = action.lower()
        if action_l == "start":
            data = controller.start(gdb_path=gdb_path or GDB_PATH, workdir=workdir, extra_args=extra_args)
        elif action_l == "stop":
            data = controller.stop()
        elif action_l == "restart":
            data = controller.restart(gdb_path=gdb_path or GDB_PATH, workdir=workdir, extra_args=extra_args)
        elif action_l == "status":
            data = controller.status()
        else:
            return make_result(ok=False, tool="gdb_session", action=action, error=f"unsupported action: {action}")
        return make_result(ok=not data.get("error"), tool="gdb_session", action=action_l, data=data, error=data.get("error"))
    except Exception as exc:
        return make_result(ok=False, tool="gdb_session", action=action, error=str(exc))


@mcp.tool()
def gdb_load(
    binary: str | None = None,
    core: str | None = None,
    symbol_file: str | None = None,
    args: list[str] | None = None,
) -> dict[str, Any]:
    """Load a binary, core file, symbol file, and optional program arguments."""

    try:
        controller.start()
        workdir = controller.workdir or __import__("os").getcwd()
        commands: list[str] = []
        executed: list[dict[str, Any]] = []
        if binary:
            binary = resolve_path(binary, workdir)
            commands.append(f"file {controller.quote_gdb_path(binary)}")
        if symbol_file:
            symbol_file = resolve_path(symbol_file, workdir)
            commands.append(f"symbol-file {controller.quote_gdb_path(symbol_file)}")
        if core:
            core = resolve_path(core, workdir)
            commands.append(f"core-file {controller.quote_gdb_path(core)}")
        if args is not None:
            commands.append("set args " + " ".join(gdb_quote(str(arg)) for arg in args))

        for command in commands:
            res = exec_cli_internal(command, timeout=DEFAULT_TIMEOUT, parse=True)
            executed.append(brief_command_result(res))
            if command.startswith("file ") and res.ok:
                controller.current_binary = binary
            if command.startswith("core-file ") and res.ok:
                controller.current_core = core
            if command.startswith("symbol-file ") and res.ok:
                controller.current_symbol_file = symbol_file

        files = exec_cli_internal("info files", parse=True)
        arch = exec_cli_internal("show architecture", parse=False)
        file_info = files.data.get("files", parse_info_files(files.stdout)) if files.data else parse_info_files(files.stdout)
        data = {
            "status": controller.status(),
            "executed": executed,
            "file_info": file_info,
            "architecture": arch.stdout.strip(),
        }
        return make_result(
            ok=all(item["ok"] for item in executed) if executed else True,
            tool="gdb_load",
            action="load",
            data=data,
            stdout=files.stdout,
            stderr=files.stderr,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_load", action="load", error=str(exc))
