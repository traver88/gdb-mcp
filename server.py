"""MCP server exposing high-permission GDB automation tools."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except Exception as exc:  # pragma: no cover - import failure is reported at runtime
    raise RuntimeError("mcp Python SDK is required. Install with: pip install mcp") from exc

from config import (
    DEFAULT_REMOTE_TIMEOUT,
    DEFAULT_TIMEOUT,
    ENABLE_PWNDBG_COMMANDS,
    ENABLE_RAW_GDB_EXEC,
    ENABLE_RAW_GDB_MI,
    GDB_PATH,
    MAX_MEMORY_DUMP_WITHOUT_CONFIRM,
    MAX_MEMORY_READ,
    MAX_MEMORY_WRITE,
    MAX_STEP_COUNT,
    REMOTE_DEBUG_ENABLED,
)
from gdb_controller import CommandResult, GdbController
from models import RiskAssessment, confirmation_required_result, make_result
from safety import (
    assess_elf_action,
    assess_gdb_command,
    assess_memory_action,
    assess_mi_command,
    assess_register_action,
    assess_run_control,
    max_write_size_exceeded,
)
from utils import (
    ascii_preview,
    bytes_from_xb_output,
    gdb_quote,
    quote_gdb_path,
    parse_backtrace,
    parse_breakpoints,
    parse_cli_common,
    parse_disassembly,
    parse_info_files,
    parse_int_expression,
    parse_memory_examine,
    parse_registers,
    parse_hex_bytes,
    resolve_path,
    run_host_command,
)

mcp = FastMCP("gdb-mcp")
controller = GdbController()


def _risk_gate(
    *,
    tool: str,
    action: str | None,
    command: str,
    assessment: RiskAssessment,
    confirm: bool,
    suggested_extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if assessment.requires_confirmation and not confirm:
        return confirmation_required_result(
            tool=tool,
            action=action,
            command=command,
            assessment=assessment,
            suggested_extra=suggested_extra,
        )
    return None


def _command_result_to_tool_result(
    *,
    tool: str,
    action: str | None,
    command: str,
    result: CommandResult,
    assessment: RiskAssessment,
    confirmed: bool,
) -> dict[str, Any]:
    return make_result(
        ok=result.ok,
        tool=tool,
        action=action,
        risk_level=assessment.level,
        need_confirm=False,
        executed_with_risk=assessment.requires_confirmation and confirmed,
        warning=assessment.warning if assessment.requires_confirmation and confirmed else None,
        data=result.data,
        stdout=result.stdout,
        stderr=result.stderr,
        raw=result.raw,
        error=result.error,
    ) | {"command": command}


def _exec_cli_internal(command: str, timeout: int = DEFAULT_TIMEOUT, parse: bool = True) -> CommandResult:
    return controller.execute_cli(command, timeout=timeout, parse=parse)


def _availability(result: CommandResult, value: Any) -> dict[str, Any]:
    return {
        "available": result.ok,
        "data": value if result.ok else None,
        "error": None if result.ok else result.error,
        "stdout": result.stdout,
    }


def _max_assessment(assessments: list[RiskAssessment]) -> RiskAssessment:
    """Return the highest-risk assessment from a list."""

    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return max(assessments, key=lambda item: rank[item.level], default=RiskAssessment())


def _brief_command_result(result: CommandResult) -> dict[str, Any]:
    """Convert a controller command result into compact JSON data."""

    return {
        "command": result.command,
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": result.error,
        "timeout": result.timeout,
    }


def _replace_result_data(result: CommandResult, command: str, data: dict[str, Any]) -> CommandResult:
    """Reuse a command result while replacing its structured data payload."""

    return CommandResult(
        ok=result.ok,
        command=command,
        stdout=result.stdout,
        stderr=result.stderr,
        raw=result.raw,
        data=data,
        error=result.error,
        timeout=result.timeout,
    )


def _context_summary(context: dict[str, Any]) -> dict[str, Any]:
    data = context.get("data", {})
    registers = data.get("registers", {})
    interesting = {
        name: registers[name]
        for name in ("rip", "eip", "pc", "rsp", "esp", "rbp", "ebp")
        if name in registers
    }
    backtrace = data.get("backtrace") or {}
    backtrace_data = backtrace.get("data", []) if isinstance(backtrace, dict) else backtrace
    return {
        "remote": data.get("remote"),
        "pc": data.get("pc"),
        "sp": data.get("sp"),
        "current_instruction": data.get("current_instruction"),
        "registers": interesting,
        "backtrace_top": (backtrace_data or [])[:3],
    }


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
        return make_result(
            ok=not data.get("error"),
            tool="gdb_session",
            action=action_l,
            data=data,
            error=data.get("error"),
        )
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
        workdir = controller.workdir or os.getcwd()
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
            res = _exec_cli_internal(command, timeout=DEFAULT_TIMEOUT, parse=True)
            executed.append(_brief_command_result(res))
            if command.startswith("file ") and res.ok:
                controller.current_binary = binary
            if command.startswith("core-file ") and res.ok:
                controller.current_core = core
            if command.startswith("symbol-file ") and res.ok:
                controller.current_symbol_file = symbol_file

        files = _exec_cli_internal("info files", parse=True)
        arch = _exec_cli_internal("show architecture", parse=False)
        checksec = (
            gdb_elf(action="checksec", path=binary)
            if binary
            else make_result(
                ok=False,
                tool="gdb_elf",
                action="checksec",
                error="no binary",
            )
        )
        file_info = (
            files.data.get("files", parse_info_files(files.stdout))
            if files.data
            else parse_info_files(files.stdout)
        )
        data = {
            "status": controller.status(),
            "executed": executed,
            "file_info": file_info,
            "architecture": arch.stdout.strip(),
            "checksec": checksec.get("data", {}),
        }
        return make_result(
            ok=all(item["ok"] for item in executed),
            tool="gdb_load",
            action="load",
            data=data,
            stdout=files.stdout,
            stderr=files.stderr,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_load", action="load", error=str(exc))


@mcp.tool()
def gdb_exec(command: str, confirm: bool = False, timeout: int = DEFAULT_TIMEOUT, parse: bool = True) -> dict[str, Any]:
    """Execute an arbitrary GDB CLI command with warning-and-confirm risk handling."""

    if not ENABLE_RAW_GDB_EXEC:
        return make_result(
            ok=False,
            tool="gdb_exec",
            action="exec",
            error="raw GDB CLI execution is disabled",
        ) | {"command": command}
    try:
        assessment = assess_gdb_command(command)
        gated = _risk_gate(tool="gdb_exec", action="exec", command=command, assessment=assessment, confirm=confirm)
        if gated:
            return gated
        result = controller.execute_cli(command, timeout=timeout, parse=parse)
        return _command_result_to_tool_result(
            tool="gdb_exec",
            action="exec",
            command=command,
            result=result,
            assessment=assessment,
            confirmed=confirm,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_exec", action="exec", error=str(exc)) | {"command": command}


@mcp.tool()
def gdb_mi(mi_command: str, confirm: bool = False, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Execute a raw GDB/MI command with warning-and-confirm risk handling."""

    if not ENABLE_RAW_GDB_MI:
        return make_result(
            ok=False,
            tool="gdb_mi",
            action="mi",
            error="raw GDB/MI execution is disabled",
        ) | {"command": mi_command}
    try:
        assessment = assess_mi_command(mi_command)
        gated = _risk_gate(tool="gdb_mi", action="mi", command=mi_command, assessment=assessment, confirm=confirm)
        if gated:
            return gated
        result = controller.execute_mi(mi_command, timeout=timeout)
        return _command_result_to_tool_result(
            tool="gdb_mi",
            action="mi",
            command=mi_command,
            result=result,
            assessment=assessment,
            confirmed=confirm,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_mi", action="mi", error=str(exc)) | {"command": mi_command}


@mcp.tool()
def gdb_remote(
    action: str,
    host: str | None = None,
    port: int | None = None,
    mode: str = "remote",
    local_binary: str | None = None,
    remote_binary: str | None = None,
    sysroot: str | None = None,
    solib_search_path: str | None = None,
    debug_file_directory: str | None = None,
    architecture: str | None = None,
    confirm: bool = False,
    timeout: int = DEFAULT_REMOTE_TIMEOUT,
) -> dict[str, Any]:
    """Configure or connect Windows GDB to a VM-side gdbserver."""

    try:
        if not REMOTE_DEBUG_ENABLED:
            return make_result(ok=False, tool="gdb_remote", action=action, error="remote debugging is disabled")
        action_l = action.lower()
        if action_l == "status":
            return make_result(ok=True, tool="gdb_remote", action=action_l, data=controller.remote_status())

        if action_l == "connect":
            if not host or port is None:
                return make_result(ok=False, tool="gdb_remote", action=action_l, error="host and port are required")
            if mode not in {"remote", "extended-remote"}:
                return make_result(
                    ok=False,
                    tool="gdb_remote",
                    action=action_l,
                    error="mode must be 'remote' or 'extended-remote'",
                )
            target_command = f"target {mode} {host}:{int(port)}"
            assessment = assess_gdb_command(target_command)
            gated = _risk_gate(
                tool="gdb_remote",
                action=action_l,
                command=target_command,
                assessment=assessment,
                confirm=confirm,
                suggested_extra={
                    "action": "connect",
                    "host": host,
                    "port": int(port),
                    "mode": mode,
                    "local_binary": local_binary,
                    "remote_binary": remote_binary,
                    "sysroot": sysroot,
                    "solib_search_path": solib_search_path,
                    "debug_file_directory": debug_file_directory,
                    "architecture": architecture,
                },
            )
            if gated:
                return gated
            result = controller.connect_remote(
                host=host,
                port=int(port),
                mode=mode,
                local_binary=local_binary,
                remote_binary=remote_binary,
                sysroot=sysroot,
                solib_search_path=solib_search_path,
                debug_file_directory=debug_file_directory,
                architecture=architecture,
                timeout=timeout,
            )
            target = result.get("target_result", {})
            return make_result(
                ok=bool(result.get("ok")),
                tool="gdb_remote",
                action=action_l,
                risk_level=assessment.level,
                executed_with_risk=assessment.requires_confirmation and confirm,
                warning=assessment.warning if assessment.requires_confirmation and confirm else None,
                data=result,
                stdout=target.get("stdout", ""),
                stderr=target.get("stderr", ""),
                raw=target.get("raw", {}),
                error=result.get("error"),
            ) | {"command": target_command}

        if action_l == "disconnect":
            command = "disconnect"
            assessment = assess_gdb_command(command)
            gated = _risk_gate(
                tool="gdb_remote",
                action=action_l,
                command=command,
                assessment=assessment,
                confirm=confirm,
            )
            if gated:
                return gated
            result = controller.disconnect_remote(timeout=timeout)
            brief = result.get("result", {})
            return make_result(
                ok=bool(result.get("ok")),
                tool="gdb_remote",
                action=action_l,
                risk_level=assessment.level,
                executed_with_risk=assessment.requires_confirmation and confirm,
                warning=assessment.warning if assessment.requires_confirmation and confirm else None,
                data=result,
                stdout=brief.get("stdout", ""),
                stderr=brief.get("stderr", ""),
                error=result.get("error"),
            ) | {"command": command}

        if action_l == "reconnect":
            cached = controller.remote_status()
            if not cached.get("host") or not cached.get("port"):
                return make_result(
                    ok=False,
                    tool="gdb_remote",
                    action=action_l,
                    data=cached,
                    error="missing cached host/port",
                )
            command = f"target {cached.get('mode') or mode} {cached['host']}:{cached['port']}"
            assessment = assess_gdb_command(command)
            gated = _risk_gate(
                tool="gdb_remote",
                action=action_l,
                command=command,
                assessment=assessment,
                confirm=confirm,
            )
            if gated:
                return gated
            result = controller.reconnect_remote(timeout=timeout)
            target = result.get("target_result", {})
            return make_result(
                ok=bool(result.get("ok")),
                tool="gdb_remote",
                action=action_l,
                risk_level=assessment.level,
                executed_with_risk=assessment.requires_confirmation and confirm,
                warning=assessment.warning if assessment.requires_confirmation and confirm else None,
                data=result,
                stdout=target.get("stdout", ""),
                stderr=target.get("stderr", ""),
                error=result.get("error"),
            ) | {"command": command}

        if action_l == "setup":
            commands = []
            if local_binary:
                commands.append(f"file {controller.quote_gdb_path(local_binary)}")
            if architecture:
                commands.append(f"set architecture {architecture}")
            if sysroot:
                commands.append(f"set sysroot {gdb_quote(controller.normalize_gdb_path(sysroot))}")
            if solib_search_path:
                commands.append(f"set solib-search-path {gdb_quote(controller.normalize_gdb_path(solib_search_path))}")
            if debug_file_directory:
                commands.append(
                    "set debug-file-directory "
                    f"{gdb_quote(controller.normalize_gdb_path(debug_file_directory))}"
                )
            if remote_binary and mode == "extended-remote":
                commands.append(f"set remote exec-file {remote_binary}")
            assessment = _max_assessment([assess_gdb_command(command) for command in commands])
            gated = _risk_gate(
                tool="gdb_remote",
                action=action_l,
                command="; ".join(commands),
                assessment=assessment,
                confirm=confirm,
            )
            if gated:
                return gated
            controller.start()
            results = controller.setup_remote(
                local_binary=local_binary,
                remote_binary=remote_binary,
                sysroot=sysroot,
                solib_search_path=solib_search_path,
                debug_file_directory=debug_file_directory,
                architecture=architecture,
                mode=mode,
                timeout=timeout,
            )
            data = {
                "results": [
                    controller._command_result_brief(item)
                    for item in results
                ],
                "remote_status": controller.remote_status(),
            }
            ok = all(item.ok for item in results)
            return make_result(
                ok=ok,
                tool="gdb_remote",
                action=action_l,
                risk_level=assessment.level,
                executed_with_risk=assessment.requires_confirmation and confirm,
                warning=assessment.warning if assessment.requires_confirmation and confirm else None,
                data=data,
                error=None if ok else "one or more setup commands failed",
            )

        if action_l == "set_sysroot":
            if not sysroot:
                return make_result(ok=False, tool="gdb_remote", action=action_l, error="sysroot is required")
            command = f"set sysroot {gdb_quote(controller.normalize_gdb_path(sysroot))}"
            assessment = assess_gdb_command(command)
            gated = _risk_gate(
                tool="gdb_remote",
                action=action_l,
                command=command,
                assessment=assessment,
                confirm=confirm,
            )
            if gated:
                return gated
            result = controller.set_sysroot(sysroot, timeout=timeout)
            return _command_result_to_tool_result(
                tool="gdb_remote",
                action=action_l,
                command=command,
                result=result,
                assessment=assessment,
                confirmed=confirm,
            )

        if action_l == "set_solib_search_path":
            if not solib_search_path:
                return make_result(ok=False, tool="gdb_remote", action=action_l, error="solib_search_path is required")
            command = f"set solib-search-path {gdb_quote(controller.normalize_gdb_path(solib_search_path))}"
            assessment = assess_gdb_command(command)
            gated = _risk_gate(
                tool="gdb_remote",
                action=action_l,
                command=command,
                assessment=assessment,
                confirm=confirm,
            )
            if gated:
                return gated
            result = controller.set_solib_search_path(solib_search_path, timeout=timeout)
            return _command_result_to_tool_result(
                tool="gdb_remote",
                action=action_l,
                command=command,
                result=result,
                assessment=assessment,
                confirmed=confirm,
            )

        if action_l == "set_remote_exec_file":
            if not remote_binary:
                return make_result(ok=False, tool="gdb_remote", action=action_l, error="remote_binary is required")
            command = f"set remote exec-file {remote_binary}"
            assessment = assess_gdb_command(command)
            gated = _risk_gate(
                tool="gdb_remote",
                action=action_l,
                command=command,
                assessment=assessment,
                confirm=confirm,
            )
            if gated:
                return gated
            result = controller.set_remote_exec_file(remote_binary, timeout=timeout)
            return _command_result_to_tool_result(
                tool="gdb_remote",
                action=action_l,
                command=command,
                result=result,
                assessment=assessment,
                confirmed=confirm,
            )

        if action_l == "set_debug_file_directory":
            if not debug_file_directory:
                return make_result(
                    ok=False,
                    tool="gdb_remote",
                    action=action_l,
                    error="debug_file_directory is required",
                )
            command = f"set debug-file-directory {gdb_quote(controller.normalize_gdb_path(debug_file_directory))}"
            assessment = assess_gdb_command(command)
            gated = _risk_gate(
                tool="gdb_remote",
                action=action_l,
                command=command,
                assessment=assessment,
                confirm=confirm,
            )
            if gated:
                return gated
            result = controller.set_debug_file_directory(debug_file_directory, timeout=timeout)
            return _command_result_to_tool_result(
                tool="gdb_remote",
                action=action_l,
                command=command,
                result=result,
                assessment=assessment,
                confirmed=confirm,
            )

        return make_result(ok=False, tool="gdb_remote", action=action_l, error=f"unsupported action: {action}")
    except Exception as exc:
        return make_result(ok=False, tool="gdb_remote", action=action, error=str(exc))


@mcp.tool()
def gdb_context(depth: int = 20) -> dict[str, Any]:
    """Return registers, current instruction, disassembly, stack, backtrace, breakpoints, and mappings."""

    try:
        depth = max(1, min(int(depth), 256))
        regs_res = _exec_cli_internal("info registers", parse=True)
        registers = (
            regs_res.data.get("registers", parse_registers(regs_res.stdout))
            if regs_res.data
            else parse_registers(regs_res.stdout)
        )
        pc_name = next((name for name in ("rip", "eip", "pc") if name in registers), None)
        sp_name = next((name for name in ("rsp", "esp", "sp") if name in registers), None)
        pc = registers.get(pc_name, {}).get("value") if pc_name else None
        sp = registers.get(sp_name, {}).get("value") if sp_name else None

        current = _exec_cli_internal("x/i $pc", parse=True)
        disasm = _exec_cli_internal("x/16i $pc-32", parse=True)
        stack_cmd = f"x/{depth}gx $sp"
        stack = _exec_cli_internal(stack_cmd, parse=True)
        if not stack.ok:
            stack_cmd = f"x/{depth}wx $sp"
            stack = _exec_cli_internal(stack_cmd, parse=True)
        bt = _exec_cli_internal("bt", parse=True)
        bps = _exec_cli_internal("info breakpoints", parse=True)
        mappings = _exec_cli_internal("info proc mappings", parse=True)
        shared = _exec_cli_internal("info sharedlibrary", parse=True)
        frame = _exec_cli_internal("frame", parse=False)
        thread = _exec_cli_internal("info threads", parse=False)

        current_ins = parse_disassembly(current.stdout)
        disassembly_rows = parse_disassembly(disasm.stdout)
        stack_rows = parse_memory_examine(stack.stdout)
        backtrace_frames = parse_backtrace(bt.stdout)
        breakpoint_rows = parse_breakpoints(bps.stdout)
        mapping_rows = mappings.data.get("mappings", []) if mappings.data else []
        shared_rows = shared.data.get("shared_libraries", []) if shared.data else []
        data = {
            "remote": controller.remote_status(),
            "remote_debugging": controller.remote_connected,
            "remote_host": controller.remote_host,
            "remote_port": controller.remote_port,
            "remote_mode": controller.remote_mode,
            "thread": thread.stdout,
            "thread_info": _availability(thread, thread.stdout),
            "pc_register": pc_name,
            "sp_register": sp_name,
            "pc": pc,
            "sp": sp,
            "current_instruction": (
                current_ins[0]
                if current_ins
                else (
                    current.stdout.strip()
                    if current.ok
                    else {"available": False, "error": current.error}
                )
            ),
            "disassembly": _availability(disasm, disassembly_rows),
            "registers": registers,
            "registers_available": regs_res.ok,
            "stack": _availability(stack, stack_rows),
            "stack_rows": stack_rows,
            "stack_command": stack_cmd,
            "backtrace": _availability(bt, backtrace_frames),
            "backtrace_frames": backtrace_frames,
            "breakpoints": _availability(bps, breakpoint_rows),
            "mappings": _availability(mappings, mapping_rows),
            "mapping_rows": mapping_rows,
            "shared_libraries": _availability(shared, shared_rows),
            "shared_library_rows": shared_rows,
            "source_location": _availability(frame, frame.stdout),
            "function_arguments": _guess_function_arguments(registers, stack_rows),
            "command_errors": {
                "registers": regs_res.error,
                "current_instruction": current.error,
                "disassembly": disasm.error,
                "stack": stack.error,
                "backtrace": bt.error,
                "breakpoints": bps.error,
                "mappings": mappings.error,
                "shared_libraries": shared.error,
                "frame": frame.error,
                "thread": thread.error,
            },
        }
        return make_result(
            ok=True,
            tool="gdb_context",
            action="context",
            data=data,
            error=None if regs_res.ok else regs_res.error,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_context", action="context", error=str(exc))


def _guess_function_arguments(registers: dict[str, Any], stack_rows: list[dict[str, Any]]) -> dict[str, Any]:
    x64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    if any(name in registers for name in x64):
        return {"abi": "x86_64_sysv", "args": {name: registers.get(name) for name in x64 if name in registers}}
    flat_stack = [value for row in stack_rows for value in row.get("values", [])]
    if "esp" in registers or "eip" in registers:
        return {"abi": "i386_cdecl_guess", "stack_args": flat_stack[1:7]}
    return {"abi": "unknown", "args": {}}


@mcp.tool()
def gdb_memory(
    action: str,
    address: str | None = None,
    size: int = 64,
    data_hex: str | None = None,
    pattern: str | None = None,
    output_file: str | None = None,
    confirm: bool = False,
) -> dict[str, Any]:
    """Read, write, search, or dump inferior memory."""

    try:
        action_l = action.lower()
        size = max(0, int(size))
        assessment = assess_memory_action(action_l, size)
        command_preview = f"memory {action_l} {address or ''} size={size}"
        write_bytes: bytes | None = None
        if action_l == "write" and data_hex:
            write_bytes = parse_hex_bytes(data_hex)
            if max_write_size_exceeded(len(write_bytes)):
                assessment = RiskAssessment(
                    "high",
                    f"writing more than {MAX_MEMORY_WRITE} bytes is high risk",
                    "memory.large_write",
                )
        gated = _risk_gate(
            tool="gdb_memory",
            action=action_l,
            command=command_preview,
            assessment=assessment,
            confirm=confirm,
        )
        if gated:
            return gated

        if action_l == "read":
            if not address:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="address is required")
            read_size = min(size, MAX_MEMORY_READ if not confirm else max(size, MAX_MEMORY_READ))
            command = f"x/{read_size}xb {address}"
            res = _exec_cli_internal(command, parse=True)
            raw_bytes = bytes_from_xb_output(res.stdout)
            data = {
                "address": address,
                "requested_size": size,
                "returned_size": len(raw_bytes),
                "hex": raw_bytes.hex(),
                "ascii": ascii_preview(raw_bytes),
                "memory": parse_memory_examine(res.stdout),
            }
            return _command_result_to_tool_result(
                tool="gdb_memory",
                action=action_l,
                command=command,
                result=_replace_result_data(res, command, data),
                assessment=assessment,
                confirmed=confirm,
            )

        if action_l == "write":
            if not address or not data_hex:
                return make_result(
                    ok=False,
                    tool="gdb_memory",
                    action=action_l,
                    error="address and data_hex are required",
                )
            write_bytes = write_bytes if write_bytes is not None else parse_hex_bytes(data_hex)
            if not write_bytes:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="data_hex produced no bytes")
            before = gdb_memory(action="read", address=address, size=len(write_bytes), confirm=True)
            base = parse_int_expression(address)
            outputs: list[dict[str, Any]] = []
            for offset, value in enumerate(write_bytes):
                target = f"0x{base + offset:x}" if base is not None else f"({address})+{offset}"
                command = f"set {{unsigned char}}{target} = 0x{value:02x}"
                res = _exec_cli_internal(command, parse=False)
                outputs.append({"command": command, "ok": res.ok, "error": res.error, "stderr": res.stderr})
                if not res.ok:
                    break
            after = gdb_memory(action="read", address=address, size=len(write_bytes), confirm=True)
            ok = all(item["ok"] for item in outputs)
            return make_result(
                ok=ok,
                tool="gdb_memory",
                action=action_l,
                risk_level=assessment.level,
                executed_with_risk=True,
                warning=assessment.warning,
                data={"before": before.get("data"), "after": after.get("data"), "writes": outputs},
                error=None if ok else "one or more byte writes failed",
            )

        if action_l == "search":
            if not address or not pattern:
                return make_result(
                    ok=False,
                    tool="gdb_memory",
                    action=action_l,
                    error="address and pattern are required",
                )
            try:
                pat_bytes = parse_hex_bytes(pattern)
                pattern_expr = ", ".join(f"0x{b:02x}" for b in pat_bytes)
            except Exception:
                pattern_expr = gdb_quote(pattern)
            command = f"find /b {address}, +{size}, {pattern_expr}"
            res = _exec_cli_internal(command, parse=False)
            matches = [line.strip() for line in res.stdout.splitlines() if line.strip().startswith("0x")]
            data = {"matches": matches, "count": len(matches), "pattern": pattern}
            return _command_result_to_tool_result(
                tool="gdb_memory",
                action=action_l,
                command=command,
                result=_replace_result_data(res, command, data),
                assessment=assessment,
                confirmed=confirm,
            )

        if action_l == "dump":
            if not address:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="address is required")
            base = parse_int_expression(address)
            if base is None:
                return make_result(
                    ok=False,
                    tool="gdb_memory",
                    action=action_l,
                    error="dump requires a numeric address",
                )
            if output_file:
                out_path = Path(output_file)
                if not out_path.is_absolute():
                    out_path = Path(controller.workdir or os.getcwd()) / out_path
                out_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                dump_dir = Path(controller.workdir or os.getcwd()) / "dumps"
                dump_dir.mkdir(parents=True, exist_ok=True)
                out_path = dump_dir / f"gdb_dump_{int(time.time())}_{base:x}_{size}.bin"
            command = f"dump memory {controller.quote_gdb_path(str(out_path))} 0x{base:x} 0x{base + size:x}"
            res = _exec_cli_internal(command, parse=False)
            data = {
                "path": controller.normalize_gdb_path(str(out_path)),
                "address": address,
                "size": size,
                "large_dump_threshold": MAX_MEMORY_DUMP_WITHOUT_CONFIRM,
                "exists": out_path.exists(),
            }
            return _command_result_to_tool_result(
                tool="gdb_memory",
                action=action_l,
                command=command,
                result=_replace_result_data(res, command, data),
                assessment=assessment,
                confirmed=confirm,
            )

        return make_result(ok=False, tool="gdb_memory", action=action_l, error=f"unsupported action: {action}")
    except Exception as exc:
        return make_result(ok=False, tool="gdb_memory", action=action, error=str(exc))


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
        assessment = assess_register_action(action_l)
        gated = _risk_gate(
            tool="gdb_register",
            action=action_l,
            command=f"register {action_l} {name or ''}",
            assessment=assessment,
            confirm=confirm,
        )
        if gated:
            return gated
        if action_l == "read_all":
            res = _exec_cli_internal("info registers", parse=True)
            return _command_result_to_tool_result(
                tool="gdb_register",
                action=action_l,
                command="info registers",
                result=res,
                assessment=assessment,
                confirmed=confirm,
            )
        if action_l == "read":
            if not name:
                return make_result(ok=False, tool="gdb_register", action=action_l, error="name is required")
            command = f"p/x ${name}"
            res = _exec_cli_internal(command, parse=False)
            return _command_result_to_tool_result(
                tool="gdb_register",
                action=action_l,
                command=command,
                result=res,
                assessment=assessment,
                confirmed=confirm,
            )
        if action_l == "write":
            if not name or value is None:
                return make_result(ok=False, tool="gdb_register", action=action_l, error="name and value are required")
            before = gdb_register(action="read", name=name)
            command = f"set ${name}={value}"
            res = _exec_cli_internal(command, parse=False)
            after = gdb_register(action="read", name=name)
            res.data = {"before": before.get("stdout"), "after": after.get("stdout")}
            return _command_result_to_tool_result(
                tool="gdb_register",
                action=action_l,
                command=command,
                result=res,
                assessment=assessment,
                confirmed=confirm,
            )
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
                return make_result(
                    ok=False,
                    tool="gdb_breakpoint",
                    action=action_l,
                    error="watch_expr or location is required",
                )
            command = f"{action_l} {expr}"
            if condition:
                command += f" if {condition}"
        elif action_l in {"delete", "enable", "disable"}:
            if number is None:
                return make_result(ok=False, tool="gdb_breakpoint", action=action_l, error="number is required")
            command = f"{action_l} {number}"
        elif action_l == "condition":
            if number is None or condition is None:
                return make_result(
                    ok=False,
                    tool="gdb_breakpoint",
                    action=action_l,
                    error="number and condition are required",
                )
            command = f"condition {number} {condition}"
        elif action_l == "clear":
            command = f"clear {location}" if location else f"delete {number}" if number is not None else "delete"
        else:
            return make_result(ok=False, tool="gdb_breakpoint", action=action_l, error=f"unsupported action: {action}")
        assessment = assess_gdb_command(command)
        gated = _risk_gate(
            tool="gdb_breakpoint",
            action=action_l,
            command=command,
            assessment=assessment,
            confirm=confirm,
        )
        if gated:
            return gated
        res = _exec_cli_internal(command, parse=True)
        return _command_result_to_tool_result(
            tool="gdb_breakpoint",
            action=action_l,
            command=command,
            result=res,
            assessment=assessment,
            confirmed=confirm,
        )
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
    """Run, continue, step, next, instruction-step, finish, until, interrupt, kill, or restart."""

    try:
        action_l = action.lower()
        count = int(count)
        assessment = assess_run_control(action_l, count)
        gated = _risk_gate(
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
            _exec_cli_internal("set args " + " ".join(gdb_quote(str(arg)) for arg in args), parse=False)

        remote = controller.remote_status()
        if remote.get("connected") and action_l == "run" and remote.get("mode") == "remote":
            return make_result(
                ok=False,
                tool="gdb_run_control",
                action=action_l,
                data={"remote_status": remote},
                error=(
                    "run is usually unavailable with target remote because gdbserver "
                    "already started the process; use continue, or use extended-remote "
                    "with remote_binary"
                ),
            )
        if (
            remote.get("connected")
            and action_l == "run"
            and remote.get("mode") == "extended-remote"
            and not remote.get("remote_binary")
        ):
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
                res = _exec_cli_internal(command, timeout=timeout, parse=True)
                outputs.append(_brief_command_result(res))
        else:
            command = command_map.get(action_l)
            if not command:
                return make_result(
                    ok=False,
                    tool="gdb_run_control",
                    action=action_l,
                    error=f"unsupported action: {action}",
                )
            if action_l == "run" and stdin is not None:
                fd, stdin_path = tempfile.mkstemp(prefix="gdb_mcp_stdin_", text=True)
                temp_stdin_path = stdin_path
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(stdin)
                command = f"run < {gdb_quote(stdin_path)}"
            repeat = max(1, count if action_l in {"step", "next", "stepi", "nexti"} else 1)
            for _ in range(repeat):
                res = _exec_cli_internal(command, timeout=timeout, parse=True)
                outputs.append(_brief_command_result(res))
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
            data={"executed": outputs, "context_summary": _context_summary(context)},
            error=None if ok else "one or more run-control commands failed",
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_run_control", action=action, error=str(exc))


@mcp.tool()
def gdb_analyze(mode: str = "crash") -> dict[str, Any]:
    """Analyze crash state, registers, stack, exploitability, calling convention, or memory faults."""

    try:
        context = gdb_context(depth=32)
        info_program = _exec_cli_internal("info program", parse=False)
        siginfo = _exec_cli_internal("p/x $_siginfo._sifields._sigfault.si_addr", parse=False)
        data = context.get("data", {})
        registers = data.get("registers", {})
        pc = data.get("pc")
        sp = data.get("sp")
        stack_field = data.get("stack") or {}
        stack_rows = stack_field.get("data", []) if isinstance(stack_field, dict) else stack_field
        bt_field = data.get("backtrace") or {}
        bt_rows = bt_field.get("data", []) if isinstance(bt_field, dict) else bt_field
        stack_text = "\n".join(row.get("raw", "") for row in stack_rows or [])
        signal_match = None
        combined = info_program.stdout + "\n" + info_program.stderr
        if "SIG" in combined:
            signal_match = combined.strip()
        controlled_markers = ["0x41414141", "0x42424242", "0x61616161", "0x63636363"]
        pc_text = str(pc or "").lower()
        controlled_pc = any(marker in pc_text for marker in controlled_markers)
        cyclic_on_stack = any(marker.replace("0x", "") in stack_text.lower() for marker in controlled_markers)
        causes: list[str] = []
        if signal_match and "SIGSEGV" in signal_match:
            causes.append("SIGSEGV memory access fault")
        if pc in {"0x0", "0x00000000", "0x0000000000000000"}:
            causes.append("NULL pointer jump/call")
        if controlled_pc:
            causes.append("instruction pointer appears controllable")
        if cyclic_on_stack:
            causes.append("stack contains obvious cyclic/filler pattern")
        if "SIGILL" in combined:
            causes.append("illegal instruction")
        if not causes:
            causes.append("no strong crash signature detected")
        analysis = {
            "mode": mode,
            "remote": data.get("remote"),
            "signal": signal_match,
            "pc": pc,
            "sp": sp,
            "fault_address": siginfo.stdout.strip(),
            "controlled_pc_guess": controlled_pc,
            "cyclic_or_filler_on_stack": cyclic_on_stack,
            "function_arguments": data.get("function_arguments"),
            "register_arguments_x86_64": {
                name: registers.get(name)
                for name in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
                if name in registers
            },
            "possible_causes": causes,
            "backtrace": (bt_rows or [])[:8],
            "confidence": 0.4 if causes == ["no strong crash signature detected"] else 0.7,
            "unavailable": {
                "siginfo": siginfo.error if not siginfo.ok else None,
                "context": context.get("error") if not context.get("ok") else None,
            },
        }
        return make_result(
            ok=True,
            tool="gdb_analyze",
            action=mode,
            data=analysis,
            stdout=info_program.stdout,
            stderr=info_program.stderr,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_analyze", action=mode, error=str(exc))


@mcp.tool()
def gdb_elf(action: str, path: str | None = None) -> dict[str, Any]:
    """Inspect ELF metadata using pyelftools when available and readelf/objdump as fallback."""

    try:
        action_l = action.lower()
        assessment = assess_elf_action(action_l)
        target = resolve_path(
            path or controller.local_binary or controller.current_binary,
            controller.workdir or os.getcwd(),
        )
        if not target:
            return make_result(
                ok=False,
                tool="gdb_elf",
                action=action_l,
                error="path is required or load a binary first",
            )
        if not Path(target).exists():
            return make_result(ok=False, tool="gdb_elf", action=action_l, error=f"file not found: {target}")

        data: dict[str, Any]
        stdout = ""
        stderr = ""
        if action_l == "checksec":
            data = _checksec(target)
        elif action_l in {"info", "entry"}:
            data = _elf_info(target)
        elif action_l == "sections":
            cmd = run_host_command(["readelf", "-SW", target])
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {"sections_text": stdout}
        elif action_l == "segments":
            cmd = run_host_command(["readelf", "-lW", target])
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {"segments_text": stdout}
        elif action_l == "symbols":
            cmd = run_host_command(["readelf", "-sW", target])
            data, stdout, stderr = {"symbols_text": cmd.get("stdout", "")}, cmd.get("stdout", ""), cmd.get("stderr", "")
        elif action_l == "relocations":
            cmd = run_host_command(["readelf", "-rW", target])
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {"relocations_text": stdout}
        elif action_l == "dynamic":
            cmd = run_host_command(["readelf", "-dW", target])
            data, stdout, stderr = {"dynamic_text": cmd.get("stdout", "")}, cmd.get("stdout", ""), cmd.get("stderr", "")
        elif action_l in {"got", "plt"}:
            cmd = run_host_command(["objdump", "-d", "-j", f".{action_l}", target])
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {f"{action_l}_text": stdout}
        elif action_l == "strings":
            cmd = run_host_command(["strings", "-a", "-n", "4", target])
            lines = cmd.get("stdout", "").splitlines()
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {"strings": lines[:2000], "truncated": len(lines) > 2000}
        else:
            return make_result(ok=False, tool="gdb_elf", action=action_l, error=f"unsupported action: {action}")
        data["path"] = target
        return make_result(
            ok=True,
            tool="gdb_elf",
            action=action_l,
            risk_level=assessment.level,
            data=data,
            stdout=stdout,
            stderr=stderr,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_elf", action=action, error=str(exc))


def _elf_info(path: str) -> dict[str, Any]:
    info = {"path": path}
    try:
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as f:
            elf = ELFFile(f)
            info.update(
                {
                    "architecture": elf.get_machine_arch(),
                    "elfclass": elf.elfclass,
                    "endian": "little" if elf.little_endian else "big",
                    "entry": hex(elf.header.e_entry),
                    "type": elf.header.e_type,
                    "sections_count": elf.num_sections(),
                    "segments_count": elf.num_segments(),
                    "interpreter": _elf_interpreter(elf),
                }
            )
            return info
    except Exception as exc:
        info["pyelftools_error"] = str(exc)
    cmd = run_host_command(["readelf", "-hW", path])
    info["readelf_header"] = cmd.get("stdout", "")
    entry = None
    for line in cmd.get("stdout", "").splitlines():
        if "Entry point address:" in line:
            entry = line.split(":", 1)[1].strip()
    if entry:
        info["entry"] = entry
    return info


def _elf_interpreter(elf: Any) -> str | None:
    for segment in elf.iter_segments():
        if segment.header.p_type == "PT_INTERP":
            return segment.get_interp_name()
    return None


def _checksec(path: str) -> dict[str, Any]:
    info = _elf_info(path)
    header = run_host_command(["readelf", "-hW", path])
    program = run_host_command(["readelf", "-lW", path])
    dynamic = run_host_command(["readelf", "-dW", path])
    symbols = run_host_command(["readelf", "-sW", path])
    h = header.get("stdout", "")
    p = program.get("stdout", "")
    d = dynamic.get("stdout", "")
    s = symbols.get("stdout", "")
    relro = (
        "Full RELRO"
        if "GNU_RELRO" in p and "BIND_NOW" in d
        else "Partial RELRO"
        if "GNU_RELRO" in p
        else "No RELRO"
    )
    nx = "NX enabled" if re_search_gnu_stack_nx(p) else "NX disabled or unknown"
    canary = "Canary found" if "__stack_chk_fail" in s else "No canary found"
    pie = "PIE enabled" if "Type:                              DYN" in h or "Type: DYN" in h else "No PIE"
    return {
        **info,
        "relro": relro,
        "nx": nx,
        "canary": canary,
        "pie": pie,
        "raw_tools": {
            "readelf_header_ok": header.get("ok"),
            "readelf_program_ok": program.get("ok"),
            "readelf_dynamic_ok": dynamic.get("ok"),
            "readelf_symbols_ok": symbols.get("ok"),
        },
    }


def re_search_gnu_stack_nx(program_headers: str) -> bool:
    for line in program_headers.splitlines():
        if "GNU_STACK" in line:
            return "RWE" not in line
    return False


@mcp.tool()
def gdb_pwndbg(command: str, confirm: bool = False) -> dict[str, Any]:
    """Execute pwndbg/gef/peda helper commands if they appear available."""

    if not ENABLE_PWNDBG_COMMANDS:
        return make_result(ok=False, tool="gdb_pwndbg", action="plugin", error="pwndbg commands are disabled")
    try:
        assessment = assess_gdb_command(command)
        gated = _risk_gate(tool="gdb_pwndbg", action="plugin", command=command, assessment=assessment, confirm=confirm)
        if gated:
            return gated
        availability_checks = {
            "pwndbg": _exec_cli_internal("help pwndbg", parse=False).ok,
            "gef": "GEF" in _exec_cli_internal("gef config", parse=False).stdout,
            "peda": _exec_cli_internal("help peda", parse=False).ok,
        }
        if not any(availability_checks.values()):
            return make_result(
                ok=False,
                tool="gdb_pwndbg",
                action="plugin",
                data={"available": False, "checks": availability_checks},
                error="pwndbg/gef/peda does not appear to be loaded in this GDB session",
            )
        res = _exec_cli_internal(command, timeout=DEFAULT_TIMEOUT, parse=True)
        return _command_result_to_tool_result(
            tool="gdb_pwndbg",
            action="plugin",
            command=command,
            result=res,
            assessment=assessment,
            confirmed=confirm,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_pwndbg", action="plugin", error=str(exc))


def main() -> None:
    """Run the MCP server over stdio."""

    mcp.run()


if __name__ == "__main__":
    main()
