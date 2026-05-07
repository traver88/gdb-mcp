"""Remote connection and context MCP tools."""

from __future__ import annotations

from typing import Any

from config import DEFAULT_REMOTE_TIMEOUT, DEFAULT_TIMEOUT, REMOTE_DEBUG_ENABLED
from models import make_result
from safety import assess_gdb_command
from server_runtime import (
    availability,
    command_result_to_tool_result,
    context_summary,
    controller,
    exec_cli_internal,
    max_assessment,
    mcp,
    risk_gate,
)
from utils import gdb_quote, parse_backtrace, parse_breakpoints, parse_disassembly, parse_memory_examine, parse_registers


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
    """Configure or connect local GDB to a remote gdbserver."""

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
                return make_result(ok=False, tool="gdb_remote", action=action_l, error="mode must be 'remote' or 'extended-remote'")
            target_command = f"target {mode} {host}:{int(port)}"
            assessment = assess_gdb_command(target_command)
            gated = risk_gate(
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
            gated = risk_gate(tool="gdb_remote", action=action_l, command=command, assessment=assessment, confirm=confirm)
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
                return make_result(ok=False, tool="gdb_remote", action=action_l, data=cached, error="missing cached host/port")
            command = f"target {cached.get('mode') or mode} {cached['host']}:{cached['port']}"
            assessment = assess_gdb_command(command)
            gated = risk_gate(tool="gdb_remote", action=action_l, command=command, assessment=assessment, confirm=confirm)
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
                commands.append("set debug-file-directory " f"{gdb_quote(controller.normalize_gdb_path(debug_file_directory))}")
            if remote_binary and mode == "extended-remote":
                commands.append(f"set remote exec-file {remote_binary}")
            if not commands:
                return make_result(ok=True, tool="gdb_remote", action=action_l, data={"results": [], "remote_status": controller.remote_status()})
            assessment = max_assessment([assess_gdb_command(command) for command in commands])
            gated = risk_gate(tool="gdb_remote", action=action_l, command="; ".join(commands), assessment=assessment, confirm=confirm)
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
            data = {"results": [controller._command_result_brief(item) for item in results], "remote_status": controller.remote_status()}
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

        setter_map = {
            "set_sysroot": (sysroot, controller.set_sysroot, "set sysroot"),
            "set_solib_search_path": (solib_search_path, controller.set_solib_search_path, "set solib-search-path"),
            "set_remote_exec_file": (remote_binary, controller.set_remote_exec_file, "set remote exec-file"),
            "set_debug_file_directory": (debug_file_directory, controller.set_debug_file_directory, "set debug-file-directory"),
        }
        if action_l in setter_map:
            value, setter, prefix = setter_map[action_l]
            if not value:
                return make_result(ok=False, tool="gdb_remote", action=action_l, error=f"{action_l.split('set_', 1)[1]} is required")
            normalized = controller.normalize_gdb_path(value) if action_l != "set_remote_exec_file" else value
            command = f"{prefix} {gdb_quote(normalized) if action_l != 'set_remote_exec_file' else value}"
            assessment = assess_gdb_command(command)
            gated = risk_gate(tool="gdb_remote", action=action_l, command=command, assessment=assessment, confirm=confirm)
            if gated:
                return gated
            result = setter(value, timeout=timeout)
            return command_result_to_tool_result(
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
    """Return registers, instruction, stack, backtrace, breakpoints, and remote context."""

    try:
        depth = max(1, min(int(depth), 256))
        regs_res = exec_cli_internal("info registers", parse=True)
        registers = regs_res.data.get("registers", parse_registers(regs_res.stdout)) if regs_res.data else parse_registers(regs_res.stdout)
        pc_name = next((name for name in ("rip", "eip", "pc") if name in registers), None)
        sp_name = next((name for name in ("rsp", "esp", "sp") if name in registers), None)
        pc = registers.get(pc_name, {}).get("value") if pc_name else None
        sp = registers.get(sp_name, {}).get("value") if sp_name else None

        current = exec_cli_internal("x/i $pc", parse=True)
        disasm = exec_cli_internal("x/16i $pc-32", parse=True)
        stack_cmd = f"x/{depth}gx $sp"
        stack = exec_cli_internal(stack_cmd, parse=True)
        if not stack.ok:
            stack_cmd = f"x/{depth}wx $sp"
            stack = exec_cli_internal(stack_cmd, parse=True)
        bt = exec_cli_internal("bt", parse=True)
        bps = exec_cli_internal("info breakpoints", parse=True)
        mappings = exec_cli_internal("info proc mappings", parse=True)
        shared = exec_cli_internal("info sharedlibrary", parse=True)
        frame = exec_cli_internal("frame", parse=False)
        thread = exec_cli_internal("info threads", parse=False)

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
            "thread_info": availability(thread, thread.stdout),
            "pc_register": pc_name,
            "sp_register": sp_name,
            "pc": pc,
            "sp": sp,
            "current_instruction": current_ins[0] if current_ins else (current.stdout.strip() if current.ok else {"available": False, "error": current.error}),
            "disassembly": availability(disasm, disassembly_rows),
            "registers": registers,
            "registers_available": regs_res.ok,
            "stack": availability(stack, stack_rows),
            "stack_rows": stack_rows,
            "stack_command": stack_cmd,
            "backtrace": availability(bt, backtrace_frames),
            "backtrace_frames": backtrace_frames,
            "breakpoints": availability(bps, breakpoint_rows),
            "mappings": availability(mappings, mapping_rows),
            "mapping_rows": mapping_rows,
            "shared_libraries": availability(shared, shared_rows),
            "shared_library_rows": shared_rows,
            "source_location": availability(frame, frame.stdout),
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
        return make_result(ok=True, tool="gdb_context", action="context", data=data, error=None if regs_res.ok else regs_res.error)
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
