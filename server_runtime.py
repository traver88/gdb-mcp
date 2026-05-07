"""Shared server runtime and helper functions."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from config import BLOCK_MEMORY_WRITE_CHUNK_SIZE, DEFAULT_TIMEOUT, GDB_PATH, READ_ONLY_MODE
from gdb_controller import CommandResult, GdbController
from models import RiskAssessment, confirmation_required_result, make_result
from utils import ascii_preview, bytes_from_xb_output, parse_backtrace, parse_breakpoints, parse_disassembly, parse_int_expression, parse_memory_examine

mcp = FastMCP("gdb-mcp")
controller = GdbController()


def exec_cli_internal(command: str, timeout: int = DEFAULT_TIMEOUT, parse: bool = True) -> CommandResult:
    return controller.execute_cli(command, timeout=timeout, parse=parse)


def risk_gate(
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


def command_result_to_tool_result(
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


def availability(result: CommandResult, value: Any) -> dict[str, Any]:
    return {
        "available": result.ok,
        "data": value if result.ok else None,
        "error": None if result.ok else result.error,
        "stdout": result.stdout,
    }


def max_assessment(assessments: list[RiskAssessment]) -> RiskAssessment:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return max(assessments, key=lambda item: rank[item.level], default=RiskAssessment())


def brief_command_result(result: CommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "ok": result.ok,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "error": result.error,
        "timeout": result.timeout,
    }


def replace_result_data(result: CommandResult, command: str, data: dict[str, Any]) -> CommandResult:
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


def read_memory_bytes(address: str, size: int) -> tuple[CommandResult, bytes, list[dict[str, Any]], str]:
    command = f"x/{size}xb {address}"
    result = exec_cli_internal(command, parse=True)
    rows = parse_memory_examine(result.stdout)
    raw_bytes = bytes_from_xb_output(result.stdout)
    return result, raw_bytes, rows, command


def memory_read_result(
    *,
    address: str,
    requested_size: int,
    effective_size: int,
    assessment: RiskAssessment,
    confirmed: bool,
) -> dict[str, Any]:
    result, raw_bytes, rows, command = read_memory_bytes(address, effective_size)
    data = {
        "address": address,
        "requested_size": requested_size,
        "returned_size": len(raw_bytes),
        "hex": raw_bytes.hex(),
        "ascii": ascii_preview(raw_bytes),
        "memory": rows,
    }
    return command_result_to_tool_result(
        tool="gdb_memory",
        action="read",
        command=command,
        result=replace_result_data(result, command, data),
        assessment=assessment,
        confirmed=confirmed,
    )


def context_summary(context: dict[str, Any]) -> dict[str, Any]:
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


def is_write_like_memory_action(action: str) -> bool:
    return action in {"write", "write_block"}


def ensure_mutation_allowed(tool: str, action: str) -> dict[str, Any] | None:
    if READ_ONLY_MODE:
        return make_result(ok=False, tool=tool, action=action, error="read-only mode is enabled")
    return None


def write_memory_with_restore(address: str, data: bytes) -> tuple[list[dict[str, Any]], str]:
    base = parse_int_expression(address)
    if base is None:
        raise ValueError("block write requires a numeric address")
    workdir = Path(controller.workdir or os.getcwd())
    temp_dir = workdir / "dumps"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"gdb_patch_{int(time.time())}_{base:x}_{len(data)}.bin"
    temp_path.write_bytes(data)
    command = f"restore {controller.quote_gdb_path(str(temp_path))} binary 0x{base:x}"
    result = exec_cli_internal(command, parse=False)
    outputs = [{"command": command, "ok": result.ok, "error": result.error, "stderr": result.stderr}]
    try:
        temp_path.unlink(missing_ok=True)
    except Exception:
        pass
    return outputs, command


def write_memory_bytewise(address: str, data: bytes) -> list[dict[str, Any]]:
    base = parse_int_expression(address)
    outputs: list[dict[str, Any]] = []
    chunk_size = max(1, BLOCK_MEMORY_WRITE_CHUNK_SIZE)
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset : offset + chunk_size]
        for inner_offset, value in enumerate(chunk):
            absolute_offset = offset + inner_offset
            target = f"0x{base + absolute_offset:x}" if base is not None else f"({address})+{absolute_offset}"
            command = f"set {{unsigned char}}{target} = 0x{value:02x}"
            result = exec_cli_internal(command, parse=False)
            outputs.append({"command": command, "ok": result.ok, "error": result.error, "stderr": result.stderr})
            if not result.ok:
                return outputs
    return outputs
