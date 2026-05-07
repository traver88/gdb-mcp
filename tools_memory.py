"""Memory-oriented MCP tools."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from config import MAX_MEMORY_DUMP_WITHOUT_CONFIRM, MAX_MEMORY_READ, MAX_MEMORY_WRITE
from models import RiskAssessment, make_result
from safety import assess_memory_action, max_write_size_exceeded
from server_runtime import (
    command_result_to_tool_result,
    controller,
    ensure_mutation_allowed,
    exec_cli_internal,
    is_write_like_memory_action,
    mcp,
    memory_read_result,
    replace_result_data,
    write_memory_bytewise,
    write_memory_with_restore,
)
from utils import gdb_quote, parse_hex_bytes, parse_int_expression


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
    """Read, write, block-write, search, or dump inferior memory."""

    try:
        action_l = action.lower()
        size = max(0, int(size))
        if is_write_like_memory_action(action_l):
            blocked = ensure_mutation_allowed("gdb_memory", action_l)
            if blocked:
                return blocked
        assessment = assess_memory_action("write" if action_l == "write_block" else action_l, size)
        command_preview = f"memory {action_l} {address or ''} size={size}"
        write_bytes: bytes | None = None
        if action_l in {"write", "write_block"} and data_hex:
            write_bytes = parse_hex_bytes(data_hex)
            if max_write_size_exceeded(len(write_bytes)):
                assessment = RiskAssessment(
                    "high",
                    f"writing more than {MAX_MEMORY_WRITE} bytes is high risk",
                    "memory.large_write",
                )
        if assessment.requires_confirmation and not confirm:
            from models import confirmation_required_result

            return confirmation_required_result(
                tool="gdb_memory",
                action=action_l,
                command=command_preview,
                assessment=assessment,
            )

        if action_l == "read":
            if not address:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="address is required")
            read_size = min(size, MAX_MEMORY_READ if not confirm else max(size, MAX_MEMORY_READ))
            return memory_read_result(
                address=address,
                requested_size=size,
                effective_size=read_size,
                assessment=assessment,
                confirmed=confirm,
            )

        if action_l in {"write", "write_block"}:
            if not address or not data_hex:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="address and data_hex are required")
            write_bytes = write_bytes if write_bytes is not None else parse_hex_bytes(data_hex)
            if not write_bytes:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="data_hex produced no bytes")
            before = memory_read_result(
                address=address,
                requested_size=len(write_bytes),
                effective_size=len(write_bytes),
                assessment=RiskAssessment("low"),
                confirmed=True,
            )
            if action_l == "write_block":
                outputs, executed_command = write_memory_with_restore(address, write_bytes)
            else:
                outputs = write_memory_bytewise(address, write_bytes)
                executed_command = outputs[0]["command"] if outputs else ""
            after = memory_read_result(
                address=address,
                requested_size=len(write_bytes),
                effective_size=len(write_bytes),
                assessment=RiskAssessment("low"),
                confirmed=True,
            )
            ok = all(item["ok"] for item in outputs)
            return make_result(
                ok=ok,
                tool="gdb_memory",
                action=action_l,
                risk_level=assessment.level,
                executed_with_risk=True,
                warning=assessment.warning,
                data={
                    "before": before.get("data"),
                    "after": after.get("data"),
                    "writes": outputs,
                    "write_mode": "block" if action_l == "write_block" else "bytewise",
                    "executed_command": executed_command,
                    "partial_write_possible": not ok,
                    "byte_count": len(write_bytes),
                },
                error=None if ok else "one or more memory writes failed",
            )

        if action_l == "search":
            if not address or not pattern:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="address and pattern are required")
            try:
                pat_bytes = parse_hex_bytes(pattern)
                pattern_expr = ", ".join(f"0x{b:02x}" for b in pat_bytes)
            except Exception:
                pattern_expr = gdb_quote(pattern)
            command = f"find /b {address}, +{size}, {pattern_expr}"
            res = exec_cli_internal(command, parse=False)
            matches = [line.strip() for line in res.stdout.splitlines() if line.strip().startswith("0x")]
            data = {"matches": matches, "count": len(matches), "pattern": pattern}
            return command_result_to_tool_result(
                tool="gdb_memory",
                action=action_l,
                command=command,
                result=replace_result_data(res, command, data),
                assessment=assessment,
                confirmed=confirm,
            )

        if action_l == "dump":
            if not address:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="address is required")
            base = parse_int_expression(address)
            if base is None:
                return make_result(ok=False, tool="gdb_memory", action=action_l, error="dump requires a numeric address")
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
            res = exec_cli_internal(command, parse=False)
            data = {
                "path": controller.normalize_gdb_path(str(out_path)),
                "address": address,
                "size": size,
                "large_dump_threshold": MAX_MEMORY_DUMP_WITHOUT_CONFIRM,
                "exists": out_path.exists(),
            }
            return command_result_to_tool_result(
                tool="gdb_memory",
                action=action_l,
                command=command,
                result=replace_result_data(res, command, data),
                assessment=assessment,
                confirmed=confirm,
            )

        return make_result(ok=False, tool="gdb_memory", action=action_l, error=f"unsupported action: {action}")
    except Exception as exc:
        return make_result(ok=False, tool="gdb_memory", action=action, error=str(exc))
