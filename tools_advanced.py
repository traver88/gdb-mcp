"""Raw command, analysis, ELF, and plugin MCP tools."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from config import DEFAULT_TIMEOUT, ENABLE_PWNDBG_COMMANDS, ENABLE_RAW_GDB_EXEC, ENABLE_RAW_GDB_MI
from models import make_result
from safety import assess_elf_action, assess_gdb_command, assess_mi_command
from server_runtime import (
    command_result_to_tool_result,
    controller,
    exec_cli_internal,
    mcp,
    risk_gate,
)
from utils import resolve_path, run_host_command
from tools_remote import gdb_context


@mcp.tool()
def gdb_exec(command: str, confirm: bool = False, timeout: int = DEFAULT_TIMEOUT, parse: bool = True) -> dict[str, Any]:
    """Execute an arbitrary GDB CLI command with warning-and-confirm risk handling."""

    if not ENABLE_RAW_GDB_EXEC:
        return make_result(ok=False, tool="gdb_exec", action="exec", error="raw GDB CLI execution is disabled") | {"command": command}
    try:
        assessment = assess_gdb_command(command)
        gated = risk_gate(tool="gdb_exec", action="exec", command=command, assessment=assessment, confirm=confirm)
        if gated:
            return gated
        result = controller.execute_cli(command, timeout=timeout, parse=parse)
        return command_result_to_tool_result(
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
        return make_result(ok=False, tool="gdb_mi", action="mi", error="raw GDB/MI execution is disabled") | {"command": mi_command}
    try:
        assessment = assess_mi_command(mi_command)
        gated = risk_gate(tool="gdb_mi", action="mi", command=mi_command, assessment=assessment, confirm=confirm)
        if gated:
            return gated
        result = controller.execute_mi(mi_command, timeout=timeout)
        return command_result_to_tool_result(
            tool="gdb_mi",
            action="mi",
            command=mi_command,
            result=result,
            assessment=assessment,
            confirmed=confirm,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_mi", action="mi", error=str(exc)) | {"command": mi_command}


def _extract_leak_hints(stack_rows: list[dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    for row in stack_rows[:8]:
        for value in row.get("values", []):
            lower = value.lower()
            if lower.startswith("0x7f"):
                hints.append(f"possible libc/loader pointer: {value}")
            elif lower.startswith("0x55") or lower.startswith("0x56"):
                hints.append(f"possible PIE/text pointer: {value}")
    return hints[:6]


def _classify_gadget(instruction: str) -> str | None:
    lower = instruction.strip().lower()
    if lower == "ret":
        return "ret"
    if lower.startswith("pop rdi"):
        return "pop_rdi"
    if lower.startswith("pop rsi"):
        return "pop_rsi"
    if lower.startswith("pop rdx"):
        return "pop_rdx"
    if lower.startswith("pop rcx"):
        return "pop_rcx"
    if lower.startswith("syscall"):
        return "syscall"
    if lower.startswith("leave"):
        return "leave"
    if lower.startswith("jmp rsp") or lower.startswith("jmp esp"):
        return "jmp_sp"
    if lower.startswith("call rsp") or lower.startswith("call esp"):
        return "call_sp"
    if lower.startswith("pop "):
        return "generic_pop"
    return None


def _extract_rop_gadget_hints(disassembly: list[dict[str, Any]]) -> dict[str, list[str]]:
    categorized: dict[str, list[str]] = {}
    for item in disassembly[:40]:
        instruction = str(item.get("instruction", "")).strip()
        address = item.get("address")
        category = _classify_gadget(instruction)
        if not category:
            continue
        categorized.setdefault(category, []).append(f"{address}: {instruction}")
    return {name: values[:5] for name, values in categorized.items()}


def _guess_libc_base(stack_rows: list[dict[str, Any]]) -> str | None:
    for row in stack_rows[:8]:
        for value in row.get("values", []):
            lower = value.lower()
            if lower.startswith("0x7f"):
                try:
                    address = int(lower, 16)
                except ValueError:
                    continue
                base = address & ~0xFFF
                return hex(base)
    return None


def _suggest_leak_chains(candidates: list[str], has_pie_pointer: bool, has_libc_pointer: bool) -> list[str]:
    suggestions: list[str] = []
    if "puts" in candidates and has_libc_pointer:
        suggestions.append("leak puts@got via puts@plt to recover libc base")
    if "printf" in candidates:
        suggestions.append("use printf-style output path to disclose pointers or stack data")
    if "write" in candidates:
        suggestions.append("use write(fd, addr, len) as an arbitrary memory disclosure primitive")
    if "read" in candidates:
        suggestions.append("pair read primitive with stack pivot or ROP chain staging")
    if has_pie_pointer:
        suggestions.append("derive PIE base from leaked text pointer before resolving GOT/PLT targets")
    return suggestions[:6]


def _build_ret2libc_candidates(rop_hints: dict[str, list[str]], leak_hints: list[str], libc_base_guess: str | None) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    has_pop_rdi = bool(rop_hints.get("pop_rdi"))
    has_ret = bool(rop_hints.get("ret"))
    has_libc_leak = any("libc/loader" in item for item in leak_hints)
    if has_pop_rdi and has_libc_leak:
        candidates.append(
            {
                "name": "ret2libc_puts_leak",
                "requirements": ["pop rdi gadget", "GOT/PLT symbol such as puts", "libc leak or libc base guess"],
                "notes": "Use pop rdi to pass GOT entry to puts/printf, then return to main or another re-entry point.",
                "libc_base_guess": libc_base_guess,
            }
        )
    if has_ret and has_pop_rdi:
        candidates.append(
            {
                "name": "stack_alignment_then_ret2libc",
                "requirements": ["ret gadget", "pop rdi gadget", "callable PLT function"],
                "notes": "Insert a ret for stack alignment on x86_64 before jumping into libc or PLT calls when needed.",
                "libc_base_guess": libc_base_guess,
            }
        )
    return candidates[:4]


def _build_rop_candidates(rop_hints: dict[str, list[str]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if rop_hints.get("syscall") and rop_hints.get("pop_rdi") and rop_hints.get("pop_rsi"):
        candidates.append(
            {
                "name": "syscall_chain_candidate",
                "requirements": ["syscall gadget", "argument setup gadgets"],
                "notes": "Potential direct syscall chain if a matching rax/control primitive is available.",
            }
        )
    if rop_hints.get("leave"):
        candidates.append(
            {
                "name": "stack_pivot_candidate",
                "requirements": ["leave gadget", "controlled saved rbp/stack frame"],
                "notes": "leave can be useful for stack pivoting into attacker-controlled memory.",
            }
        )
    if rop_hints.get("jmp_sp") or rop_hints.get("call_sp"):
        candidates.append(
            {
                "name": "direct_stack_transfer_candidate",
                "requirements": ["jmp/call sp gadget", "controlled stack contents"],
                "notes": "May support shellcode or staged ROP depending on NX and writable/executable memory.",
            }
        )
    return candidates[:4]


def _build_exploitation_hints(context_data: dict[str, Any], combined_signal_text: str) -> dict[str, Any]:
    stack_field = context_data.get("stack") or {}
    stack_rows = stack_field.get("data", []) if isinstance(stack_field, dict) else stack_field
    disassembly_field = context_data.get("disassembly") or {}
    disassembly_rows = disassembly_field.get("data", []) if isinstance(disassembly_field, dict) else disassembly_field
    leak_hints = _extract_leak_hints(stack_rows or [])
    rop_hints = _extract_rop_gadget_hints(disassembly_rows or [])
    libc_base_guess = _guess_libc_base(stack_rows or [])
    has_libc_pointer = any("libc/loader" in item for item in leak_hints)
    has_pie_pointer = any("PIE/text" in item for item in leak_hints)
    leak_chain_candidates = _suggest_leak_chains(["puts", "printf", "read", "write"], has_pie_pointer, has_libc_pointer)
    strategy_hints = []
    if "SIGSEGV" in combined_signal_text:
        strategy_hints.append("memory access fault may indicate overwrite primitive or bad dereference")
    if leak_hints:
        strategy_hints.append("stack contains addresses that may help identify libc or PIE base")
    if libc_base_guess:
        strategy_hints.append(f"possible page-aligned libc base candidate: {libc_base_guess}")
    return {
        "leak_hints": leak_hints,
        "rop_gadget_hints": rop_hints,
        "libc_base_guess": libc_base_guess,
        "leak_chain_suggestions": leak_chain_candidates,
        "ret2libc_candidates": _build_ret2libc_candidates(rop_hints, leak_hints, libc_base_guess),
        "rop_chain_candidates": _build_rop_candidates(rop_hints),
        "strategy_hints": strategy_hints,
    }


@mcp.tool()
def gdb_analyze(mode: str = "crash") -> dict[str, Any]:
    """Analyze crash state, registers, stack, and exploitability hints."""

    try:
        context = gdb_context(depth=32)
        info_program = exec_cli_internal("info program", parse=False)
        siginfo = exec_cli_internal("p/x $_siginfo._sifields._sigfault.si_addr", parse=False)
        data = context.get("data", {})
        registers = data.get("registers", {})
        pc = data.get("pc")
        sp = data.get("sp")
        stack_field = data.get("stack") or {}
        stack_rows = stack_field.get("data", []) if isinstance(stack_field, dict) else stack_field
        bt_field = data.get("backtrace") or {}
        bt_rows = bt_field.get("data", []) if isinstance(bt_field, dict) else bt_field
        stack_text = "\n".join(row.get("raw", "") for row in stack_rows or [])
        combined = info_program.stdout + "\n" + info_program.stderr
        signal_match = combined.strip() if "SIG" in combined else None
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
        exploit_hints = _build_exploitation_hints(data, combined)
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
            "register_arguments_x86_64": {name: registers.get(name) for name in ("rdi", "rsi", "rdx", "rcx", "r8", "r9") if name in registers},
            "possible_causes": causes,
            "backtrace": (bt_rows or [])[:8],
            "exploitation_hints": exploit_hints,
            "confidence": 0.4 if causes == ["no strong crash signature detected"] else 0.7,
            "unavailable": {
                "siginfo": siginfo.error if not siginfo.ok else None,
                "context": context.get("error") if not context.get("ok") else None,
            },
        }
        return make_result(ok=True, tool="gdb_analyze", action=mode, data=analysis, stdout=info_program.stdout, stderr=info_program.stderr)
    except Exception as exc:
        return make_result(ok=False, tool="gdb_analyze", action=mode, error=str(exc))


def _checksec(path: str) -> dict[str, Any]:
    file_result = run_host_command(["readelf", "-W", "-l", path])
    dynamic_result = run_host_command(["readelf", "-W", "-d", path])
    symbols_result = run_host_command(["readelf", "-W", "-s", path])
    dynamic_text = dynamic_result.get("stdout", "")
    file_text = file_result.get("stdout", "")
    symbols_text = symbols_result.get("stdout", "")
    return {
        "path": path,
        "nx": "GNU_STACK" in file_text and "RWE" not in file_text,
        "pie": "DYN" in file_text,
        "relro": "BIND_NOW" in dynamic_text,
        "canary": "__stack_chk_fail" in symbols_text,
    }


def _elf_info(path: str) -> dict[str, Any]:
    info = {"path": path}
    try:
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as handle:
            elf = ELFFile(handle)
            info.update(
                {
                    "architecture": elf.get_machine_arch(),
                    "elfclass": elf.elfclass,
                    "endian": "little" if elf.little_endian else "big",
                    "entry_point": hex(elf.header["e_entry"]),
                    "type": elf.header["e_type"],
                }
            )
    except Exception as exc:
        info["error"] = str(exc)
    return info


def _parse_got_entries(text: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or "<" not in stripped or ":" not in stripped:
            continue
        address, rest = stripped.split(":", 1)
        entries.append({"address": address.strip(), "text": rest.strip(), "raw": line})
    return entries[:200]


def _parse_rop_gadgets(text: str) -> list[dict[str, Any]]:
    gadgets: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue
        address, instruction = stripped.split(":", 1)
        instruction = instruction.strip()
        category = _classify_gadget(instruction)
        if category:
            gadgets.append({"address": address.strip().split()[0], "instruction": instruction, "category": category, "raw": line})
    return gadgets[:200]


def _build_leak_candidates(symbols: str, dynamic: str) -> dict[str, Any]:
    candidates = []
    for marker in ("puts", "printf", "read", "write", "system", "__libc_start_main"):
        if marker in symbols or marker in dynamic:
            candidates.append(marker)
    suggestions = _suggest_leak_chains(candidates, has_pie_pointer=True, has_libc_pointer=True)
    return {"candidates": candidates, "count": len(candidates), "suggestions": suggestions}


@mcp.tool()
def gdb_elf(action: str, path: str | None = None) -> dict[str, Any]:
    """Inspect ELF metadata using pyelftools and readelf/objdump helpers."""

    try:
        action_l = action.lower()
        assessment = assess_elf_action(action_l)
        target = resolve_path(path or controller.local_binary or controller.current_binary, controller.workdir or os.getcwd())
        if not target:
            return make_result(ok=False, tool="gdb_elf", action=action_l, error="path is required or load a binary first")
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
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {"symbols_text": stdout}
        elif action_l == "relocations":
            cmd = run_host_command(["readelf", "-rW", target])
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {"relocations_text": stdout}
        elif action_l == "dynamic":
            cmd = run_host_command(["readelf", "-dW", target])
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {"dynamic_text": stdout}
        elif action_l in {"got", "plt"}:
            cmd = run_host_command(["objdump", "-d", "-j", f".{action_l}", target])
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {f"{action_l}_text": stdout, f"{action_l}_entries": _parse_got_entries(stdout)}
        elif action_l == "rop":
            cmd = run_host_command(["objdump", "-d", target])
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            gadgets = _parse_rop_gadgets(stdout)
            data = {
                "gadgets": gadgets,
                "ret2libc_candidates": _build_ret2libc_candidates(
                    {g["category"]: [g["instruction"]] for g in gadgets},
                    ["possible libc/loader pointer"],
                    None,
                ),
                "rop_chain_candidates": _build_rop_candidates({g["category"]: [g["instruction"]] for g in gadgets}),
                "text": stdout,
            }
        elif action_l == "leaks":
            symbols = run_host_command(["readelf", "-sW", target]).get("stdout", "")
            dynamic = run_host_command(["readelf", "-dW", target]).get("stdout", "")
            data = _build_leak_candidates(symbols, dynamic)
        elif action_l == "strings":
            cmd = run_host_command(["strings", "-a", "-n", "4", target])
            lines = cmd.get("stdout", "").splitlines()
            stdout, stderr = cmd.get("stdout", ""), cmd.get("stderr", "")
            data = {"strings": lines[:2000], "truncated": len(lines) > 2000}
        else:
            return make_result(ok=False, tool="gdb_elf", action=action_l, error=f"unsupported action: {action}")
        data["path"] = target
        return make_result(ok=True, tool="gdb_elf", action=action_l, risk_level=assessment.level, data=data, stdout=stdout, stderr=stderr)
    except Exception as exc:
        return make_result(ok=False, tool="gdb_elf", action=action, error=str(exc))


@mcp.tool()
def gdb_pwndbg(command: str, confirm: bool = False) -> dict[str, Any]:
    """Execute pwndbg/gef/peda-compatible commands through the GDB CLI bridge."""

    if not ENABLE_PWNDBG_COMMANDS:
        return make_result(ok=False, tool="gdb_pwndbg", action="plugin", error="plugin commands are disabled")
    try:
        assessment = assess_gdb_command(command)
        gated = risk_gate(tool="gdb_pwndbg", action="plugin", command=command, assessment=assessment, confirm=confirm)
        if gated:
            return gated
        res = exec_cli_internal(command, timeout=DEFAULT_TIMEOUT, parse=True)
        return command_result_to_tool_result(
            tool="gdb_pwndbg",
            action="plugin",
            command=command,
            result=res,
            assessment=assessment,
            confirmed=confirm,
        )
    except Exception as exc:
        return make_result(ok=False, tool="gdb_pwndbg", action="plugin", error=str(exc))
