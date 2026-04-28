"""Utility helpers for GDB output parsing and host-side commands."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

from config import WINDOWS_PATH_NORMALIZE

_SPACE_RE = re.compile(r"\s+")
_REGISTER_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9_]+)\s+(\S+)(?:\s+(.*))?$")
_BACKTRACE_RE = re.compile(r"^#(\d+)\s+(?:(0x[0-9a-fA-F]+)\s+in\s+)?(.+)$")
_BREAKPOINT_RE = re.compile(r"^(\d+)\s+(\S.*?)\s+(keep|del)\s+([yn])\s+(\S+)\s+(.+)$")
_BREAKPOINT_FALLBACK_RE = re.compile(r"^(\d+)\s+(.+)$")
_DISASSEMBLY_RE = re.compile(r"^(=>)?\s*(0x[0-9a-fA-F]+)\s+<([^>]*)>:\s*(.*)$")
_MEMORY_ROW_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+)(?:\s+<[^>]+>)?:\s*(.*)$")
_BYTE_RE = re.compile(r"0x([0-9a-fA-F]{1,2})$")


def gdb_quote(value: str) -> str:
    """Quote a string for GDB CLI commands when needed."""

    if not value:
        return '""'
    if re.search(r"\s", value) or any(ch in value for ch in ['"', "\\"]):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def normalize_windows_path(path: str | None) -> str | None:
    """Normalize Windows local paths for GDB CLI consumption.

    GDB on Windows accepts forward slashes more predictably than raw
    backslashes because backslashes can be treated as escapes inside CLI
    strings. Linux remote target paths are returned unchanged.
    """

    if path is None:
        return None
    normalized = path.strip()
    if not normalized:
        return normalized
    if normalized.startswith(("/", "~")):
        return normalized
    if WINDOWS_PATH_NORMALIZE:
        normalized = normalized.replace("\\", "/")
    return normalized


def quote_gdb_path(path: str) -> str:
    """Return a path string suitable for embedding in a GDB CLI command."""

    normalized = normalize_windows_path(path) or ""
    return '"' + normalized.replace('"', '\\"') + '"'


def resolve_path(path: str | None, workdir: str | None = None) -> str | None:
    """Resolve a user path against an optional working directory."""

    if path is None:
        return None
    p = Path(path)
    if not p.is_absolute() and workdir:
        p = Path(workdir) / p
    return normalize_windows_path(str(p.resolve()))


def extract_mi_streams(records: list[dict[str, Any]]) -> tuple[str, str]:
    """Collect console/target output as stdout and log/error output as stderr."""

    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    for record in records or []:
        record_type = record.get("type")
        payload = record.get("payload")
        if payload is None:
            continue
        if not isinstance(payload, str):
            payload = str(payload)
        if record_type in {"console", "target", "output"}:
            stdout_parts.append(payload)
        elif record_type in {"log", "notify"}:
            stderr_parts.append(payload)
        elif record_type == "result" and record.get("message") == "error":
            stderr_parts.append(payload)
    return "".join(stdout_parts), "".join(stderr_parts)


def mi_has_error(records: list[dict[str, Any]]) -> str | None:
    """Return a MI error message if the response contains one."""

    for record in records or []:
        if record.get("type") == "result" and record.get("message") == "error":
            payload = record.get("payload")
            if isinstance(payload, dict):
                return str(payload.get("msg") or payload)
            return str(payload)
    return None


def parse_registers(text: str) -> dict[str, Any]:
    """Parse ``info registers`` output into a dictionary."""

    registers: dict[str, Any] = {}
    for line in text.splitlines():
        match = _REGISTER_RE.match(line)
        if not match:
            continue
        name, value, rest = match.groups()
        registers[name] = {"value": value, "detail": (rest or "").strip()}
    return registers


def parse_backtrace(text: str) -> list[dict[str, Any]]:
    """Parse common ``bt`` output."""

    frames: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _BACKTRACE_RE.match(line.strip())
        if not match:
            continue
        level, address, rest = match.groups()
        frames.append({"level": int(level), "address": address, "text": rest.strip(), "raw": line})
    return frames


def parse_breakpoints(text: str) -> list[dict[str, Any]]:
    """Parse ``info breakpoints`` output into a best-effort list."""

    breakpoints: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("Num") or stripped.startswith("No breakpoints"):
            continue
        match = _BREAKPOINT_RE.match(stripped)
        if match:
            number, btype, disposition, enabled, address, what = match.groups()
            breakpoints.append(
                {
                    "number": int(number),
                    "type": btype.strip(),
                    "disposition": disposition,
                    "enabled": enabled == "y",
                    "address": address,
                    "what": what,
                    "raw": line,
                }
            )
            continue
        match = _BREAKPOINT_FALLBACK_RE.match(stripped)
        if match:
            breakpoints.append({"number": int(match.group(1)), "raw": line})
    return breakpoints


def parse_disassembly(text: str) -> list[dict[str, Any]]:
    """Parse GDB disassembly output."""

    instructions: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        match = _DISASSEMBLY_RE.match(stripped)
        if match:
            current, address, symbol, instruction = match.groups()
            instructions.append(
                {
                    "current": bool(current),
                    "address": address,
                    "symbol": symbol,
                    "instruction": instruction.strip(),
                    "raw": line,
                }
            )
    return instructions


def parse_memory_examine(text: str) -> list[dict[str, Any]]:
    """Parse GDB ``x/...`` memory examine output."""

    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _MEMORY_ROW_RE.match(line)
        if not match:
            continue
        address, values_text = match.groups()
        values = [part for part in _SPACE_RE.split(values_text.strip()) if part]
        rows.append({"address": address, "values": values, "raw": line})
    return rows


def parse_mappings(text: str) -> list[dict[str, Any]]:
    """Parse Linux ``info proc mappings`` output."""

    mappings: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("0x"):
            continue
        parts = stripped.split()
        if len(parts) < 4:
            continue
        mapping = {
            "start": parts[0],
            "end": parts[1],
            "size": parts[2],
            "offset": parts[3],
            "perms": parts[4] if len(parts) > 4 else None,
            "path": parts[5] if len(parts) > 5 else None,
            "raw": line,
        }
        mappings.append(mapping)
    return mappings


def parse_info_files(text: str) -> dict[str, Any]:
    """Parse selected fields from ``info files`` output."""

    data: dict[str, Any] = {"raw_lines": text.splitlines()}
    entry_match = re.search(r"Entry point:\s*(0x[0-9a-fA-F]+)", text)
    if entry_match:
        data["entry"] = entry_match.group(1)
    symbols_match = re.search(r"Symbols from \"([^\"]+)\"", text)
    if symbols_match:
        data["symbols_from"] = symbols_match.group(1)
    return data


def parse_functions_or_variables(text: str) -> list[str]:
    """Extract symbol-like lines from ``info functions`` or ``info variables``."""

    items: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.endswith(":") or stripped.startswith("All "):
            continue
        items.append(stripped)
    return items


def parse_sharedlibrary(text: str) -> list[dict[str, Any]]:
    """Parse ``info sharedlibrary`` output into best-effort records."""

    libraries: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("From") or stripped.startswith("No shared"):
            continue
        parts = stripped.split()
        if len(parts) >= 4 and parts[0].startswith("0x") and parts[1].startswith("0x"):
            libraries.append(
                {
                    "from": parts[0],
                    "to": parts[1],
                    "syms_read": parts[2],
                    "path": " ".join(parts[3:]),
                    "raw": line,
                }
            )
        else:
            libraries.append({"raw": line})
    return libraries


def parse_cli_common(command: str, stdout: str) -> dict[str, Any]:
    """Best-effort parser for common GDB CLI commands."""

    cmd = command.strip().lower()
    if cmd.startswith("info registers") or cmd == "i r":
        return {"registers": parse_registers(stdout)}
    if cmd.startswith("info break") or cmd in {"i b", "info b"}:
        return {"breakpoints": parse_breakpoints(stdout)}
    if cmd == "bt" or cmd.startswith("backtrace"):
        return {"backtrace": parse_backtrace(stdout)}
    if cmd.startswith("x/"):
        return {"memory": parse_memory_examine(stdout)}
    if cmd.startswith("disassemble") or cmd.startswith("disas"):
        return {"instructions": parse_disassembly(stdout)}
    if cmd.startswith("info proc mappings"):
        return {"mappings": parse_mappings(stdout)}
    if cmd.startswith("info files"):
        return {"files": parse_info_files(stdout)}
    if cmd.startswith("info sharedlibrary") or cmd.startswith("info shared"):
        return {"shared_libraries": parse_sharedlibrary(stdout)}
    if cmd.startswith("info functions") or cmd.startswith("info variables"):
        return {"symbols": parse_functions_or_variables(stdout)}
    return {}


def parse_hex_bytes(data_hex: str) -> bytes:
    """Parse a hex string such as ``414243`` or ``0x41 0x42 0x43``."""

    cleaned = data_hex.strip()
    if "\\x" in cleaned:
        cleaned = cleaned.replace("\\x", " ")
    cleaned = cleaned.replace(",", " ").replace("0x", " ")
    parts = [part for part in _SPACE_RE.split(cleaned) if part]
    if len(parts) == 1 and len(parts[0]) > 2:
        text = parts[0]
        if len(text) % 2 != 0:
            text = "0" + text
        return bytes.fromhex(text)
    return bytes(int(part, 16) & 0xFF for part in parts)


def ascii_preview(data: bytes) -> str:
    """Return printable ASCII preview for memory bytes."""

    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def bytes_from_xb_output(text: str) -> bytes:
    """Extract byte values from ``x/Nxb`` output."""

    values: list[int] = []
    for row in parse_memory_examine(text):
        for value in row["values"]:
            match = _BYTE_RE.match(value)
            if match:
                values.append(int(match.group(1), 16))
    return bytes(values)


def parse_int_expression(value: str) -> int | None:
    """Parse simple numeric address strings."""

    try:
        return int(value, 0)
    except Exception:
        return None


def run_host_command(args: list[str], timeout: int = 10, cwd: str | None = None) -> dict[str, Any]:
    """Run a local read-only helper command and return structured output."""

    executable = shutil.which(args[0])
    if not executable:
        return {"ok": False, "error": f"{args[0]} not found", "stdout": "", "stderr": ""}
    try:
        completed = subprocess.run(
            [executable, *args[1:]],
            cwd=cwd,
            timeout=timeout,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "stdout": "", "stderr": ""}


def shell_join(args: list[str]) -> str:
    """Return a display string for command arguments."""

    if os.name == "nt":
        return subprocess.list2cmdline(args)
    return shlex.join(args)
