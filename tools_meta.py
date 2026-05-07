"""Snapshot and metadata MCP tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from config import DEFAULT_REMOTE_TIMEOUT, DEFAULT_TIMEOUT
from models import make_result
from server_runtime import controller, mcp


_SNAPSHOT_DIRNAME = ".gdb-mcp-snapshots"


def _snapshot_dir() -> Path:
    root = Path(controller.workdir or Path.cwd())
    path = root / _SNAPSHOT_DIRNAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def _build_snapshot() -> dict[str, Any]:
    return {
        "status": controller.status(),
        "remote": controller.remote_status(),
        "binary": controller.current_binary,
        "core": controller.current_core,
        "symbol_file": controller.current_symbol_file,
        "last_command": controller.last_command,
        "inferior_state": controller.current_inferior_state,
    }


def _restore_snapshot_state(restored: dict[str, Any]) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    status = restored.get("status", {})
    remote = restored.get("remote", {})
    binary = restored.get("binary")
    core = restored.get("core")
    symbol_file = restored.get("symbol_file")

    start_result = controller.start(
        gdb_path=status.get("gdb_path"),
        workdir=status.get("workdir"),
    )
    operations.append({"step": "start", "result": start_result})

    if binary:
        result = controller.execute_cli(f"file {controller.quote_gdb_path(binary)}", timeout=DEFAULT_TIMEOUT, parse=True)
        operations.append({"step": "file", "ok": result.ok, "error": result.error})
        if result.ok:
            controller.current_binary = binary

    if symbol_file:
        result = controller.execute_cli(f"symbol-file {controller.quote_gdb_path(symbol_file)}", timeout=DEFAULT_TIMEOUT, parse=True)
        operations.append({"step": "symbol-file", "ok": result.ok, "error": result.error})
        if result.ok:
            controller.current_symbol_file = symbol_file

    if core:
        result = controller.execute_cli(f"core-file {controller.quote_gdb_path(core)}", timeout=DEFAULT_TIMEOUT, parse=True)
        operations.append({"step": "core-file", "ok": result.ok, "error": result.error})
        if result.ok:
            controller.current_core = core

    if remote.get("sysroot"):
        result = controller.set_sysroot(remote["sysroot"], timeout=DEFAULT_TIMEOUT)
        operations.append({"step": "set_sysroot", "ok": result.ok, "error": result.error})
    if remote.get("solib_search_path"):
        result = controller.set_solib_search_path(remote["solib_search_path"], timeout=DEFAULT_TIMEOUT)
        operations.append({"step": "set_solib_search_path", "ok": result.ok, "error": result.error})
    if remote.get("debug_file_directory"):
        result = controller.set_debug_file_directory(remote["debug_file_directory"], timeout=DEFAULT_TIMEOUT)
        operations.append({"step": "set_debug_file_directory", "ok": result.ok, "error": result.error})
    if remote.get("remote_binary") and remote.get("mode") == "extended-remote":
        result = controller.set_remote_exec_file(remote["remote_binary"], timeout=DEFAULT_TIMEOUT)
        operations.append({"step": "set_remote_exec_file", "ok": result.ok, "error": result.error})

    if remote.get("connected") and remote.get("host") and remote.get("port"):
        connect_result = controller.connect_remote(
            host=remote["host"],
            port=int(remote["port"]),
            mode=remote.get("mode") or "remote",
            local_binary=remote.get("local_binary") or binary,
            remote_binary=remote.get("remote_binary"),
            sysroot=remote.get("sysroot"),
            solib_search_path=remote.get("solib_search_path"),
            debug_file_directory=remote.get("debug_file_directory"),
            architecture=remote.get("architecture"),
            timeout=DEFAULT_REMOTE_TIMEOUT,
        )
        operations.append({"step": "connect_remote", "result": connect_result})

    controller.last_command = restored.get("last_command")
    controller.current_inferior_state = restored.get("inferior_state")
    controller.last_remote_output = remote.get("last_remote_output")

    return {"operations": operations, "status": controller.status(), "remote": controller.remote_status()}


@mcp.tool()
def gdb_snapshot(action: str = "save", name: str = "default") -> dict[str, Any]:
    """Save, show, list, or restore a lightweight session snapshot."""

    try:
        action_l = action.lower()
        snapshot = _build_snapshot()
        target = _snapshot_dir() / f"{name}.json"

        if action_l == "show":
            return make_result(ok=True, tool="gdb_snapshot", action=action_l, data=snapshot)

        if action_l == "save":
            target.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
            return make_result(ok=True, tool="gdb_snapshot", action=action_l, data={"name": name, "path": str(target), "snapshot": snapshot})

        if action_l == "list":
            snapshots = sorted(item.stem for item in _snapshot_dir().glob("*.json"))
            return make_result(ok=True, tool="gdb_snapshot", action=action_l, data={"snapshots": snapshots})

        if action_l == "restore":
            if not target.exists():
                return make_result(ok=False, tool="gdb_snapshot", action=action_l, error=f"snapshot not found: {name}")
            restored = json.loads(target.read_text(encoding="utf-8"))
            restore_data = _restore_snapshot_state(restored)
            return make_result(ok=True, tool="gdb_snapshot", action=action_l, data={"name": name, "snapshot": restored, "restore": restore_data})

        return make_result(ok=False, tool="gdb_snapshot", action=action_l, error=f"unsupported action: {action}")
    except Exception as exc:
        return make_result(ok=False, tool="gdb_snapshot", action=action, error=str(exc))


@mcp.tool()
def gdb_capabilities() -> dict[str, Any]:
    """Return server capabilities and current policy flags."""

    from config import ENABLE_PWNDBG_COMMANDS, ENABLE_RAW_GDB_EXEC, ENABLE_RAW_GDB_MI, READ_ONLY_MODE, REMOTE_DEBUG_ENABLED

    data = {
        "raw_gdb_exec": ENABLE_RAW_GDB_EXEC,
        "raw_gdb_mi": ENABLE_RAW_GDB_MI,
        "pwndbg_commands": ENABLE_PWNDBG_COMMANDS,
        "remote_debugging": REMOTE_DEBUG_ENABLED,
        "read_only_mode": READ_ONLY_MODE,
    }
    return make_result(ok=True, tool="gdb_capabilities", action="list", data=data)
