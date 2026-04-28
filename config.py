"""Runtime configuration for gdb-mcp.

Every setting can be overridden with an environment variable prefixed with
``GDB_MCP_``.  This keeps the checked-in defaults usable for the current local
setup while allowing the same code to run cleanly on another Windows host,
Linux VM, CI runner, or editor-managed MCP environment.
"""

from __future__ import annotations

import os


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean config value from the environment."""

    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Read a positive integer config value with a safe fallback."""

    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(0, int(raw.strip()))
    except ValueError:
        return default


def _env_str(name: str, default: str) -> str:
    """Read a string config value from the environment."""

    return os.environ.get(name, default).strip()


GDB_PATH = _env_str("GDB_MCP_GDB_PATH", "gdb")
DEFAULT_TIMEOUT = _env_int("GDB_MCP_DEFAULT_TIMEOUT", 10)
DEFAULT_REMOTE_TIMEOUT = _env_int("GDB_MCP_DEFAULT_REMOTE_TIMEOUT", 10)

MAX_MEMORY_READ = _env_int("GDB_MCP_MAX_MEMORY_READ", 4096)
MAX_MEMORY_WRITE = _env_int("GDB_MCP_MAX_MEMORY_WRITE", 4096)
MAX_MEMORY_DUMP_WITHOUT_CONFIRM = _env_int("GDB_MCP_MAX_MEMORY_DUMP_WITHOUT_CONFIRM", 4096)
MAX_STEP_COUNT = _env_int("GDB_MCP_MAX_STEP_COUNT", 1000)

ENABLE_RAW_GDB_EXEC = _env_bool("GDB_MCP_ENABLE_RAW_GDB_EXEC", True)
ENABLE_RAW_GDB_MI = _env_bool("GDB_MCP_ENABLE_RAW_GDB_MI", True)
ENABLE_PWNDBG_COMMANDS = _env_bool("GDB_MCP_ENABLE_PWNDBG_COMMANDS", True)

HIGH_RISK_CONFIRM_REQUIRED = _env_bool("GDB_MCP_HIGH_RISK_CONFIRM_REQUIRED", True)
ALLOW_DANGEROUS_COMMANDS_WITH_CONFIRM = _env_bool(
    "GDB_MCP_ALLOW_DANGEROUS_COMMANDS_WITH_CONFIRM",
    True,
)
ALLOW_TARGET_REMOTE_WITH_CONFIRM = _env_bool("GDB_MCP_ALLOW_TARGET_REMOTE_WITH_CONFIRM", True)
ALLOW_TARGET_EXTENDED_REMOTE_WITH_CONFIRM = _env_bool(
    "GDB_MCP_ALLOW_TARGET_EXTENDED_REMOTE_WITH_CONFIRM",
    True,
)

REMOTE_DEBUG_ENABLED = _env_bool("GDB_MCP_REMOTE_DEBUG_ENABLED", True)
DEFAULT_REMOTE_MODE = _env_str("GDB_MCP_DEFAULT_REMOTE_MODE", "remote")
REMOTE_STATUS_CACHE = _env_bool("GDB_MCP_REMOTE_STATUS_CACHE", True)
AUTO_APPLY_REMOTE_PATHS = _env_bool("GDB_MCP_AUTO_APPLY_REMOTE_PATHS", True)
DEFAULT_SYSROOT = _env_str("GDB_MCP_DEFAULT_SYSROOT", "E:/ctftimu/pwn/ctf_debug")
DEFAULT_SOLIB_SEARCH_PATH = _env_str(
    "GDB_MCP_DEFAULT_SOLIB_SEARCH_PATH",
    "E:/ctftimu/pwn/ctf_debug/lib/x86_64-linux-gnu;E:/ctftimu/pwn/ctf_debug/lib64",
)
DEFAULT_DEBUG_FILE_DIRECTORY = _env_str(
    "GDB_MCP_DEFAULT_DEBUG_FILE_DIRECTORY",
    "E:/ctftimu/pwn/ctf_debug/usr/lib/debug",
)

WINDOWS_PATH_NORMALIZE = _env_bool("GDB_MCP_WINDOWS_PATH_NORMALIZE", True)
LOG_LEVEL = _env_str("GDB_MCP_LOG_LEVEL", "INFO")
