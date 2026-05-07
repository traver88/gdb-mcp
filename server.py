"""MCP server exposing high-permission GDB automation tools."""

from __future__ import annotations

from server_runtime import context_summary as _context_summary
from server_runtime import mcp
from tools_advanced import gdb_analyze, gdb_elf, gdb_exec, gdb_mi, gdb_pwndbg
from tools_control import gdb_breakpoint, gdb_register, gdb_run_control
from tools_memory import gdb_memory
from tools_meta import gdb_capabilities, gdb_snapshot
from tools_remote import gdb_context, gdb_remote
from tools_session import gdb_load, gdb_session


def main() -> None:
    """Run the MCP server over stdio."""

    mcp.run()


if __name__ == "__main__":
    main()
