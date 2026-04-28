"""Smoke test for the GDB controller.

Run from the repository root:
    python tests/smoke_test.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from pygdbmi.gdbcontroller import GdbController as _PygdbmiController  # noqa: F401
except ImportError:
    print("SKIP: pygdbmi not installed; run `pip install -e .` first")
    raise SystemExit(0)

from gdb_controller import GdbController
from utils import gdb_quote


def require(ok: bool, message: str, detail: object | None = None) -> None:
    if not ok:
        raise AssertionError(f"{message}: {detail!r}")


def build_example() -> Path:
    target = ROOT / "examples" / "hello_noprotection"
    if target.exists():
        return target
    gcc = shutil.which("gcc")
    if not gcc:
        raise RuntimeError("gcc not found; cannot build example")
    linux_flags = ["-g", "-fno-stack-protector", "-z", "execstack", "-no-pie"]
    portable_flags = ["-g", "-fno-stack-protector"]
    flag_sets = [linux_flags, portable_flags] if os.name == "nt" else [linux_flags]
    last_error: subprocess.CalledProcessError | None = None
    for flags in flag_sets:
        try:
            subprocess.run(
                [gcc, *flags, "-o", str(target), str(ROOT / "examples" / "hello.c")],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return target
        except subprocess.CalledProcessError as exc:
            last_error = exc
    if last_error:
        raise last_error
    return target


def main() -> None:
    if not shutil.which("gdb"):
        print("SKIP: gdb not found")
        return
    binary = build_example()
    gdb = GdbController(workdir=str(ROOT))
    status = gdb.start()
    require(status["running"], "failed to start GDB", status)

    try:
        res = gdb.execute_cli(f"file {gdb_quote(str(binary))}", timeout=10)
        require(res.ok, "failed to load example binary", res)
        res = gdb.execute_cli("break main", timeout=10)
        require(res.ok, "failed to set breakpoint at main", res)
        res = gdb.execute_cli("run", timeout=10)
        require(res.ok, "failed to run example binary", res)
        regs = gdb.execute_cli("info registers", timeout=10)
        require(regs.ok and "registers" in (regs.data or {}), "failed to read registers", regs)
        stack = gdb.execute_cli("x/8gx $sp", timeout=10)
        if not stack.ok:
            stack = gdb.execute_cli("x/8wx $sp", timeout=10)
        require(stack.ok, "failed to read stack", stack)
        disasm = gdb.execute_cli("disassemble main", timeout=10)
        require(disasm.ok, "failed to disassemble main", disasm)
        cont = gdb.execute_cli("continue", timeout=3)
        require(cont.ok or cont.timeout or bool(cont.error), "continue returned an unexpected empty result", cont)

        remote_host = os.environ.get("GDB_MCP_REMOTE_HOST")
        remote_port = os.environ.get("GDB_MCP_REMOTE_PORT")
        remote_binary = os.environ.get("GDB_MCP_REMOTE_BINARY")
        local_binary = os.environ.get("GDB_MCP_LOCAL_BINARY")
        remote_mode = os.environ.get("GDB_MCP_REMOTE_MODE", "remote")
        if remote_host and remote_port and local_binary:
            remote = gdb.connect_remote(
                host=remote_host,
                port=int(remote_port),
                mode=remote_mode,
                local_binary=local_binary,
                remote_binary=remote_binary,
                timeout=10,
            )
            require(remote["ok"], "failed optional remote gdbserver connection", remote)
            regs = gdb.execute_cli("info registers", timeout=10)
            require(regs.ok, "failed to read remote registers", regs)
    finally:
        gdb.stop()
    print("smoke test passed")


if __name__ == "__main__":
    main()
