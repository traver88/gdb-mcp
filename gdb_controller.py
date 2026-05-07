"""GDB/MI controller built on pygdbmi."""

from __future__ import annotations

import atexit
import json
import os
import signal
import threading
from dataclasses import dataclass
from typing import Any

from config import (
    AUTO_APPLY_REMOTE_PATHS,
    DEFAULT_DEBUG_FILE_DIRECTORY,
    DEFAULT_REMOTE_MODE,
    DEFAULT_REMOTE_TIMEOUT,
    DEFAULT_SOLIB_SEARCH_PATH,
    DEFAULT_SYSROOT,
    DEFAULT_TIMEOUT,
    GDB_PATH,
)
from utils import extract_mi_streams, gdb_quote, mi_has_error, normalize_windows_path, parse_cli_common, quote_gdb_path


@dataclass
class CommandResult:
    """Internal result for GDB command execution."""

    ok: bool
    command: str
    stdout: str = ""
    stderr: str = ""
    raw: list[dict[str, Any]] | None = None
    data: dict[str, Any] | None = None
    error: str | None = None
    timeout: bool = False


class GdbController:
    """Owns a single GDB/MI process and exposes CLI/MI execution helpers."""

    def __init__(
        self,
        gdb_path: str = GDB_PATH,
        workdir: str | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self.gdb_path = gdb_path
        self.workdir = workdir
        self.extra_args = extra_args or []
        self._gdbmi: Any | None = None
        self._lock = threading.RLock()
        self.current_binary: str | None = None
        self.current_core: str | None = None
        self.current_symbol_file: str | None = None
        self.current_inferior_state: str | None = None
        self.last_command: str | None = None
        self.last_output: Any | None = None
        self.gdb_version: str | None = None

        self.remote_enabled = True
        self.remote_connected = False
        self.remote_host: str | None = None
        self.remote_port: int | None = None
        self.remote_mode: str = DEFAULT_REMOTE_MODE
        self.local_binary: str | None = None
        self.remote_binary: str | None = None
        self.sysroot: str | None = None
        self.solib_search_path: str | None = None
        self.debug_file_directory: str | None = None
        self.architecture: str | None = None
        self.last_remote_output: Any | None = None
        atexit.register(self.stop)

    @property
    def is_running(self) -> bool:
        return self._gdbmi is not None

    @property
    def pid(self) -> int | None:
        if not self._gdbmi:
            return None
        process = getattr(self._gdbmi, "gdb_process", None)
        return getattr(process, "pid", None)

    def start(
        self,
        gdb_path: str | None = None,
        workdir: str | None = None,
        extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        """Start ``gdb --interpreter=mi2`` if it is not already running."""

        with self._lock:
            if self._gdbmi is not None:
                return self.status()
            if gdb_path:
                self.gdb_path = gdb_path
            if workdir:
                self.workdir = workdir
            if extra_args is not None:
                self.extra_args = list(extra_args)

            try:
                from pygdbmi.gdbcontroller import GdbController as PygdbmiController

                command = [self.gdb_path, "--interpreter=mi2", "--quiet", *self.extra_args]
                try:
                    self._gdbmi = PygdbmiController(
                        command=command,
                        time_to_check_for_additional_output_sec=0.1,
                    )
                except TypeError:
                    self._gdbmi = PygdbmiController(command=command)
                self._drain(1)
                if self.workdir:
                    self.execute_cli(
                        f"cd {self.quote_gdb_path(self.workdir)}",
                        timeout=DEFAULT_TIMEOUT,
                        parse=False,
                    )
                version = self.execute_cli("show version", timeout=DEFAULT_TIMEOUT, parse=False)
                if version.ok:
                    version_lines = version.stdout.splitlines()
                    self.gdb_version = version_lines[0] if version_lines else version.stdout.strip()
                return self.status()
            except Exception as exc:
                self._gdbmi = None
                return {
                    "running": False,
                    "error": str(exc),
                    "gdb_path": self.gdb_path,
                    "workdir": self.workdir,
                }

    def stop(self) -> dict[str, Any]:
        """Stop GDB and clean up the subprocess."""

        with self._lock:
            if self._gdbmi is None:
                return self.status()
            process = getattr(self._gdbmi, "gdb_process", None)
            try:
                self._gdbmi.exit()
            except Exception:
                try:
                    if process and process.poll() is None:
                        process.terminate()
                except Exception:
                    pass
            try:
                if process and process.poll() is None:
                    process.wait(timeout=2)
            except Exception:
                try:
                    if process and process.poll() is None:
                        process.kill()
                except Exception:
                    pass
            finally:
                self._gdbmi = None
                self.remote_connected = False
                self.current_inferior_state = None
            return self.status()

    def restart(
        self,
        gdb_path: str | None = None,
        workdir: str | None = None,
        extra_args: list[str] | None = None,
    ) -> dict[str, Any]:
        """Restart GDB while preserving controller state fields."""

        self.stop()
        return self.start(gdb_path=gdb_path, workdir=workdir, extra_args=extra_args)

    def status(self) -> dict[str, Any]:
        """Return current debugger status."""

        running = self._gdbmi is not None
        return {
            "running": running,
            "pid": self.pid,
            "gdb_path": self.gdb_path,
            "workdir": self.workdir or os.getcwd(),
            "binary": self.current_binary,
            "core": self.current_core,
            "symbol_file": self.current_symbol_file,
            "inferior_state": self.current_inferior_state,
            "last_command": self.last_command,
            "gdb_version": self.gdb_version,
            "remote_status": self.remote_status(),
        }

    def _ensure_started(self) -> None:
        if self._gdbmi is None:
            status = self.start()
            if not status.get("running"):
                raise RuntimeError(status.get("error") or "failed to start GDB")

    def _drain(self, timeout: int = 1) -> list[dict[str, Any]]:
        if self._gdbmi is None:
            return []
        try:
            return self._gdbmi.get_gdb_response(timeout_sec=timeout, raise_error_on_timeout=False)
        except TypeError:
            try:
                return self._gdbmi.get_gdb_response(timeout_sec=timeout)
            except Exception:
                return []
        except Exception:
            return []

    def _interrupt(self) -> None:
        if self._gdbmi is None:
            return
        try:
            if hasattr(self._gdbmi, "interrupt_gdb"):
                self._gdbmi.interrupt_gdb()
                self._drain(timeout=1)
                return
        except Exception:
            pass
        try:
            self._gdbmi.write("-exec-interrupt", timeout_sec=1, raise_error_on_timeout=False)
        except Exception:
            pass
        process = getattr(self._gdbmi, "gdb_process", None)
        pid = getattr(process, "pid", None)
        if pid and os.name != "nt":
            try:
                os.kill(pid, signal.SIGINT)
            except Exception:
                pass
        self._drain(timeout=1)

    @staticmethod
    def _is_timeout_exception(exc: Exception) -> bool:
        """Return whether an exception looks like a pygdbmi/GDB timeout."""

        exc_text = str(exc).lower()
        return "timeout" in exc.__class__.__name__.lower() or "timed out" in exc_text

    def execute_mi(self, command: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        """Execute a raw GDB/MI command."""

        with self._lock:
            try:
                timeout = max(1, int(timeout or DEFAULT_TIMEOUT))
                self._ensure_started()
                assert self._gdbmi is not None
                self.last_command = command
                try:
                    records = self._gdbmi.write(command, timeout_sec=timeout, raise_error_on_timeout=True)
                except TypeError:
                    records = self._gdbmi.write(command, timeout_sec=timeout)
                stdout, stderr = extract_mi_streams(records)
                error = mi_has_error(records)
                self.last_output = records
                self._update_state_from_records(records)
                return CommandResult(
                    ok=error is None,
                    command=command,
                    stdout=stdout,
                    stderr=stderr,
                    raw=records,
                    data={"mi_records": records},
                    error=error,
                )
            except Exception as exc:
                if self._is_timeout_exception(exc):
                    self._interrupt()
                    return CommandResult(
                        ok=False,
                        command=command,
                        raw=[],
                        error=f"timeout after {timeout}s: {exc}",
                        timeout=True,
                    )
                return CommandResult(ok=False, command=command, raw=[], error=f"{exc.__class__.__name__}: {exc}")

    def execute_cli(self, command: str, timeout: int = DEFAULT_TIMEOUT, parse: bool = True) -> CommandResult:
        """Execute a GDB CLI command through ``-interpreter-exec console``."""

        mi_command = f"-interpreter-exec console {json.dumps(command)}"
        result = self.execute_mi(mi_command, timeout=timeout)
        data: dict[str, Any] = dict(result.data or {})
        if parse and result.stdout:
            data.update(parse_cli_common(command, result.stdout))
        result.command = command
        result.data = data
        return result

    def _update_state_from_records(self, records: list[dict[str, Any]]) -> None:
        for record in records or []:
            message = record.get("message")
            payload = record.get("payload")
            if message == "running":
                self.current_inferior_state = "running"
            elif message == "stopped":
                self.current_inferior_state = "stopped"
            if isinstance(payload, dict):
                if payload.get("reason"):
                    self.current_inferior_state = f"stopped:{payload.get('reason')}"

    def normalize_gdb_path(self, path: str) -> str:
        """Normalize a Windows local path for GDB CLI commands."""

        return normalize_windows_path(path) or ""

    def quote_gdb_path(self, path: str) -> str:
        """Quote a local path for GDB CLI commands."""

        return quote_gdb_path(path)

    def set_sysroot(self, path: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        """Set the remote sysroot used by GDB."""

        self.sysroot = self.normalize_gdb_path(path)
        return self.execute_cli(
            f"set sysroot {gdb_quote(self.sysroot)}",
            timeout=timeout,
            parse=False,
        )

    def set_solib_search_path(self, path: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        """Set the shared-library search path used by GDB."""

        self.solib_search_path = self.normalize_gdb_path(path)
        return self.execute_cli(
            f"set solib-search-path {gdb_quote(self.solib_search_path)}",
            timeout=timeout,
            parse=False,
        )

    def set_debug_file_directory(self, path: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        """Set the local directory where GDB looks for separate debug files."""

        self.debug_file_directory = self.normalize_gdb_path(path)
        return self.execute_cli(
            f"set debug-file-directory {gdb_quote(self.debug_file_directory)}",
            timeout=timeout,
            parse=False,
        )

    def set_remote_exec_file(self, path: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        """Set the Linux target path used by extended-remote run."""

        self.remote_binary = path
        return self.execute_cli(f"set remote exec-file {gdb_quote(path)}", timeout=timeout, parse=False)

    def remote_status(self) -> dict[str, Any]:
        """Return cached remote debugging state."""

        return {
            "enabled": self.remote_enabled,
            "connected": self.remote_connected,
            "host": self.remote_host,
            "port": self.remote_port,
            "mode": self.remote_mode,
            "local_binary": self.local_binary,
            "remote_binary": self.remote_binary,
            "sysroot": self.sysroot,
            "solib_search_path": self.solib_search_path,
            "debug_file_directory": self.debug_file_directory,
            "architecture": self.architecture,
            "inferior_state": self.current_inferior_state,
            "last_remote_output": self.last_remote_output,
        }

    def setup_remote(
        self,
        *,
        local_binary: str | None = None,
        remote_binary: str | None = None,
        sysroot: str | None = None,
        solib_search_path: str | None = None,
        debug_file_directory: str | None = None,
        architecture: str | None = None,
        mode: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> list[CommandResult]:
        """Configure local symbols and remote-target settings without connecting."""

        self._ensure_started()
        if mode:
            self.remote_mode = mode
        results: list[CommandResult] = []
        if AUTO_APPLY_REMOTE_PATHS:
            sysroot = sysroot or DEFAULT_SYSROOT
            solib_search_path = solib_search_path or DEFAULT_SOLIB_SEARCH_PATH
            debug_file_directory = debug_file_directory or DEFAULT_DEBUG_FILE_DIRECTORY
        if local_binary:
            self.local_binary = self.normalize_gdb_path(local_binary)
            self.current_binary = self.local_binary
            results.append(
                self.execute_cli(
                    f"file {self.quote_gdb_path(self.local_binary)}",
                    timeout=timeout,
                    parse=True,
                )
            )
        if architecture:
            self.architecture = architecture
            results.append(self.execute_cli(f"set architecture {architecture}", timeout=timeout, parse=False))
        if sysroot:
            results.append(self.set_sysroot(sysroot, timeout=timeout))
        if solib_search_path:
            results.append(self.set_solib_search_path(solib_search_path, timeout=timeout))
        if debug_file_directory:
            results.append(self.set_debug_file_directory(debug_file_directory, timeout=timeout))
        if remote_binary:
            self.remote_binary = remote_binary
            if (mode or self.remote_mode) == "extended-remote":
                results.append(self.set_remote_exec_file(remote_binary, timeout=timeout))
        return results

    def connect_remote(
        self,
        *,
        host: str,
        port: int,
        mode: str = DEFAULT_REMOTE_MODE,
        local_binary: str | None = None,
        remote_binary: str | None = None,
        sysroot: str | None = None,
        solib_search_path: str | None = None,
        debug_file_directory: str | None = None,
        architecture: str | None = None,
        timeout: int = DEFAULT_REMOTE_TIMEOUT,
    ) -> dict[str, Any]:
        """Connect this Windows-side GDB to a VM-side gdbserver."""

        if mode not in {"remote", "extended-remote"}:
            return {"ok": False, "error": f"unsupported remote mode: {mode}", "results": []}
        self._ensure_started()
        self.remote_host = host
        self.remote_port = int(port)
        self.remote_mode = mode
        setup_results = self.setup_remote(
            local_binary=local_binary,
            remote_binary=remote_binary,
            sysroot=sysroot,
            solib_search_path=solib_search_path,
            debug_file_directory=debug_file_directory,
            architecture=architecture,
            mode=mode,
            timeout=timeout,
        )
        target_command = f"target {mode} {host}:{int(port)}"
        target_result = self.execute_cli(target_command, timeout=timeout, parse=True)
        self.last_remote_output = {
            "command": target_command,
            "ok": target_result.ok,
            "stdout": target_result.stdout,
            "stderr": target_result.stderr,
            "error": target_result.error,
            "raw": target_result.raw,
        }
        self.remote_connected = target_result.ok
        if not target_result.ok:
            self.current_inferior_state = None
        return {
            "ok": target_result.ok,
            "target_command": target_command,
            "setup_results": [
                self._command_result_brief(result)
                for result in setup_results
            ],
            "target_result": self._command_result_brief(target_result),
            "remote_status": self.remote_status(),
            "error": target_result.error,
        }

    def disconnect_remote(self, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
        """Disconnect from gdbserver without killing local GDB."""

        self._ensure_started()
        result = self.execute_cli("disconnect", timeout=timeout, parse=False)
        if result.ok:
            self.remote_connected = False
            self.current_inferior_state = None
        self.last_remote_output = self._command_result_brief(result)
        return {
            "ok": result.ok,
            "result": self._command_result_brief(result),
            "remote_status": self.remote_status(),
            "error": result.error,
        }

    def reconnect_remote(self, timeout: int = DEFAULT_REMOTE_TIMEOUT) -> dict[str, Any]:
        """Reconnect using the cached remote target configuration."""

        if not self.remote_host or not self.remote_port:
            return {"ok": False, "error": "missing cached host/port; call gdb_remote(action='connect', ...) first"}
        self.disconnect_remote(timeout=timeout)
        return self.connect_remote(
            host=self.remote_host,
            port=self.remote_port,
            mode=self.remote_mode,
            local_binary=self.local_binary,
            remote_binary=self.remote_binary,
            sysroot=self.sysroot,
            solib_search_path=self.solib_search_path,
            debug_file_directory=self.debug_file_directory,
            architecture=self.architecture,
            timeout=timeout,
        )

    @staticmethod
    def _command_result_brief(result: CommandResult) -> dict[str, Any]:
        return {
            "command": result.command,
            "ok": result.ok,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "error": result.error,
            "timeout": result.timeout,
            "data": result.data or {},
            "raw": result.raw or {},
        }
