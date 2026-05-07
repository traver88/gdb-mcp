import unittest
from unittest.mock import patch

from tools_control import gdb_breakpoint, gdb_register, gdb_run_control
from gdb_controller import CommandResult


def _result(command: str, ok: bool = True, stdout: str = "", error: str | None = None) -> CommandResult:
    return CommandResult(ok=ok, command=command, stdout=stdout, stderr="", raw=[], data={}, error=error)


class ControlToolTests(unittest.TestCase):
    @patch("tools_control.exec_cli_internal")
    def test_gdb_register_read_uses_p_x(self, mock_exec) -> None:
        mock_exec.return_value = _result("p/x $rip", stdout="$1 = 0x401000")
        result = gdb_register(action="read", name="rip")
        self.assertTrue(result["ok"])
        self.assertEqual(result["command"], "p/x $rip")

    @patch("tools_control.exec_cli_internal")
    def test_gdb_breakpoint_list_reads_info_breakpoints(self, mock_exec) -> None:
        mock_exec.return_value = _result("info breakpoints", stdout="No breakpoints or watchpoints.")
        result = gdb_breakpoint(action="list")
        self.assertTrue(result["ok"])
        self.assertEqual(result["command"], "info breakpoints")

    @patch("tools_control.controller.remote_status")
    def test_gdb_run_control_remote_run_is_rejected(self, mock_remote_status) -> None:
        mock_remote_status.return_value = {"connected": True, "mode": "remote", "remote_binary": None}
        result = gdb_run_control(action="run")
        self.assertFalse(result["ok"])
        self.assertIn("target remote", result["error"])

    @patch("tools_control.gdb_context")
    @patch("tools_control.exec_cli_internal")
    @patch("tools_control.controller.remote_status")
    def test_gdb_run_control_continue_returns_context_summary(self, mock_remote_status, mock_exec, mock_context) -> None:
        mock_remote_status.return_value = {"connected": False}
        mock_exec.return_value = _result("continue", stdout="Continuing.")
        mock_context.return_value = {"data": {"remote": {"connected": False}, "pc": "0x401000", "sp": "0x7fffffffe000", "current_instruction": {}, "registers": {}, "backtrace": {"data": []}}}

        result = gdb_run_control(action="continue")

        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["context_summary"]["pc"], "0x401000")


if __name__ == "__main__":
    unittest.main()
