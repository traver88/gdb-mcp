import unittest
from unittest.mock import patch

from tools_remote import gdb_context, gdb_remote
from gdb_controller import CommandResult


def _result(command: str, ok: bool = True, stdout: str = "", data: dict | None = None, error: str | None = None) -> CommandResult:
    return CommandResult(ok=ok, command=command, stdout=stdout, stderr="", raw=[], data=data or {}, error=error)


class RemoteToolTests(unittest.TestCase):
    def test_gdb_remote_status_returns_cached_status(self) -> None:
        with patch("tools_remote.controller.remote_status", return_value={"connected": False, "host": None}):
            result = gdb_remote(action="status")
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["connected"], False)

    def test_gdb_remote_connect_requires_confirm_for_remote_target(self) -> None:
        result = gdb_remote(action="connect", host="127.0.0.1", port=1234)
        self.assertFalse(result["ok"])
        self.assertTrue(result["need_confirm"])

    @patch("tools_remote.controller.remote_status")
    @patch("tools_remote.controller.setup_remote")
    @patch("tools_remote.controller.start")
    def test_gdb_remote_setup_without_commands_returns_empty_success(self, mock_start, mock_setup, mock_remote_status) -> None:
        mock_remote_status.return_value = {"connected": False}
        result = gdb_remote(action="setup")
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["results"], [])
        mock_start.assert_not_called()
        mock_setup.assert_not_called()

    @patch("tools_remote.controller.set_sysroot")
    def test_gdb_remote_set_sysroot_requires_confirm(self, mock_setter) -> None:
        result = gdb_remote(action="set_sysroot", sysroot="E:/symbols")
        self.assertFalse(result["ok"])
        self.assertTrue(result["need_confirm"])
        mock_setter.assert_not_called()

    @patch("tools_remote.exec_cli_internal")
    @patch("tools_remote.controller.remote_status")
    def test_gdb_context_returns_register_and_stack_summary(self, mock_remote_status, mock_exec) -> None:
        mock_remote_status.return_value = {"connected": False}
        mock_exec.side_effect = [
            _result("info registers", stdout="rip 0x401000\nrsp 0x7fffffffe000", data={"registers": {"rip": {"value": "0x401000"}, "rsp": {"value": "0x7fffffffe000"}}}),
            _result("x/i $pc", stdout="=> 0x401000 <main>: ret"),
            _result("x/16i $pc-32", stdout="=> 0x401000 <main>: ret"),
            _result("x/20gx $sp", stdout="0x7fffffffe000: 0x0000000000000000"),
            _result("bt", stdout="#0  main\n#1  start"),
            _result("info breakpoints", stdout="No breakpoints or watchpoints."),
            _result("info proc mappings", stdout=""),
            _result("info sharedlibrary", stdout=""),
            _result("frame", stdout="#0  main"),
            _result("info threads", stdout="* 1 Thread 1"),
        ]

        result = gdb_context()

        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["pc"], "0x401000")
        self.assertEqual(result["data"]["sp"], "0x7fffffffe000")


if __name__ == "__main__":
    unittest.main()
