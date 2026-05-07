import unittest
from unittest.mock import patch

from gdb_controller import CommandResult
from tools_meta import gdb_capabilities, gdb_snapshot


class MetaToolTests(unittest.TestCase):
    def test_gdb_capabilities_returns_policy_flags(self) -> None:
        result = gdb_capabilities()
        self.assertTrue(result["ok"])
        self.assertIn("read_only_mode", result["data"])
        self.assertIn("remote_debugging", result["data"])

    def test_gdb_snapshot_show_returns_session_summary(self) -> None:
        result = gdb_snapshot(action="show")
        self.assertTrue(result["ok"])
        self.assertIn("status", result["data"])
        self.assertIn("remote", result["data"])

    def test_gdb_snapshot_save_list_restore_cycle(self) -> None:
        with patch("tools_meta.controller.workdir", None):
            save_result = gdb_snapshot(action="save", name="unit_test_snapshot")
            self.assertTrue(save_result["ok"])
            list_result = gdb_snapshot(action="list")
            self.assertTrue(list_result["ok"])
            self.assertIn("unit_test_snapshot", list_result["data"]["snapshots"])
            restore_result = gdb_snapshot(action="restore", name="unit_test_snapshot")
            self.assertTrue(restore_result["ok"])
            self.assertEqual(restore_result["data"]["name"], "unit_test_snapshot")
            self.assertIn("restore", restore_result["data"])

    @patch("tools_meta.controller.connect_remote")
    @patch("tools_meta.controller.set_remote_exec_file")
    @patch("tools_meta.controller.set_debug_file_directory")
    @patch("tools_meta.controller.set_solib_search_path")
    @patch("tools_meta.controller.set_sysroot")
    @patch("tools_meta.controller.execute_cli")
    @patch("tools_meta.controller.start")
    def test_gdb_snapshot_restore_replays_runtime_state(
        self,
        mock_start,
        mock_execute_cli,
        mock_set_sysroot,
        mock_set_solib,
        mock_set_debug,
        mock_set_remote_exec,
        mock_connect_remote,
    ) -> None:
        ok_result = CommandResult(ok=True, command="cmd", stdout="", stderr="", raw=[], data={}, error=None)
        mock_start.return_value = {"running": True}
        mock_execute_cli.return_value = ok_result
        mock_set_sysroot.return_value = ok_result
        mock_set_solib.return_value = ok_result
        mock_set_debug.return_value = ok_result
        mock_set_remote_exec.return_value = ok_result
        mock_connect_remote.return_value = {"ok": True}

        snapshot = {
            "status": {"gdb_path": "gdb", "workdir": "E:/tmp"},
            "remote": {
                "connected": True,
                "host": "127.0.0.1",
                "port": 1234,
                "mode": "extended-remote",
                "local_binary": "E:/bin/pwn",
                "remote_binary": "/tmp/pwn",
                "sysroot": "E:/sysroot",
                "solib_search_path": "E:/solib",
                "debug_file_directory": "E:/debug",
                "architecture": "i386:x86-64",
                "last_remote_output": {"ok": True},
            },
            "binary": "E:/bin/pwn",
            "core": "E:/bin/core",
            "symbol_file": "E:/bin/pwn.sym",
            "last_command": "bt",
            "inferior_state": "stopped:breakpoint-hit",
        }

        with patch("tools_meta._snapshot_dir") as mock_dir:
            from pathlib import Path

            temp_dir = Path.cwd() / ".gdb-mcp-snapshots-test"
            temp_dir.mkdir(parents=True, exist_ok=True)
            target = temp_dir / "restore_case.json"
            target.write_text(__import__("json").dumps(snapshot), encoding="utf-8")
            mock_dir.return_value = temp_dir
            result = gdb_snapshot(action="restore", name="restore_case")

        self.assertTrue(result["ok"])
        mock_start.assert_called_once()
        self.assertGreaterEqual(mock_execute_cli.call_count, 3)
        mock_set_sysroot.assert_called_once()
        mock_set_solib.assert_called_once()
        mock_set_debug.assert_called_once()
        mock_set_remote_exec.assert_called_once()
        mock_connect_remote.assert_called_once()

    def test_gdb_snapshot_rejects_unknown_action(self) -> None:
        result = gdb_snapshot(action="unknown")
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
