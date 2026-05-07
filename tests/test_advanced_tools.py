import unittest
from unittest.mock import patch

from gdb_controller import CommandResult
from tools_advanced import gdb_analyze, gdb_elf, gdb_exec, gdb_mi, gdb_pwndbg


def _result(command: str, ok: bool = True, stdout: str = "", stderr: str = "", data: dict | None = None, error: str | None = None) -> CommandResult:
    return CommandResult(ok=ok, command=command, stdout=stdout, stderr=stderr, raw=[], data=data or {}, error=error)


class AdvancedToolTests(unittest.TestCase):
    @patch("tools_advanced.controller.execute_cli")
    def test_gdb_exec_runs_low_risk_command(self, mock_exec) -> None:
        mock_exec.return_value = _result("info registers", stdout="rip 0x401000")
        result = gdb_exec("info registers")
        self.assertTrue(result["ok"])
        self.assertEqual(result["command"], "info registers")

    def test_gdb_exec_requires_confirm_for_shell_command(self) -> None:
        result = gdb_exec("shell echo hi")
        self.assertFalse(result["ok"])
        self.assertTrue(result["need_confirm"])

    @patch("tools_advanced.controller.execute_mi")
    def test_gdb_mi_runs_low_risk_command(self, mock_exec) -> None:
        mock_exec.return_value = _result("-thread-info", data={"mi_records": []})
        result = gdb_mi("-thread-info")
        self.assertTrue(result["ok"])
        self.assertEqual(result["command"], "-thread-info")

    def test_gdb_mi_requires_confirm_for_target_select(self) -> None:
        result = gdb_mi("-target-select remote 127.0.0.1:1234")
        self.assertFalse(result["ok"])
        self.assertTrue(result["need_confirm"])

    @patch("tools_advanced.gdb_context")
    @patch("tools_advanced.exec_cli_internal")
    def test_gdb_analyze_summarizes_crash_markers(self, mock_exec, mock_context) -> None:
        mock_context.return_value = {
            "ok": True,
            "data": {
                "remote": {"connected": False},
                "pc": "0x41414141",
                "sp": "0x7fffffffe000",
                "registers": {"rdi": {"value": "0x1"}},
                "stack": {"data": [{"raw": "41414141", "values": ["0x7ffff7dd18b0", "0x555555554000"]}]},
                "backtrace": {"data": [{"level": 0, "text": "main"}]},
                "function_arguments": {"abi": "x86_64_sysv"},
                "disassembly": {"data": [{"address": "0x401000", "instruction": "ret"}, {"address": "0x401001", "instruction": "pop rdi"}]},
            },
        }
        mock_exec.side_effect = [
            _result("info program", stdout="Program received signal SIGSEGV"),
            _result("p/x $_siginfo._sifields._sigfault.si_addr", stdout="$1 = 0x0"),
        ]

        result = gdb_analyze()

        self.assertTrue(result["ok"])
        self.assertTrue(result["data"]["controlled_pc_guess"])
        self.assertIn("SIGSEGV", result["data"]["signal"])
        self.assertTrue(result["data"]["exploitation_hints"]["leak_hints"])
        self.assertIn("ret", result["data"]["exploitation_hints"]["rop_gadget_hints"])
        self.assertIsNotNone(result["data"]["exploitation_hints"]["libc_base_guess"])
        self.assertTrue(result["data"]["exploitation_hints"]["leak_chain_suggestions"])

    def test_gdb_elf_rejects_missing_file(self) -> None:
        result = gdb_elf(action="info", path="E:/does/not/exist")
        self.assertFalse(result["ok"])

    @patch("tools_advanced.run_host_command")
    def test_gdb_elf_strings_truncates_large_output(self, mock_run) -> None:
        mock_run.return_value = {"stdout": "\n".join(f"line{i}" for i in range(2100)), "stderr": "", "ok": True}
        with patch("tools_advanced.resolve_path", return_value=__file__):
            result = gdb_elf(action="strings", path=__file__)
        self.assertTrue(result["ok"])
        self.assertTrue(result["data"]["truncated"])
        self.assertEqual(len(result["data"]["strings"]), 2000)

    @patch("tools_advanced.run_host_command")
    def test_gdb_elf_rop_extracts_categorized_gadgets(self, mock_run) -> None:
        mock_run.return_value = {"stdout": "401000: ret\n401001: pop rdi\n401002: syscall", "stderr": "", "ok": True}
        with patch("tools_advanced.resolve_path", return_value=__file__):
            result = gdb_elf(action="rop", path=__file__)
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(len(result["data"]["gadgets"]), 2)
        self.assertIn("category", result["data"]["gadgets"][0])

    @patch("tools_advanced.run_host_command")
    def test_gdb_elf_leaks_lists_candidate_symbols_and_suggestions(self, mock_run) -> None:
        mock_run.side_effect = [
            {"stdout": "puts\n__libc_start_main\nread\n", "stderr": "", "ok": True},
            {"stdout": "printf\n", "stderr": "", "ok": True},
        ]
        with patch("tools_advanced.resolve_path", return_value=__file__):
            result = gdb_elf(action="leaks", path=__file__)
        self.assertTrue(result["ok"])
        self.assertIn("puts", result["data"]["candidates"])
        self.assertTrue(result["data"]["suggestions"])

    @patch("tools_advanced.exec_cli_internal")
    def test_gdb_pwndbg_runs_plugin_command(self, mock_exec) -> None:
        mock_exec.return_value = _result("context", stdout="pwndbg context")
        result = gdb_pwndbg("context")
        self.assertTrue(result["ok"])
        self.assertEqual(result["command"], "context")


if __name__ == "__main__":
    unittest.main()
