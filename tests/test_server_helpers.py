import unittest
from unittest.mock import patch

from models import RiskAssessment
from server_runtime import context_summary, ensure_mutation_allowed, memory_read_result
from tools_memory import gdb_memory
from gdb_controller import CommandResult


class MemoryFeatureTests(unittest.TestCase):
    def test_context_summary_extracts_top_registers_and_backtrace(self) -> None:
        context = {
            "data": {
                "remote": {"connected": True},
                "pc": "0x401000",
                "sp": "0x7fffffffe000",
                "current_instruction": {"address": "0x401000", "instruction": "ret"},
                "registers": {
                    "rip": {"value": "0x401000"},
                    "rsp": {"value": "0x7fffffffe000"},
                    "rax": {"value": "0x1"},
                },
                "backtrace": {
                    "data": [
                        {"level": 0, "text": "main"},
                        {"level": 1, "text": "start"},
                        {"level": 2, "text": "__libc_start_main"},
                        {"level": 3, "text": "_start"},
                    ]
                },
            }
        }

        summary = context_summary(context)

        self.assertEqual(summary["remote"], {"connected": True})
        self.assertEqual(summary["pc"], "0x401000")
        self.assertEqual(summary["sp"], "0x7fffffffe000")
        self.assertEqual(set(summary["registers"]), {"rip", "rsp"})
        self.assertEqual(len(summary["backtrace_top"]), 3)

    @patch("server_runtime.READ_ONLY_MODE", True)
    def test_read_only_mode_blocks_memory_mutation(self) -> None:
        result = ensure_mutation_allowed("gdb_memory", "write")
        self.assertIsNotNone(result)
        assert result is not None
        self.assertIn("read-only mode", result["error"])

    @patch("tools_memory.write_memory_with_restore")
    @patch("tools_memory.memory_read_result")
    def test_write_block_uses_restore_path(self, mock_read_result, mock_write_restore) -> None:
        mock_read_result.side_effect = [
            {"data": {"hex": "4142"}},
            {"data": {"hex": "4344"}},
        ]
        mock_write_restore.return_value = ([{"command": "restore temp.bin binary 0x401000", "ok": True, "error": None, "stderr": ""}], "restore temp.bin binary 0x401000")

        result = gdb_memory(action="write_block", address="0x401000", data_hex="4142", confirm=True)

        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["write_mode"], "block")
        self.assertEqual(result["data"]["byte_count"], 2)
        mock_write_restore.assert_called_once()

    @patch("server_runtime.read_memory_bytes")
    def test_memory_read_result_keeps_requested_and_returned_sizes(self, mock_read_memory_bytes) -> None:
        mock_read_memory_bytes.return_value = (
            CommandResult(ok=True, command="x/2xb 0x401000", stdout="0x401000: 0x41 0x42", stderr="", raw=[], data={}, error=None),
            b"AB",
            [{"address": "0x401000", "values": ["0x41", "0x42"]}],
            "x/2xb 0x401000",
        )

        result = memory_read_result(
            address="0x401000",
            requested_size=2,
            effective_size=2,
            assessment=RiskAssessment("low"),
            confirmed=True,
        )

        self.assertTrue(result["ok"])
        self.assertEqual(result["data"]["requested_size"], 2)
        self.assertEqual(result["data"]["returned_size"], 2)
        self.assertEqual(result["data"]["hex"], "4142")


if __name__ == "__main__":
    unittest.main()
