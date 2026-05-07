import unittest

from utils import parse_hex_bytes


class ParseHexBytesTests(unittest.TestCase):
    def test_accepts_empty_inputs(self) -> None:
        self.assertEqual(parse_hex_bytes(""), b"")
        self.assertEqual(parse_hex_bytes("   "), b"")
        self.assertEqual(parse_hex_bytes("\\x"), b"")

    def test_supports_compact_and_spaced_hex(self) -> None:
        self.assertEqual(parse_hex_bytes("414243"), b"ABC")
        self.assertEqual(parse_hex_bytes("0x41 0x42 0x43"), b"ABC")
        self.assertEqual(parse_hex_bytes("41,42,43"), b"ABC")

    def test_pads_odd_length_compact_hex(self) -> None:
        self.assertEqual(parse_hex_bytes("abc"), bytes.fromhex("0abc"))


if __name__ == "__main__":
    unittest.main()
