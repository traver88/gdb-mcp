import unittest

from gdb_controller import CommandResult, GdbController


def _result(command: str, ok: bool = True) -> CommandResult:
    return CommandResult(ok=ok, command=command, stdout="", stderr="", raw=[], data={}, error=None if ok else "boom")


class GdbControllerStateTests(unittest.TestCase):
    def test_disconnect_remote_clears_connection_state(self) -> None:
        controller = GdbController()
        controller.remote_connected = True
        controller.current_inferior_state = "stopped:breakpoint-hit"
        controller.execute_cli = lambda command, timeout=0, parse=False: _result(command, ok=True)  # type: ignore[method-assign]
        controller._ensure_started = lambda: None  # type: ignore[method-assign]

        result = controller.disconnect_remote()

        self.assertTrue(result["ok"])
        self.assertFalse(controller.remote_connected)
        self.assertIsNone(controller.current_inferior_state)

    def test_connect_remote_failure_clears_inferior_state(self) -> None:
        controller = GdbController()
        controller.current_inferior_state = "running"
        controller.setup_remote = lambda **kwargs: []  # type: ignore[method-assign]
        controller._ensure_started = lambda: None  # type: ignore[method-assign]
        controller.execute_cli = lambda command, timeout=0, parse=True: _result(command, ok=False)  # type: ignore[method-assign]

        result = controller.connect_remote(host="127.0.0.1", port=1234)

        self.assertFalse(result["ok"])
        self.assertFalse(controller.remote_connected)
        self.assertIsNone(controller.current_inferior_state)


if __name__ == "__main__":
    unittest.main()
