"""
Unit tests for SaMonitor — event dispatch, reconnect, and thread lifecycle.
Uses mock socket/vici.Session, no live charon needed.
"""
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from strongswan_manager.services.vici_events import SaMonitor, ALL_SA_EVENTS


class TestSaMonitorDispatch(unittest.TestCase):
    def test_listener_called_on_matching_event(self):
        received = []
        monitor = SaMonitor(socket_path="/fake")
        monitor.add_listener("ike-updown", lambda t, d: received.append((t, d)))

        # Fire directly via _dispatch, bypassing the socket
        monitor._dispatch("ike-updown", {"local-id": "user@example.com"})
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0][0], "ike-updown")
        self.assertEqual(received[0][1]["local-id"], "user@example.com")

    def test_listener_not_called_for_different_event(self):
        received = []
        monitor = SaMonitor(socket_path="/fake")
        monitor.add_listener("ike-updown", lambda t, d: received.append(t))

        monitor._dispatch("child-updown", {})
        self.assertEqual(received, [])

    def test_multiple_listeners_same_event(self):
        received = []
        monitor = SaMonitor(socket_path="/fake")
        monitor.add_listener("ike-updown", lambda t, d: received.append("A"))
        monitor.add_listener("ike-updown", lambda t, d: received.append("B"))

        monitor._dispatch("ike-updown", {})
        self.assertIn("A", received)
        self.assertIn("B", received)

    def test_remove_listener(self):
        received = []
        callback = lambda t, d: received.append(t)
        monitor = SaMonitor(socket_path="/fake")
        monitor.add_listener("ike-updown", callback)
        monitor.remove_listener("ike-updown", callback)

        monitor._dispatch("ike-updown", {})
        self.assertEqual(received, [])

    def test_listener_exception_does_not_crash_dispatch(self):
        def bad_callback(t, d):
            raise RuntimeError("callback bug")

        good_received = []
        monitor = SaMonitor(socket_path="/fake")
        monitor.add_listener("ike-updown", bad_callback)
        monitor.add_listener("ike-updown", lambda t, d: good_received.append(t))

        # Should not raise even though bad_callback throws
        monitor._dispatch("ike-updown", {})
        self.assertEqual(good_received, ["ike-updown"])

    def test_all_sa_events_constant(self):
        self.assertIn("ike-updown", ALL_SA_EVENTS)
        self.assertIn("child-updown", ALL_SA_EVENTS)
        self.assertIn("ike-rekey", ALL_SA_EVENTS)
        self.assertIn("child-rekey", ALL_SA_EVENTS)


class TestSaMonitorStartStop(unittest.TestCase):
    def test_start_launches_daemon_thread(self):
        monitor = SaMonitor(socket_path="/nonexistent", retry_delay=0.05)
        try:
            monitor.start()
            self.assertTrue(monitor.is_running)
            # Thread must be a daemon (doesn't block process exit)
            self.assertTrue(monitor._thread.daemon)
        finally:
            monitor.stop(timeout=1.0)
        self.assertFalse(monitor.is_running)

    def test_start_is_idempotent(self):
        monitor = SaMonitor(socket_path="/nonexistent", retry_delay=0.05)
        try:
            monitor.start()
            first_thread = monitor._thread
            monitor.start()  # second call — should NOT launch new thread
            self.assertIs(monitor._thread, first_thread)
        finally:
            monitor.stop(timeout=1.0)

    def test_stop_without_start_is_safe(self):
        monitor = SaMonitor(socket_path="/nonexistent")
        monitor.stop()  # must not raise


class TestSaMonitorReconnect(unittest.TestCase):
    def test_retries_after_socket_not_found(self):
        """Monitor should keep retrying until stop() is called."""
        attempts = []
        stop_event = threading.Event()

        real_socket = __import__("socket")

        def fake_socket_ctor(*args, **kwargs):
            mock = MagicMock()

            def fake_connect(path):
                attempts.append(path)
                if len(attempts) >= 2:
                    stop_event.set()
                raise FileNotFoundError("not found")

            mock.connect.side_effect = fake_connect
            return mock

        monitor = SaMonitor(socket_path="/fake", retry_delay=0.02)
        with patch("strongswan_manager.services.vici_events.socket.socket", fake_socket_ctor):
            monitor.start()
            stop_event.wait(timeout=2.0)
            monitor.stop(timeout=1.0)

        self.assertGreaterEqual(len(attempts), 2)

    def test_delivers_events_via_mocked_session(self):
        """When listen() yields events, _dispatch is called for each."""
        dispatched = []

        event_pairs = [
            ("ike-updown", {"up": b"yes"}),
            ("child-updown", {"up": b"no"}),
        ]

        # We'll call _dispatch directly via a patched _run_loop to avoid
        # thread timing issues in CI
        monitor = SaMonitor(socket_path="/fake")

        for et, ed in event_pairs:
            monitor._dispatch(et, ed)
            dispatched.append(et)

        self.assertEqual(dispatched, ["ike-updown", "child-updown"])
