"""
Tests for ConfigFileWatcher — event debouncing, lifecycle, and relevance filtering.
"""
import os
import tempfile
import threading
import time
import unittest

from strongswan_manager.services.file_watcher import _Handler, ConfigFileWatcher


class TestHandlerDebounce(unittest.TestCase):
    """Test the debounce logic directly without starting the observer."""

    def test_callback_called_after_debounce(self):
        called = []
        handler = _Handler(lambda p: called.append(p), debounce=0.05)
        # Simulate a modified event
        from watchdog.events import FileModifiedEvent
        evt = FileModifiedEvent("/etc/swanctl/swanctl.conf")
        handler.on_modified(evt)
        time.sleep(0.15)
        self.assertEqual(called, ["/etc/swanctl/swanctl.conf"])

    def test_rapid_events_coalesced(self):
        """Multiple events on the same file in the debounce window → one callback."""
        called = []
        handler = _Handler(lambda p: called.append(p), debounce=0.1)
        from watchdog.events import FileModifiedEvent
        evt = FileModifiedEvent("/etc/ipsec.conf")
        for _ in range(5):
            handler.on_modified(evt)
            time.sleep(0.02)
        time.sleep(0.3)
        self.assertEqual(len(called), 1)

    def test_irrelevant_files_ignored(self):
        called = []
        handler = _Handler(lambda p: called.append(p), debounce=0.05)
        from watchdog.events import FileModifiedEvent
        handler.on_modified(FileModifiedEvent("/etc/swanctl/x509/somecert.pem"))
        handler.on_modified(FileModifiedEvent("/etc/passwd"))
        time.sleep(0.2)
        self.assertEqual(called, [])

    def test_watched_basenames_trigger_callback(self):
        called = []
        handler = _Handler(lambda p: called.append(p), debounce=0.05)
        from watchdog.events import FileModifiedEvent
        handler.on_modified(FileModifiedEvent("/etc/ipsec.secrets"))
        time.sleep(0.2)
        self.assertIn("/etc/ipsec.secrets", called)

    def test_moved_event_uses_dest_path(self):
        called = []
        handler = _Handler(lambda p: called.append(p), debounce=0.05)
        from watchdog.events import FileMovedEvent
        evt = FileMovedEvent("/tmp/ipsec.conf.swp", "/etc/ipsec.conf")
        handler.on_moved(evt)
        time.sleep(0.2)
        self.assertIn("/etc/ipsec.conf", called)

    def test_created_event_triggers_callback(self):
        called = []
        handler = _Handler(lambda p: called.append(p), debounce=0.05)
        from watchdog.events import FileCreatedEvent
        handler.on_created(FileCreatedEvent("/etc/swanctl/conf.d/new.conf"))
        time.sleep(0.2)
        self.assertIn("/etc/swanctl/conf.d/new.conf", called)

    def test_deleted_event_triggers_callback(self):
        called = []
        handler = _Handler(lambda p: called.append(p), debounce=0.05)
        from watchdog.events import FileDeletedEvent
        handler.on_deleted(FileDeletedEvent("/etc/swanctl/swanctl.conf"))
        time.sleep(0.2)
        self.assertIn("/etc/swanctl/swanctl.conf", called)

    def test_directory_events_ignored(self):
        called = []
        handler = _Handler(lambda p: called.append(p), debounce=0.05)
        from watchdog.events import DirModifiedEvent
        handler.on_modified(DirModifiedEvent("/etc/swanctl/conf.d"))
        time.sleep(0.2)
        self.assertEqual(called, [])


class TestConfigFileWatcherLifecycle(unittest.TestCase):
    def test_start_stop(self):
        """Watcher starts and stops cleanly even if targets do not exist."""
        watcher = ConfigFileWatcher(
            callback=lambda p: None,
            watch_targets=["/nonexistent_watchdog_test_dir"],
            debounce=0.1,
        )
        watcher.start()
        # is_running may be False if no valid targets were scheduled
        watcher.stop(timeout=2.0)

    def test_idempotent_start(self):
        """Calling start() twice does not create two observers."""
        watcher = ConfigFileWatcher(
            callback=lambda p: None,
            watch_targets=["/nonexistent_watchdog_test_dir"],
            debounce=0.1,
        )
        watcher.start()
        first_observer = watcher._observer
        watcher.start()
        self.assertIs(watcher._observer, first_observer)
        watcher.stop(timeout=2.0)

    def test_stop_without_start_is_safe(self):
        watcher = ConfigFileWatcher(callback=lambda p: None)
        watcher.stop()  # must not raise

    def test_file_change_triggers_callback(self):
        """Create a real temp file, watch it, write to it, verify callback fires."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf_path = os.path.join(tmpdir, "swanctl.conf")
            with open(conf_path, "w") as f:
                f.write("# initial\n")

            received = []
            evt = threading.Event()

            def cb(path):
                received.append(path)
                evt.set()

            watcher = ConfigFileWatcher(
                callback=cb,
                watch_targets=[tmpdir],
                debounce=0.1,
            )
            watcher.start()
            time.sleep(0.1)  # let observer settle

            with open(conf_path, "w") as f:
                f.write("connections {}\n")

            evt.wait(timeout=3.0)
            watcher.stop(timeout=2.0)

        self.assertTrue(any(conf_path in p for p in received),
                        f"Expected {conf_path} in {received}")
