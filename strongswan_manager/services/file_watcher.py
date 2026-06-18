"""
ConfigFileWatcher — inotify-based watcher for StrongSwan config files.

Watches:
  /etc/ipsec.conf
  /etc/ipsec.secrets
  /etc/swanctl/swanctl.conf
  /etc/swanctl/conf.d/   (directory)

When any watched file changes (created, modified, or deleted), calls
SyncEngine.handle_file_changed() after a short debounce period so that
editors that write-then-rename (vim, most text editors) don't fire twice.

Usage:
    watcher = ConfigFileWatcher()
    watcher.start()
    # … runs in background thread …
    watcher.stop()
"""
import logging
import os
import threading
from typing import Callable

from watchdog.events import (
    FileCreatedEvent, FileDeletedEvent, FileModifiedEvent,
    FileMovedEvent, FileSystemEventHandler,
)
from watchdog.observers import Observer

logger = logging.getLogger(__name__)

# Files / directories to monitor
DEFAULT_WATCH_TARGETS = [
    "/etc/ipsec.conf",
    "/etc/ipsec.secrets",
    "/etc/swanctl",
]

# Only react to these extensions / exact filenames
WATCHED_EXTENSIONS = (".conf", ".secrets")
WATCHED_BASENAMES = {"ipsec.conf", "ipsec.secrets", "swanctl.conf"}

DEBOUNCE_SECONDS = 2.0


class _Handler(FileSystemEventHandler):
    """
    Watchdog event handler with per-path debouncing.
    Converts filesystem events into calls to the registered callback.
    """

    def __init__(self, callback: Callable[[str], None], debounce: float = DEBOUNCE_SECONDS):
        super().__init__()
        self._callback = callback
        self._debounce = debounce
        self._timers: dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def _is_relevant(self, path: str) -> bool:
        basename = os.path.basename(path)
        _, ext = os.path.splitext(path)
        return (
            basename in WATCHED_BASENAMES
            or ext in WATCHED_EXTENSIONS
        )

    def _schedule(self, path: str) -> None:
        if not self._is_relevant(path):
            return
        with self._lock:
            existing = self._timers.pop(path, None)
            if existing:
                existing.cancel()
            t = threading.Timer(self._debounce, self._fire, args=(path,))
            t.daemon = True
            t.start()
            self._timers[path] = t

    def _fire(self, path: str) -> None:
        with self._lock:
            self._timers.pop(path, None)
        logger.debug("ConfigFileWatcher: firing callback for %r", path)
        try:
            self._callback(path)
        except Exception as exc:
            logger.exception("ConfigFileWatcher callback error for %r: %s", path, exc)

    # ─── watchdog overrides ────────────────────────────────────────────────

    def on_modified(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)

    def on_moved(self, event):
        # Editors that write to temp then rename trigger this
        if not event.is_directory:
            self._schedule(event.dest_path)


class ConfigFileWatcher:
    """
    Starts a watchdog Observer watching StrongSwan config paths.

    The callback receives the absolute path of the changed file.
    """

    def __init__(
        self,
        callback: Callable[[str], None] | None = None,
        watch_targets: list[str] | None = None,
        debounce: float = DEBOUNCE_SECONDS,
    ):
        from .sync_engine import SyncEngine
        self._callback = callback or SyncEngine().handle_file_changed
        self._targets = watch_targets or DEFAULT_WATCH_TARGETS
        self._debounce = debounce
        self._observer: Observer | None = None

    def start(self) -> None:
        """Start the inotify observer in a background daemon thread."""
        if self._observer and self._observer.is_alive():
            return

        handler = _Handler(self._callback, self._debounce)
        self._observer = Observer()

        for target in self._targets:
            if not os.path.exists(target):
                logger.debug("ConfigFileWatcher: target %r does not exist, skipping", target)
                continue
            if os.path.isdir(target):
                self._observer.schedule(handler, target, recursive=True)
                logger.info("ConfigFileWatcher: watching directory %r", target)
            else:
                # Watch the parent directory; filter in _is_relevant
                parent = os.path.dirname(target)
                self._observer.schedule(handler, parent, recursive=False)
                logger.info("ConfigFileWatcher: watching %r (via parent dir)", target)

        self._observer.start()
        logger.info("ConfigFileWatcher started")

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the observer and wait for the thread to exit."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=timeout)
            self._observer = None
        logger.info("ConfigFileWatcher stopped")

    @property
    def is_running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()
