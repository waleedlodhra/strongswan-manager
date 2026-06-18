"""
SaMonitor — background thread that subscribes to VICI daemon events.

VICI event types emitted by charon:
  ike-updown      IKE SA established or torn down
  ike-rekey       IKE SA rekeyed
  child-updown    Child SA established or torn down
  child-rekey     Child SA rekeyed
  authorize       Authorization request (credentials/policy)
  log             Daemon log line

Usage:
    monitor = SaMonitor(socket_path="/var/run/charon.vici")
    monitor.add_listener("ike-updown", my_callback)  # callback(event_type, event_dict)
    monitor.start()
    # … later …
    monitor.stop()
"""
import logging
import socket
import threading
from collections import defaultdict
from typing import Callable

import vici

logger = logging.getLogger(__name__)

EventCallback = Callable[[str, dict], None]

ALL_SA_EVENTS = ("ike-updown", "ike-rekey", "child-updown", "child-rekey")


class SaMonitor:
    """
    Opens a dedicated VICI socket and calls session.listen() in a daemon thread.
    Each subscribed event type triggers registered callbacks.

    Thread model:
      - One daemon thread runs _run_loop() indefinitely.
      - On socket error it sleeps _retry_delay seconds and reconnects.
      - stop() sets _stop_event and wakes the loop; the thread exits cleanly.
    """

    def __init__(
        self,
        socket_path: str = "/var/run/charon.vici",
        events: tuple[str, ...] = ALL_SA_EVENTS,
        retry_delay: float = 5.0,
    ):
        self._socket_path = socket_path
        self._events = events
        self._retry_delay = retry_delay
        self._listeners: dict[str, list[EventCallback]] = defaultdict(list)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ─── Public interface ─────────────────────────────────────────────────────

    def add_listener(self, event_type: str, callback: EventCallback) -> None:
        """Register a callback for an event type (may be called before start())."""
        self._listeners[event_type].append(callback)

    def remove_listener(self, event_type: str, callback: EventCallback) -> None:
        try:
            self._listeners[event_type].remove(callback)
        except ValueError:
            pass

    def start(self) -> None:
        """Start the background monitor thread (idempotent)."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="vici-sa-monitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("SaMonitor started (events: %s)", ", ".join(self._events))

    def stop(self, timeout: float = 3.0) -> None:
        """Signal the monitor thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("SaMonitor stopped")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ─── Internal loop ────────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Main loop: connect → listen → dispatch. Retry on any error."""
        while not self._stop_event.is_set():
            sock = None
            try:
                sock = socket.socket(socket.AF_UNIX)
                sock.connect(self._socket_path)
                sess = vici.Session(sock)
                logger.debug("SaMonitor connected to %s", self._socket_path)
                for event_type, event_data in sess.listen(list(self._events)):
                    if self._stop_event.is_set():
                        break
                    self._dispatch(event_type, event_data)
            except FileNotFoundError:
                logger.debug("VICI socket not found, retrying in %ss", self._retry_delay)
                self._stop_event.wait(timeout=self._retry_delay)
            except Exception as exc:
                if not self._stop_event.is_set():
                    logger.debug("SaMonitor disconnected (%s), retrying in %ss", exc, self._retry_delay)
                    self._stop_event.wait(timeout=self._retry_delay)
            finally:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def _dispatch(self, event_type: str, event_data: dict) -> None:
        """Call all registered listeners for event_type."""
        for callback in list(self._listeners.get(event_type, [])):
            try:
                callback(event_type, dict(event_data))
            except Exception as exc:
                logger.exception("SaMonitor listener error for %r: %s", event_type, exc)
