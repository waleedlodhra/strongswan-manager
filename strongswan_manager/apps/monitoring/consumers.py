"""
WebSocket consumer for the real-time SA monitoring dashboard.

Each browser tab that opens the dashboard creates one SaDashboardConsumer.
On connect the consumer:
  1. Registers itself in the module-level ``_consumers`` set.
  2. Sends an immediate SA snapshot (list_sas() result).
  3. Starts ``_send_loop``: waits on a per-consumer asyncio.Queue with a
     15-second timeout.  Queue items come from SaMonitor events (pushed by
     broadcast_sa_event below).  On timeout, sends a fresh snapshot anyway.

broadcast_sa_event() is called from the SaMonitor background thread.
It uses asyncio.run_coroutine_threadsafe to put messages onto each live
consumer's Queue — safely bridging the sync SaMonitor thread and the async
consumer event loop.
"""
import asyncio
import json
import logging
import threading

from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)

# Global registry of live consumers — populated on connect, cleared on disconnect.
_consumers: set = set()
_consumers_lock = threading.Lock()


# ─── Serialisation ────────────────────────────────────────────────────────────

def _serialize(obj):
    """Recursively convert bytes / OrderedDict to plain JSON-friendly types."""
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {_serialize(k): _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize(i) for i in obj]
    return obj


# ─── Cross-thread broadcast ───────────────────────────────────────────────────

def broadcast_sa_event(event_type: str, event_data: dict) -> None:
    """
    Push an SA event to every connected dashboard consumer.
    Called from the SaMonitor daemon thread; must not block.
    """
    msg = {
        "type": "sa.event",
        "event_type": event_type,
        "data": _serialize(event_data),
    }
    with _consumers_lock:
        for consumer in list(_consumers):
            loop = getattr(consumer, "_loop", None)
            queue = getattr(consumer, "_queue", None)
            if loop and queue and not loop.is_closed():
                asyncio.run_coroutine_threadsafe(queue.put(msg), loop)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _fetch_sas() -> tuple[list, bool]:
    """
    Fetch the current SA list synchronously (called via run_in_executor).
    Returns (sas, charon_reachable).
    """
    from strongswan_manager.services.exceptions import ViciUnavailable
    from strongswan_manager.services.vici_service import ViciService

    try:
        sas = ViciService.get_instance().list_sas()
        return sas, True
    except ViciUnavailable:
        return [], False
    except Exception:
        logger.exception("Unexpected error fetching SAs from charon")
        return [], False


# ─── Consumer ─────────────────────────────────────────────────────────────────

class SaDashboardConsumer(AsyncWebsocketConsumer):

    SNAPSHOT_INTERVAL = 15.0

    async def connect(self):
        self._loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
        self._queue: asyncio.Queue = asyncio.Queue()
        self._task: asyncio.Task | None = None

        with _consumers_lock:
            _consumers.add(self)

        await self.accept()
        self._task = asyncio.ensure_future(self._send_loop())

    async def disconnect(self, close_code):
        with _consumers_lock:
            _consumers.discard(self)

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        try:
            msg = json.loads(text_data)
        except (ValueError, TypeError):
            return
        if msg.get("type") == "refresh":
            await self._send_snapshot()

    # ─── Internal helpers ─────────────────────────────────────────────────────

    async def _send_loop(self):
        await self._send_snapshot()
        while True:
            try:
                event_msg = await asyncio.wait_for(
                    self._queue.get(), timeout=self.SNAPSHOT_INTERVAL
                )
                await self.send(json.dumps(event_msg, default=str))
            except asyncio.TimeoutError:
                await self._send_snapshot()
            except asyncio.CancelledError:
                raise

    async def _send_snapshot(self):
        loop = asyncio.get_running_loop()
        sas, charon_ok = await loop.run_in_executor(None, _fetch_sas)
        await self.send(
            json.dumps(
                {
                    "type": "sa.snapshot",
                    "sas": _serialize(sas),
                    "charon_reachable": charon_ok,
                },
                default=str,
            )
        )
