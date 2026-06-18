"""
Tests for the SaDashboardConsumer WebSocket consumer.

All tests use channels.testing.WebsocketCommunicator which exercises the
consumer directly (no HTTP server needed).  _fetch_sas is patched so no
live charon is required.

Async test classes use pytest-asyncio auto mode.
Sync test classes (TestSerialize) use unittest.TestCase.
"""
import os
import unittest

from channels.testing import WebsocketCommunicator
from unittest.mock import patch

# Disable SaMonitor so AppConfig.ready() doesn't start a background thread.
os.environ.setdefault("STRONGSWAN_DISABLE_MONITOR", "1")


async def _connect(sas=None, charon_ok=True):
    """Return an open WebsocketCommunicator with mocked _fetch_sas."""
    from strongswan_manager.apps.monitoring.consumers import SaDashboardConsumer

    app = SaDashboardConsumer.as_asgi()
    communicator = WebsocketCommunicator(app, "/ws/monitoring/")

    patcher = patch(
        "strongswan_manager.apps.monitoring.consumers._fetch_sas",
        return_value=(sas or [], charon_ok),
    )
    patcher.start()

    connected, _ = await communicator.connect()
    return communicator, patcher, connected


class TestConsumerConnect:
    async def test_consumer_accepts_connection(self):
        communicator, patcher, connected = await _connect()
        try:
            assert connected
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_snapshot_sent_on_connect(self):
        communicator, patcher, _ = await _connect(
            sas=[{"test-ike": {"state": "ESTABLISHED", "version": "2"}}]
        )
        try:
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
            assert isinstance(response["sas"], list)
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_snapshot_contains_sa_data(self):
        fake_sa = {"my-vpn": {"state": "ESTABLISHED", "version": "2", "local-host": "1.2.3.4"}}
        communicator, patcher, _ = await _connect(sas=[fake_sa])
        try:
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
            assert len(response["sas"]) == 1
            name = list(response["sas"][0].keys())[0]
            assert name == "my-vpn"
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_snapshot_has_charon_reachable_field(self):
        communicator, patcher, _ = await _connect(sas=[], charon_ok=True)
        try:
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
            assert response["charon_reachable"] is True
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_snapshot_signals_charon_unreachable(self):
        communicator, patcher, _ = await _connect(sas=[], charon_ok=False)
        try:
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
            assert response["charon_reachable"] is False
            assert response["sas"] == []
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_empty_snapshot_when_no_sas(self):
        communicator, patcher, _ = await _connect(sas=[])
        try:
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
            assert response["sas"] == []
        finally:
            patcher.stop()
            await communicator.disconnect()


class TestConsumerRefresh:
    async def test_refresh_message_triggers_new_snapshot(self):
        communicator, patcher, _ = await _connect(sas=[])
        try:
            await communicator.receive_json_from(timeout=3)  # drain initial
            await communicator.send_json_to({"type": "refresh"})
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_unknown_message_type_ignored(self):
        communicator, patcher, _ = await _connect()
        try:
            await communicator.receive_json_from(timeout=3)
            await communicator.send_json_to({"type": "unknown_command"})
            await communicator.send_json_to({"type": "refresh"})
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_malformed_json_ignored(self):
        communicator, patcher, _ = await _connect()
        try:
            await communicator.receive_json_from(timeout=3)
            await communicator.send_to(text_data="not json {{{{")
            await communicator.send_json_to({"type": "refresh"})
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
        finally:
            patcher.stop()
            await communicator.disconnect()


class TestBroadcastSaEvent:
    async def test_broadcast_delivers_to_connected_consumer(self):
        from strongswan_manager.apps.monitoring.consumers import (
            SaDashboardConsumer,
            broadcast_sa_event,
        )

        app = SaDashboardConsumer.as_asgi()
        communicator = WebsocketCommunicator(app, "/ws/monitoring/")
        patcher = patch(
            "strongswan_manager.apps.monitoring.consumers._fetch_sas",
            return_value=([], True),
        )
        patcher.start()

        await communicator.connect()
        await communicator.receive_json_from(timeout=3)  # drain initial snapshot

        broadcast_sa_event("ike-updown", {"child": "test", "up": True})

        msg = await communicator.receive_json_from(timeout=3)
        assert msg["type"] == "sa.event"
        assert msg["event_type"] == "ike-updown"

        patcher.stop()
        await communicator.disconnect()

    async def test_broadcast_to_no_consumers_is_safe(self):
        from strongswan_manager.apps.monitoring.consumers import broadcast_sa_event, _consumers
        _consumers.clear()
        broadcast_sa_event("ike-updown", {})  # must not raise


class TestConsumerDisconnect:
    async def test_consumer_removed_from_registry_on_disconnect(self):
        from strongswan_manager.apps.monitoring.consumers import _consumers

        communicator, patcher, _ = await _connect()
        try:
            assert len(_consumers) >= 1
        finally:
            patcher.stop()
            await communicator.disconnect()

        assert not any(True for _ in _consumers)


class TestSerialize(unittest.TestCase):
    def test_bytes_converted_to_str(self):
        from strongswan_manager.apps.monitoring.consumers import _serialize
        self.assertEqual(_serialize(b"hello"), "hello")

    def test_nested_bytes_in_dict(self):
        from strongswan_manager.apps.monitoring.consumers import _serialize
        result = _serialize({"key": b"value", "nested": {"x": b"y"}})
        self.assertEqual(result, {"key": "value", "nested": {"x": "y"}})

    def test_list_serialized(self):
        from strongswan_manager.apps.monitoring.consumers import _serialize
        self.assertEqual(_serialize([b"a", b"b"]), ["a", "b"])

    def test_plain_values_unchanged(self):
        from strongswan_manager.apps.monitoring.consumers import _serialize
        self.assertEqual(_serialize(42), 42)
        self.assertEqual(_serialize("hello"), "hello")
        self.assertIsNone(_serialize(None))
