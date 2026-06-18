"""
Tests for the SaDashboardConsumer WebSocket consumer.

All tests use channels.testing.WebsocketCommunicator which exercises the
consumer directly (no HTTP server needed).  ViciService.get_instance is
patched so no live charon is required.

Async test classes (TestConsumer*) use pytest-asyncio auto mode.
Sync test classes (TestSerialize) use unittest.TestCase to avoid being
collected as async by asyncio_mode=auto.
"""
import json
import os
import unittest

import pytest
from channels.testing import WebsocketCommunicator
from unittest.mock import MagicMock, patch

# Disable SaMonitor so AppConfig.ready() doesn't start a background thread.
os.environ.setdefault("STRONGSWAN_DISABLE_MONITOR", "1")


def _make_vici_mock(sas=None):
    m = MagicMock()
    m.list_sas.return_value = sas or []
    return m


async def _connect(sas=None):
    """Return an open WebsocketCommunicator with mocked ViciService."""
    from strongswan_manager.apps.monitoring.consumers import SaDashboardConsumer

    app = SaDashboardConsumer.as_asgi()
    communicator = WebsocketCommunicator(app, "/ws/monitoring/")
    vici_mock = _make_vici_mock(sas)

    patcher = patch(
        "strongswan_manager.apps.monitoring.consumers._fetch_sas",
        return_value=vici_mock.list_sas(),
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
        communicator, patcher, _ = await _connect(sas=[{"test-ike": {"state": "ESTABLISHED", "version": "2"}}])
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

    async def test_empty_snapshot_when_charon_unavailable(self):
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
            # Drain the initial snapshot
            await communicator.receive_json_from(timeout=3)

            # Request a refresh
            await communicator.send_json_to({"type": "refresh"})
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_unknown_message_type_ignored(self):
        """Sending an unknown type should not crash the consumer."""
        communicator, patcher, _ = await _connect()
        try:
            await communicator.receive_json_from(timeout=3)  # drain snapshot
            await communicator.send_json_to({"type": "unknown_command"})
            # Consumer should still be alive — a refresh should yield a snapshot
            await communicator.send_json_to({"type": "refresh"})
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
        finally:
            patcher.stop()
            await communicator.disconnect()

    async def test_malformed_json_ignored(self):
        """Malformed JSON should not crash the consumer."""
        communicator, patcher, _ = await _connect()
        try:
            await communicator.receive_json_from(timeout=3)  # drain snapshot
            await communicator.send_to(text_data="not json {{{{")
            # Consumer should still be alive — a refresh should yield a snapshot
            await communicator.send_json_to({"type": "refresh"})
            response = await communicator.receive_json_from(timeout=3)
            assert response["type"] == "sa.snapshot"
        finally:
            patcher.stop()
            await communicator.disconnect()


class TestBroadcastSaEvent:
    async def test_broadcast_delivers_to_connected_consumer(self):
        """broadcast_sa_event should put a message onto the consumer's queue."""
        from strongswan_manager.apps.monitoring.consumers import (
            SaDashboardConsumer,
            broadcast_sa_event,
        )

        app = SaDashboardConsumer.as_asgi()
        communicator = WebsocketCommunicator(app, "/ws/monitoring/")
        patcher = patch(
            "strongswan_manager.apps.monitoring.consumers._fetch_sas",
            return_value=[],
        )
        patcher.start()

        await communicator.connect()
        await communicator.receive_json_from(timeout=3)  # drain initial snapshot

        # Broadcast an event from a (simulated) background thread
        broadcast_sa_event("ike-updown", {"child": "test", "up": True})

        msg = await communicator.receive_json_from(timeout=3)
        assert msg["type"] == "sa.event"
        assert msg["event_type"] == "ike-updown"

        patcher.stop()
        await communicator.disconnect()

    async def test_broadcast_to_no_consumers_is_safe(self):
        """broadcast_sa_event with no connected consumers must not raise."""
        from strongswan_manager.apps.monitoring.consumers import broadcast_sa_event, _consumers
        _consumers.clear()
        broadcast_sa_event("ike-updown", {})  # must not raise


class TestConsumerDisconnect:
    async def test_consumer_removed_from_registry_on_disconnect(self):
        from strongswan_manager.apps.monitoring.consumers import _consumers

        communicator, patcher, _ = await _connect()
        try:
            # At least one consumer registered
            assert len(_consumers) >= 1
        finally:
            patcher.stop()
            await communicator.disconnect()

        assert not any(True for _ in _consumers)


class TestSerialize(unittest.TestCase):
    """Unit tests for the _serialize helper — sync, use unittest.TestCase to
    avoid pytest-asyncio treating them as async under asyncio_mode=auto."""

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
