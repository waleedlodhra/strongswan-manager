"""
Unit tests for SyncEngine — GUI→StrongSwan synchronization and file change handling.
All ViciService calls are mocked; no live charon required.
"""
import os
import tempfile
import textwrap
import threading
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from django.test import TestCase

from strongswan_manager.services.sync_engine import SyncEngine
from strongswan_manager.services.exceptions import ViciUnavailable


def _make_engine_with_mock_vici():
    """
    Return a (SyncEngine, vici_mock, patch_ctx) triple.
    Patch ViciService.get_instance at the module level so ALL SyncEngine
    instances (including those spawned by Django signals) share the same mock.
    The caller must call patch_ctx.start() / patch_ctx.stop() or use it as
    a context manager.
    """
    vici_mock = MagicMock()
    patcher = patch(
        "strongswan_manager.services.sync_engine.ViciService.get_instance",
        return_value=vici_mock,
    )
    engine = SyncEngine()
    return engine, vici_mock, patcher


class TestLoadConnection(TestCase):
    fixtures = ['initial_data.json']

    def setUp(self):
        self.engine, self.vici, patcher = _make_engine_with_mock_vici()
        self.patcher = patcher
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def _make_conn(self, enabled=True, profile="test-conn"):
        from strongswan_manager.apps.connections.models import IKEv2Certificate, Authentication
        conn = IKEv2Certificate(profile=profile, version="2", enabled=enabled,
                                connection_type="client")
        conn.save()
        return conn.subclass()

    def test_loads_enabled_connection(self):
        conn = self._make_conn(enabled=True)
        self.vici.reset_mock()  # ignore signal-triggered call from save()
        result = self.engine.load_connection(conn)
        self.assertTrue(result)
        self.vici.load_connection.assert_called_once()

    def test_skips_disabled_connection(self):
        conn = self._make_conn(enabled=False)
        self.vici.reset_mock()
        result = self.engine.load_connection(conn)
        self.assertFalse(result)
        self.vici.load_connection.assert_not_called()

    def test_returns_false_when_vici_unavailable(self):
        conn = self._make_conn(enabled=True)
        self.vici.reset_mock()
        self.vici.load_connection.side_effect = ViciUnavailable("down")
        result = self.engine.load_connection(conn)
        self.assertFalse(result)

    def test_returns_false_on_load_error(self):
        from strongswan_manager.services.exceptions import ViciLoadError
        conn = self._make_conn(enabled=True)
        self.vici.reset_mock()
        self.vici.load_connection.side_effect = ViciLoadError("bad dict")
        result = self.engine.load_connection(conn)
        self.assertFalse(result)


class TestUnloadConnection(TestCase):
    fixtures = ['initial_data.json']

    def setUp(self):
        self.engine, self.vici, patcher = _make_engine_with_mock_vici()
        self.patcher = patcher
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_unloads_connection(self):
        result = self.engine.unload_connection("rw")
        self.assertTrue(result)
        self.vici.unload_connection.assert_called_once_with("rw")

    def test_returns_false_when_vici_unavailable(self):
        self.vici.unload_connection.side_effect = ViciUnavailable("down")
        result = self.engine.unload_connection("rw")
        self.assertFalse(result)


class TestLoadSecret(TestCase):
    fixtures = ['initial_data.json']

    def setUp(self):
        self.engine, self.vici, patcher = _make_engine_with_mock_vici()
        self.patcher = patcher
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def _make_secret(self):
        """Create and save a Secret — the post_save signal will also call load_shared."""
        from strongswan_manager.apps.eap_secrets.models import Secret
        import os
        salt = os.urandom(16).hex()
        s = Secret(username="alice", type="EAP", salt=salt)
        s.password = salt + "alicepass"
        s.save()
        return s

    def test_loads_secret(self):
        s = self._make_secret()
        self.vici.reset_mock()  # ignore signal-triggered call from save()
        result = self.engine.load_secret(s)
        self.assertTrue(result)
        self.vici.load_shared.assert_called_once()

    def test_returns_false_when_vici_unavailable(self):
        s = self._make_secret()
        self.vici.reset_mock()
        self.vici.load_shared.side_effect = ViciUnavailable("down")
        result = self.engine.load_secret(s)
        self.assertFalse(result)


class TestLoadAuthority(TestCase):
    fixtures = ['initial_data.json']

    def setUp(self):
        self.engine, self.vici, patcher = _make_engine_with_mock_vici()
        self.patcher = patcher
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def _make_authority(self):
        from strongswan_manager.apps.certificates.models import Authority
        a = Authority(name="my-ca", cacert="caCert.pem",
                      crl_uris="http://crl.example.com/crl")
        a.save()
        return a

    def test_loads_authority(self):
        a = self._make_authority()
        self.vici.reset_mock()  # ignore signal-triggered call
        result = self.engine.load_authority(a)
        self.assertTrue(result)
        self.vici.load_authority.assert_called_once()

    def test_unloads_authority(self):
        result = self.engine.unload_authority("my-ca")
        self.assertTrue(result)
        self.vici.unload_authority.assert_called_once_with("my-ca")

    def test_returns_false_when_vici_unavailable(self):
        a = self._make_authority()
        self.vici.reset_mock()
        self.vici.load_authority.side_effect = ViciUnavailable("down")
        result = self.engine.load_authority(a)
        self.assertFalse(result)


class TestLoadPool(TestCase):
    fixtures = ['initial_data.json']

    def setUp(self):
        self.engine, self.vici, patcher = _make_engine_with_mock_vici()
        self.patcher = patcher
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def _make_pool(self):
        from strongswan_manager.apps.pools.models import Pool
        p = Pool(poolname="pool-test", addresses="10.10.0.0/24")
        p.save()
        return p

    def test_loads_pool(self):
        p = self._make_pool()
        self.vici.reset_mock()  # ignore signal-triggered call
        result = self.engine.load_pool(p)
        self.assertTrue(result)
        self.vici.load_pool.assert_called_once()

    def test_unloads_pool(self):
        result = self.engine.unload_pool("pool-test")
        self.assertTrue(result)
        self.vici.unload_pool.assert_called_once_with("pool-test")

    def test_returns_false_when_vici_unavailable(self):
        p = self._make_pool()
        self.vici.reset_mock()
        self.vici.load_pool.side_effect = ViciUnavailable("down")
        result = self.engine.load_pool(p)
        self.assertFalse(result)


class TestReloadAll(TestCase):
    fixtures = ['initial_data.json']

    def setUp(self):
        self.engine, self.vici, patcher = _make_engine_with_mock_vici()
        self.patcher = patcher
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_reload_all_calls_clear_creds_first(self):
        summary = self.engine.reload_all()
        self.vici.clear_creds.assert_called_once()

    def test_reload_all_returns_summary_dict(self):
        summary = self.engine.reload_all()
        self.assertIn("connections", summary)
        self.assertIn("secrets", summary)
        self.assertIn("errors", summary)

    def test_reload_all_graceful_when_vici_unavailable(self):
        self.vici.clear_creds.side_effect = ViciUnavailable("down")
        summary = self.engine.reload_all()
        self.assertIn("charon unavailable", summary["errors"])
        self.assertEqual(summary["connections"], 0)

    def test_reload_all_loads_enabled_connections(self):
        from strongswan_manager.apps.connections.models import IKEv2Certificate
        conn = IKEv2Certificate(profile="reload-test", version="2",
                                enabled=True, connection_type="client")
        conn.save()
        self.vici.reset_mock()
        summary = self.engine.reload_all()
        self.assertGreaterEqual(summary["connections"], 1)
        self.vici.load_connection.assert_called()

    def test_reload_all_skips_disabled_connections(self):
        from strongswan_manager.apps.connections.models import IKEv2Certificate
        conn = IKEv2Certificate(profile="disabled-test", version="2",
                                enabled=False, connection_type="client")
        conn.save()
        self.vici.reset_mock()
        self.engine.reload_all()
        for call in self.vici.load_connection.call_args_list:
            args = call[0][0] if call[0] else {}
            self.assertNotIn("disabled-test", args)


class TestHandleFileChanged(TestCase):
    fixtures = ['initial_data.json']

    IPSEC_CONF = textwrap.dedent("""\
        conn file-watcher-test
            auto=start
            keyexchange=ikev1
            authby=secret
            left=10.0.1.1
            right=10.0.1.2
    """)

    def setUp(self):
        self.engine, self.vici, patcher = _make_engine_with_mock_vici()
        self.patcher = patcher
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()

    def test_imports_new_connections_from_changed_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                        delete=False) as f:
            f.write(self.IPSEC_CONF)
            path = f.name
        try:
            created = self.engine.handle_file_changed(path)
            self.assertEqual(created, 1)
            from strongswan_manager.apps.connections.models import Connection
            self.assertTrue(Connection.objects.filter(
                profile="file-watcher-test").exists())
        finally:
            os.unlink(path)

    def test_idempotent_on_second_change(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                        delete=False) as f:
            f.write(self.IPSEC_CONF)
            path = f.name
        try:
            self.engine.handle_file_changed(path)
            created = self.engine.handle_file_changed(path)
            self.assertEqual(created, 0)  # already exists
        finally:
            os.unlink(path)

    def test_disables_connections_when_file_deleted(self):
        from strongswan_manager.apps.connections.models import IKEv2Certificate
        conn = IKEv2Certificate(
            profile="orphan-conn", version="2",
            enabled=True, connection_type="client",
            source_file="/tmp/phantom.conf",
        )
        conn.save()
        # File doesn't exist → _handle_file_deleted path
        self.engine.handle_file_changed("/tmp/phantom.conf")
        conn.refresh_from_db()
        self.assertFalse(conn.enabled)

    def test_returns_zero_for_nonexistent_file(self):
        created = self.engine.handle_file_changed("/nonexistent/file.conf")
        self.assertEqual(created, 0)
