"""
Unit tests for ViciService — all VICI commands, reconnect logic, and error handling.
All tests use unittest.mock so no live charon socket is required.
"""
import os
import socket
import tempfile
import threading
import unittest
from collections import OrderedDict
from unittest.mock import MagicMock, patch, call

from strongswan_manager.services.vici_service import ViciService
from strongswan_manager.services.exceptions import (
    ViciUnavailable,
    ViciLoadError,
    ViciOperationError,
    ViciAuthenticationError,
)


def _make_service(session_mock):
    """Return a ViciService whose _session is pre-wired to session_mock."""
    svc = ViciService.__new__(ViciService)
    svc._socket_path = "/var/run/charon.vici"
    svc._lock = threading.RLock()
    svc._sock = MagicMock()
    svc._session = session_mock
    return svc


def _make_session():
    return MagicMock(spec=[
        "load_conn", "unload_conn", "list_conns", "get_conns",
        "load_shared", "load_key", "unload_key", "get_keys",
        "unload_shared", "get_shared",
        "load_cert", "list_certs",
        "load_token", "clear_creds", "flush_certs",
        "load_authority", "unload_authority", "list_authorities", "get_authorities",
        "load_pool", "unload_pool", "get_pools",
        "install", "uninstall", "list_policies",
        "get_counters", "reset_counters",
        "reload_settings",
        "list_sas", "initiate", "terminate", "rekey", "redirect",
        "version", "stats", "get_algorithms",
    ])


class TestSingleton(unittest.TestCase):
    def tearDown(self):
        ViciService.reset_instance()

    @patch("strongswan_manager.services.vici_service.os.path.exists", return_value=True)
    @patch("strongswan_manager.services.vici_service.os.stat")
    @patch("strongswan_manager.services.vici_service.socket.socket")
    @patch("strongswan_manager.services.vici_service.vici.Session")
    def test_singleton_returns_same_instance(self, mock_session_cls, mock_socket_cls, mock_stat, mock_exists):
        import stat as stat_mod
        mock_stat.return_value.st_mode = stat_mod.S_IFSOCK
        a = ViciService.get_instance()
        b = ViciService.get_instance()
        self.assertIs(a, b)

    def test_reset_clears_singleton(self):
        ViciService.reset_instance()  # safe to call when no instance
        with patch("strongswan_manager.services.vici_service.os.path.exists", return_value=False):
            # Just verify no AttributeError
            ViciService.reset_instance()


class TestViciUnavailableOnMissingSocket(unittest.TestCase):
    def test_raises_unavailable_if_socket_missing(self):
        svc = ViciService("/nonexistent/path")
        with self.assertRaises(ViciUnavailable):
            svc._connect()

    def test_raises_unavailable_if_path_not_a_socket(self):
        # Use a real file (not a socket)
        with tempfile.NamedTemporaryFile() as tmp:
            svc = ViciService(tmp.name)
            with self.assertRaises(ViciUnavailable):
                svc._connect()


class TestConnectionManagement(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_load_connection(self):
        conn = {"test-conn": {"version": "2"}}
        self.svc.load_connection(conn)
        self.session.load_conn.assert_called_once_with(conn)

    def test_unload_connection_when_loaded(self):
        self.session.list_conns.return_value = [{"test-conn": {}}]
        self.svc.unload_connection("test-conn")
        self.session.unload_conn.assert_called_once_with(OrderedDict(name="test-conn"))

    def test_unload_connection_noop_when_not_loaded(self):
        self.session.list_conns.return_value = [{"other": {}}]
        self.svc.unload_connection("test-conn")
        self.session.unload_conn.assert_not_called()

    def test_get_connection_names(self):
        self.session.list_conns.return_value = [{"conn-a": {}}, {"conn-b": {}}]
        names = self.svc.get_connection_names()
        self.assertEqual(names, ["conn-a", "conn-b"])

    def test_is_connection_loaded_true(self):
        self.session.list_conns.return_value = [{"rw": {}}]
        self.assertTrue(self.svc.is_connection_loaded("rw"))

    def test_is_connection_loaded_false(self):
        self.session.list_conns.return_value = []
        self.assertFalse(self.svc.is_connection_loaded("rw"))

    def test_unload_all_connections(self):
        self.session.list_conns.side_effect = [
            [{"a": {}}, {"b": {}}],  # first call in get_connection_names
            [{"a": {}}],             # used in unload_connection → is_loaded check for "a"
            [],                      # used in unload_connection → is_loaded check for "b"
        ]
        # Simplify: replace with direct mock
        self.svc.get_connection_names = MagicMock(return_value=["a", "b"])
        self.svc.unload_connection = MagicMock()
        self.svc.unload_all_connections()
        self.svc.unload_connection.assert_any_call("a")
        self.svc.unload_connection.assert_any_call("b")

    def test_get_conns(self):
        self.session.get_conns.return_value = {"rw": {"version": b"2"}}
        result = self.svc.get_conns()
        self.assertIn("rw", result)

    def test_load_connection_raises_load_error_on_failure(self):
        self.session.load_conn.side_effect = Exception("bad config")
        with self.assertRaises(ViciLoadError):
            self.svc.load_connection({"bad": {}})


class TestSaCommands(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_list_sas_no_filter(self):
        self.session.list_sas.return_value = [{"rw": {"state": b"ESTABLISHED"}}]
        result = self.svc.list_sas()
        self.session.list_sas.assert_called_once_with()
        self.assertEqual(len(result), 1)

    def test_list_sas_with_ike_filter(self):
        self.session.list_sas.return_value = []
        self.svc.list_sas(ike="rw")
        self.session.list_sas.assert_called_once_with({"ike": "rw"})

    def test_list_sas_with_ike_id(self):
        self.session.list_sas.return_value = []
        self.svc.list_sas(ike_id=5)
        self.session.list_sas.assert_called_once_with({"ike-id": "5"})

    def test_get_connection_state_established(self):
        self.session.list_sas.return_value = [{"rw": {"state": b"ESTABLISHED"}}]
        state = self.svc.get_connection_state("rw")
        self.assertEqual(state, "ESTABLISHED")

    def test_get_connection_state_down_when_no_sa(self):
        self.session.list_sas.return_value = []
        state = self.svc.get_connection_state("rw")
        self.assertEqual(state, "DOWN")

    def test_initiate(self):
        self.session.initiate.return_value = [
            OrderedDict(msg=b"initiating IKE_SA"),
            OrderedDict(msg=b"IKE_SA established"),
        ]
        msgs = self.svc.initiate("child1", "rw")
        self.assertEqual(len(msgs), 2)
        self.session.initiate.assert_called_once_with(OrderedDict(ike="rw", child="child1"))

    def test_terminate_by_name(self):
        self.session.terminate.return_value = [OrderedDict(msg=b"closing IKE_SA")]
        msgs = self.svc.terminate(ike="rw")
        self.session.terminate.assert_called_once()
        req = self.session.terminate.call_args[0][0]
        self.assertEqual(req["ike"], "rw")

    def test_terminate_by_ike_id(self):
        self.session.terminate.return_value = []
        self.svc.terminate(ike_id=3)
        req = self.session.terminate.call_args[0][0]
        self.assertEqual(req["ike-id"], "3")

    def test_terminate_by_child_id(self):
        self.session.terminate.return_value = []
        self.svc.terminate(child_id=7)
        req = self.session.terminate.call_args[0][0]
        self.assertEqual(req["child-id"], "7")

    def test_rekey_ike(self):
        self.svc.rekey(ike="rw")
        req = self.session.rekey.call_args[0][0]
        self.assertEqual(req["ike"], "rw")

    def test_rekey_child(self):
        self.svc.rekey(child="all", ike_id=2)
        req = self.session.rekey.call_args[0][0]
        self.assertEqual(req["child"], "all")
        self.assertEqual(req["ike-id"], "2")

    def test_rekey_raises_operation_error_on_failure(self):
        self.session.rekey.side_effect = Exception("no such SA")
        with self.assertRaises(ViciOperationError):
            self.svc.rekey(ike="rw")

    def test_redirect(self):
        self.svc.redirect(ike_id=1, peer_ip="10.0.0.5")
        self.session.redirect.assert_called_once_with(
            OrderedDict([("ike-id", "1"), ("peer-ip", "10.0.0.5")])
        )


class TestCredentialCommands(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_load_shared(self):
        secret = OrderedDict(type="IKE", data="s3cr3t")
        self.svc.load_shared(secret)
        self.session.load_shared.assert_called_once_with(secret)

    def test_load_shared_raises_auth_error_on_failure(self):
        self.session.load_shared.side_effect = Exception("invalid")
        with self.assertRaises(ViciAuthenticationError):
            self.svc.load_shared({})

    def test_load_key(self):
        key = OrderedDict(type="RSA", data=b"-----BEGIN")
        self.svc.load_key(key)
        self.session.load_key.assert_called_once_with(key)

    def test_unload_key(self):
        self.svc.unload_key("my-key-id")
        self.session.unload_key.assert_called_once_with(OrderedDict(id="my-key-id"))

    def test_get_keys(self):
        self.session.get_keys.return_value = ["key-1", "key-2"]
        keys = self.svc.get_keys()
        self.assertEqual(keys, ["key-1", "key-2"])

    def test_unload_shared(self):
        self.svc.unload_shared("psk-id", type_="IKE")
        req = self.session.unload_shared.call_args[0][0]
        self.assertEqual(req["id"], "psk-id")
        self.assertEqual(req["type"], "IKE")

    def test_get_shared(self):
        self.session.get_shared.return_value = [{"type": "IKE"}]
        result = self.svc.get_shared()
        self.session.get_shared.assert_called_once_with({})

    def test_get_shared_with_type_filter(self):
        self.session.get_shared.return_value = []
        self.svc.get_shared(type_="EAP")
        self.session.get_shared.assert_called_once_with(OrderedDict(type="EAP"))

    def test_load_certificate(self):
        cert = {"type": "X509", "data": b"cert-bytes"}
        self.svc.load_certificate(cert)
        self.session.load_cert.assert_called_once_with(cert)

    def test_list_certificates(self):
        self.session.list_certs.return_value = [{"type": b"X509"}]
        certs = self.svc.list_certificates()
        self.session.list_certs.assert_called_once_with(OrderedDict(type="X509"))

    def test_clear_creds(self):
        self.svc.clear_creds()
        self.session.clear_creds.assert_called_once()

    def test_flush_certs(self):
        self.svc.flush_certs()
        self.session.flush_certs.assert_called_once_with({})

    def test_flush_certs_with_type(self):
        self.svc.flush_certs(type_="X509")
        self.session.flush_certs.assert_called_once_with(OrderedDict(type="X509"))


class TestAuthorityCommands(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_load_authority(self):
        auth = {"my-ca": {"cacert": b"pem-bytes", "crl_uris": ["http://ca.example.com/crl"]}}
        self.svc.load_authority(auth)
        self.session.load_authority.assert_called_once_with(auth)

    def test_load_authority_raises_load_error(self):
        self.session.load_authority.side_effect = Exception("cert not found")
        with self.assertRaises(ViciLoadError):
            self.svc.load_authority({})

    def test_unload_authority(self):
        self.svc.unload_authority("my-ca")
        self.session.unload_authority.assert_called_once_with(OrderedDict(name="my-ca"))

    def test_list_authorities(self):
        self.session.list_authorities.return_value = [{"my-ca": {}}]
        result = self.svc.list_authorities()
        self.assertEqual(len(result), 1)

    def test_get_authorities(self):
        self.session.get_authorities.return_value = {"my-ca": {}}
        result = self.svc.get_authorities()
        self.assertIn("my-ca", result)


class TestPoolCommands(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_load_pool(self):
        pool = {"pool1": {"addrs": "10.10.0.0/24"}}
        self.svc.load_pool(pool)
        self.session.load_pool.assert_called_once_with(pool)

    def test_unload_pool(self):
        self.svc.unload_pool("pool1")
        self.session.unload_pool.assert_called_once_with(OrderedDict(name="pool1"))

    def test_get_pools_no_leases(self):
        self.session.get_pools.return_value = {"pool1": {"base": b"10.10.0.0"}}
        result = self.svc.get_pools()
        self.session.get_pools.assert_called_once_with(OrderedDict(leases="no"))

    def test_get_pools_with_leases(self):
        self.session.get_pools.return_value = {}
        self.svc.get_pools(include_leases=True)
        self.session.get_pools.assert_called_once_with(OrderedDict(leases="yes"))


class TestPolicyCommands(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_install_policy(self):
        policy = {"child": {"local_ts": ["10.0.0.0/8"]}}
        self.svc.install_policy(policy)
        self.session.install.assert_called_once_with(policy)

    def test_uninstall_policy(self):
        policy = {"child": {}}
        self.svc.uninstall_policy(policy)
        self.session.uninstall.assert_called_once_with(policy)

    def test_list_policies_default(self):
        self.session.list_policies.return_value = []
        self.svc.list_policies()
        req = self.session.list_policies.call_args[0][0]
        self.assertEqual(req["trap"], "yes")
        self.assertEqual(req["drop"], "yes")
        self.assertEqual(req["pass"], "yes")

    def test_list_policies_trap_only(self):
        self.session.list_policies.return_value = []
        self.svc.list_policies(trap=True, drop=False, pass_=False)
        req = self.session.list_policies.call_args[0][0]
        self.assertNotIn("drop", req)
        self.assertNotIn("pass", req)


class TestCounterCommands(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_get_counters_all(self):
        self.session.get_counters.return_value = {"IKE_AUTH_received": 5}
        result = self.svc.get_counters()
        self.session.get_counters.assert_called_once_with({})
        self.assertEqual(result["IKE_AUTH_received"], 5)

    def test_get_counters_named(self):
        self.session.get_counters.return_value = {}
        self.svc.get_counters(name="rw")
        self.session.get_counters.assert_called_once_with(OrderedDict(name="rw"))

    def test_get_counters_returns_empty_dict_on_none(self):
        self.session.get_counters.return_value = None
        result = self.svc.get_counters()
        self.assertEqual(result, {})

    def test_reset_counters_all(self):
        self.svc.reset_counters()
        self.session.reset_counters.assert_called_once_with({})

    def test_reset_counters_named(self):
        self.svc.reset_counters(name="rw")
        self.session.reset_counters.assert_called_once_with(OrderedDict(name="rw"))

    def test_reset_counters_raises_operation_error(self):
        self.session.reset_counters.side_effect = Exception("permission denied")
        with self.assertRaises(ViciOperationError):
            self.svc.reset_counters()


class TestDaemonCommands(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_reload_settings(self):
        self.svc.reload_settings()
        self.session.reload_settings.assert_called_once()

    def test_reload_settings_raises_operation_error(self):
        self.session.reload_settings.side_effect = Exception("failed")
        with self.assertRaises(ViciOperationError):
            self.svc.reload_settings()

    def test_get_version(self):
        self.session.version.return_value = {"daemon": b"charon", "version": b"6.0.4"}
        result = self.svc.get_version()
        self.assertEqual(result["version"], b"6.0.4")

    def test_get_stats(self):
        self.session.stats.return_value = {
            "uptime": {"running": b"5 minutes"},
            "plugins": {"kernel-netlink": {}, "openssl": {}},
        }
        result = self.svc.get_stats()
        self.assertIn("uptime", result)

    def test_get_plugins(self):
        self.session.stats.return_value = {
            "plugins": {"kernel-netlink": {}, "openssl": {}, "vici": {}}
        }
        plugins = self.svc.get_plugins()
        self.assertIn("openssl", plugins)
        self.assertEqual(len(plugins), 3)

    def test_get_algorithms(self):
        self.session.get_algorithms.return_value = {"IKE": ["aes128gcm128"], "ESP": ["aes256gcm128"]}
        result = self.svc.get_algorithms()
        self.assertIn("IKE", result)


class TestReconnectBehavior(unittest.TestCase):
    def test_reconnects_on_first_call_failure(self):
        """If first call raises OSError, should reconnect and retry successfully."""
        first_session = _make_session()
        second_session = _make_session()

        first_session.list_conns.side_effect = OSError("broken pipe")
        second_session.list_conns.return_value = [{"rw": {}}]

        svc = ViciService.__new__(ViciService)
        svc._socket_path = "/fake"
        svc._lock = threading.RLock()
        svc._sock = MagicMock()
        svc._session = first_session

        connect_calls = []

        def fake_connect():
            connect_calls.append(1)
            svc._session = second_session
            svc._sock = MagicMock()

        svc._connect = fake_connect

        names = svc.get_connection_names()
        self.assertEqual(connect_calls, [1])
        self.assertEqual(names, ["rw"])

    def test_raises_unavailable_when_reconnect_also_fails(self):
        """If both the initial call and reconnect fail, raise ViciUnavailable."""
        session = _make_session()
        session.list_conns.side_effect = OSError("broken")

        svc = ViciService.__new__(ViciService)
        svc._socket_path = "/fake"
        svc._lock = threading.RLock()
        svc._sock = MagicMock()
        svc._session = session

        def fake_connect_fail():
            raise ViciUnavailable("still broken")

        svc._connect = fake_connect_fail

        with self.assertRaises(ViciUnavailable):
            svc.get_connection_names()


class TestBulkHelpers(unittest.TestCase):
    def setUp(self):
        self.session = _make_session()
        self.svc = _make_service(self.session)

    def test_load_all_connections(self):
        conn_a = MagicMock()
        conn_a.dict.return_value = {"a": {}}
        conn_a.profile = "a"
        conn_b = MagicMock()
        conn_b.dict.return_value = {"b": {}}
        conn_b.profile = "b"
        self.svc.load_all_connections([conn_a, conn_b])
        self.assertEqual(self.session.load_conn.call_count, 2)

    def test_load_all_secrets(self):
        s1 = MagicMock()
        s1.dict.return_value = {"type": "IKE", "data": "abc"}
        self.svc.load_all_secrets([s1])
        self.session.load_shared.assert_called_once()

    def test_load_all_authorities(self):
        a1 = MagicMock()
        a1.dict.return_value = {"my-ca": {"cacert": b"pem"}}
        a1.name = "my-ca"
        self.svc.load_all_authorities([a1])
        self.session.load_authority.assert_called_once()

    def test_load_all_connections_skips_bad_row(self):
        good = MagicMock()
        good.dict.return_value = {"good": {}}
        good.profile = "good"
        bad = MagicMock()
        bad.dict.side_effect = Exception("encoding error")
        bad.profile = "bad"
        self.svc.load_all_connections([bad, good])
        # bad skipped, good still loaded
        self.session.load_conn.assert_called_once_with({"good": {}})
