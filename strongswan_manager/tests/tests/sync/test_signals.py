"""
Integration tests for Django signals — verify GUI→StrongSwan sync fires on model saves.
ViciService is patched so no live charon is needed.
"""
import os
from unittest.mock import MagicMock, patch, PropertyMock

from django.test import TestCase

from strongswan_manager.services.exceptions import ViciUnavailable


def _patch_vici(mock_vici):
    """Patch ViciService.get_instance() to return mock_vici."""
    return patch(
        "strongswan_manager.services.sync_engine.ViciService.get_instance",
        return_value=mock_vici,
    )


class TestConnectionSignals(TestCase):
    fixtures = ['initial_data.json']

    def _make_vici_mock(self):
        m = MagicMock()
        m.load_connection = MagicMock()
        m.unload_connection = MagicMock()
        return m

    def test_save_enabled_connection_calls_load(self):
        from strongswan_manager.apps.connections.models import IKEv2Certificate
        vici = self._make_vici_mock()
        with _patch_vici(vici):
            conn = IKEv2Certificate(profile="sig-test", version="2",
                                    enabled=True, connection_type="client")
            conn.save()
        vici.load_connection.assert_called()
        call_arg = vici.load_connection.call_args[0][0]
        self.assertIn("sig-test", call_arg)

    def test_save_disabled_connection_calls_unload(self):
        from strongswan_manager.apps.connections.models import IKEv2Certificate
        vici = self._make_vici_mock()
        with _patch_vici(vici):
            conn = IKEv2Certificate(profile="sig-disabled", version="2",
                                    enabled=False, connection_type="client")
            conn.save()
        vici.unload_connection.assert_called_with("sig-disabled")

    def test_delete_connection_calls_unload(self):
        from strongswan_manager.apps.connections.models import IKEv2Certificate
        vici = self._make_vici_mock()
        with _patch_vici(vici):
            conn = IKEv2Certificate(profile="sig-delete", version="2",
                                    enabled=True, connection_type="client")
            conn.save()
            vici.reset_mock()
            conn.delete()
        vici.unload_connection.assert_called_with("sig-delete")

    def test_vici_unavailable_does_not_crash_save(self):
        """A save must succeed even when charon is down."""
        from strongswan_manager.apps.connections.models import IKEv2Certificate
        vici = self._make_vici_mock()
        vici.load_connection.side_effect = ViciUnavailable("down")
        with _patch_vici(vici):
            conn = IKEv2Certificate(profile="sig-nocrash", version="2",
                                    enabled=True, connection_type="client")
            conn.save()  # must not raise
        self.assertTrue(
            __import__("strongswan_manager.apps.connections.models",
                       fromlist=["IKEv2Certificate"])
            .IKEv2Certificate.objects.filter(profile="sig-nocrash").exists()
        )


class TestSecretSignals(TestCase):
    fixtures = ['initial_data.json']

    def _make_secret(self, username="testsig"):
        from strongswan_manager.apps.eap_secrets.models import Secret
        salt = os.urandom(16).hex()
        s = Secret(username=username, type="EAP", salt=salt)
        s.password = salt + "pass"
        return s

    def test_save_secret_calls_load_shared(self):
        vici = MagicMock()
        with _patch_vici(vici):
            s = self._make_secret()
            s.save()
        vici.load_shared.assert_called()

    def test_vici_unavailable_does_not_crash_secret_save(self):
        vici = MagicMock()
        vici.load_shared.side_effect = ViciUnavailable("down")
        with _patch_vici(vici):
            s = self._make_secret("safetest")
            s.save()  # must not raise
        from strongswan_manager.apps.eap_secrets.models import Secret
        self.assertTrue(Secret.objects.filter(username="safetest").exists())


class TestAuthoritySignals(TestCase):
    fixtures = ['initial_data.json']

    def test_save_authority_calls_load_authority(self):
        from strongswan_manager.apps.certificates.models import Authority
        vici = MagicMock()
        with _patch_vici(vici):
            a = Authority(name="test-ca", cacert="ca.pem")
            a.save()
        vici.load_authority.assert_called()

    def test_delete_authority_calls_unload_authority(self):
        from strongswan_manager.apps.certificates.models import Authority
        vici = MagicMock()
        with _patch_vici(vici):
            a = Authority(name="del-ca", cacert="ca.pem")
            a.save()
            vici.reset_mock()
            a.delete()
        vici.unload_authority.assert_called_with("del-ca")


class TestPoolSignals(TestCase):
    fixtures = ['initial_data.json']

    def test_save_pool_calls_load_pool(self):
        from strongswan_manager.apps.pools.models import Pool
        vici = MagicMock()
        with _patch_vici(vici):
            p = Pool(poolname="sig-pool", addresses="10.11.0.0/24")
            p.save()
        vici.load_pool.assert_called()

    def test_delete_pool_calls_unload_pool(self):
        from strongswan_manager.apps.pools.models import Pool
        vici = MagicMock()
        with _patch_vici(vici):
            p = Pool(poolname="del-pool", addresses="10.11.0.0/24")
            p.save()
            vici.reset_mock()
            p.delete()
        vici.unload_pool.assert_called_with("del-pool")
