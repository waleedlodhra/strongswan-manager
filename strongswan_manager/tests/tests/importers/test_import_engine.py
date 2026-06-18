"""
Integration tests for ConfigImportEngine.
Tests use in-memory config text (no filesystem files) by pointing the engine
at temp files or by calling the parsers directly.
"""
import os
import tempfile
import textwrap
from django.test import TestCase

from strongswan_manager.apps.connections.models import Connection, Child, Address, Proposal
from strongswan_manager.apps.eap_secrets.models import Secret
from strongswan_manager.apps.pools.models import Pool
from strongswan_manager.apps.certificates.models import Authority
from strongswan_manager.services.importers import ConfigImportEngine


def _write_tmp(content: str, suffix: str = ".conf") -> str:
    """Write content to a named temp file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.flush()
    f.close()
    return f.name


class TestImportEngineIpsecConf(TestCase):
    fixtures = ['initial_data.json']

    IPSEC_CONF = textwrap.dedent("""\
        conn hq-host1
            auto=start
            keyexchange=ikev1
            authby=secret
            left=10.10.10.3
            leftsubnet=192.168.30.10/32
            right=10.10.10.1
            rightsubnet=192.168.10.10/32
            ike=aes256-sha1-modp2048
            esp=aes256-sha1
    """)

    IPSEC_SECRETS = '10.10.10.1 10.10.10.3 : PSK "mypassword123"\n'

    def setUp(self):
        self.conf_file = _write_tmp(self.IPSEC_CONF, ".conf")
        self.secrets_file = _write_tmp(self.IPSEC_SECRETS, ".secrets")
        self.engine = ConfigImportEngine(
            ipsec_conf=self.conf_file,
            ipsec_secrets=self.secrets_file,
            swanctl_conf="/nonexistent/swanctl.conf",
        )

    def tearDown(self):
        os.unlink(self.conf_file)
        os.unlink(self.secrets_file)

    def test_creates_connection(self):
        result = self.engine.import_all()
        self.assertEqual(result.connections_created, 1)
        self.assertEqual(result.errors, [])
        self.assertTrue(Connection.objects.filter(profile="hq-host1").exists())

    def test_connection_version_ikev1(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="hq-host1")
        self.assertEqual(conn.version, "1")

    def test_connection_enabled(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="hq-host1")
        self.assertTrue(conn.enabled)
        self.assertTrue(conn.initiate)

    def test_child_sa_created(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="hq-host1")
        self.assertEqual(conn.children.count(), 1)
        child = conn.children.first()
        self.assertEqual(child.name, "hq-host1-child")

    def test_traffic_selectors(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="hq-host1")
        child = conn.children.first()
        local_ts = child.local_ts.values_list("value", flat=True)
        remote_ts = child.remote_ts.values_list("value", flat=True)
        self.assertIn("192.168.30.10/32", local_ts)
        self.assertIn("192.168.10.10/32", remote_ts)

    def test_ike_proposal_created(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="hq-host1")
        self.assertTrue(conn.proposals.filter(type="aes256-sha1-modp2048").exists())

    def test_esp_proposal_created(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="hq-host1")
        child = conn.children.first()
        self.assertTrue(child.esp_proposals.filter(type="aes256-sha1").exists())

    def test_secret_created(self):
        result = self.engine.import_all()
        self.assertEqual(result.secrets_created, 1)

    def test_skip_existing_profile(self):
        self.engine.import_all()
        result2 = self.engine.import_all()
        self.assertEqual(result2.connections_skipped, 1)
        self.assertEqual(result2.connections_created, 0)

    def test_skip_existing_secret(self):
        self.engine.import_all()
        result2 = self.engine.import_all()
        self.assertEqual(result2.secrets_skipped, 1)

    def test_two_connections(self):
        conf = textwrap.dedent("""\
            conn alpha
                auto=start
                keyexchange=ikev1
                authby=secret
                left=10.0.0.1
                right=10.0.0.2

            conn beta
                auto=add
                keyexchange=ikev2
                authby=pubkey
                left=10.0.0.1
                right=10.0.0.3
        """)
        conf_file = _write_tmp(conf)
        try:
            engine = ConfigImportEngine(
                ipsec_conf=conf_file,
                ipsec_secrets="/nonexistent",
                swanctl_conf="/nonexistent",
            )
            result = engine.import_all()
            self.assertEqual(result.connections_created, 2)
        finally:
            os.unlink(conf_file)


class TestImportEngineSwanctlConf(TestCase):
    fixtures = ['initial_data.json']

    SWANCTL_CONF = textwrap.dedent("""\
        connections {
            rw {
                version = 2
                local_addrs = 10.0.0.1
                remote_addrs = %any
                proposals = aes128gcm128-ecp256

                local {
                    auth = pubkey
                }

                remote {
                    auth = eap-mschapv2
                }

                children {
                    home {
                        local_ts = 10.1.0.0/16
                        remote_ts = dynamic
                        esp_proposals = aes128gcm128-ecp256
                        mode = tunnel
                        start_action = trap
                    }
                }
            }
        }

        secrets {
            ike-1 {
                id = %any
                secret = "testPSK"
            }
        }

        pools {
            pool-1 {
                addrs = 10.10.0.0/24
            }
        }

        authorities {
            my-ca {
                cacert = caCert.pem
                crl_uris = http://crl.example.com/crl
            }
        }
    """)

    def setUp(self):
        self.swanctl_file = _write_tmp(self.SWANCTL_CONF, ".conf")
        self.engine = ConfigImportEngine(
            ipsec_conf="/nonexistent",
            ipsec_secrets="/nonexistent",
            swanctl_conf=self.swanctl_file,
        )

    def tearDown(self):
        os.unlink(self.swanctl_file)

    def test_creates_connection(self):
        result = self.engine.import_all()
        self.assertEqual(result.connections_created, 1, result.errors)
        self.assertTrue(Connection.objects.filter(profile="rw").exists())

    def test_connection_version(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="rw")
        self.assertEqual(conn.version, "2")

    def test_proposals(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="rw")
        self.assertTrue(conn.proposals.filter(type="aes128gcm128-ecp256").exists())

    def test_child_sa(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="rw")
        self.assertEqual(conn.children.count(), 1)
        child = conn.children.first()
        self.assertEqual(child.name, "home")
        self.assertEqual(child.mode, "tunnel")
        self.assertEqual(child.start_action, "trap")

    def test_child_esp_proposals(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="rw")
        child = conn.children.first()
        self.assertTrue(child.esp_proposals.filter(type="aes128gcm128-ecp256").exists())

    def test_child_traffic_selectors(self):
        self.engine.import_all()
        conn = Connection.objects.get(profile="rw")
        child = conn.children.first()
        local_ts = list(child.local_ts.values_list("value", flat=True))
        self.assertIn("10.1.0.0/16", local_ts)

    def test_secret_created(self):
        result = self.engine.import_all()
        self.assertEqual(result.secrets_created, 1)

    def test_pool_created(self):
        result = self.engine.import_all()
        self.assertEqual(result.pools_created, 1)
        self.assertTrue(Pool.objects.filter(poolname="pool-1").exists())

    def test_authority_created(self):
        result = self.engine.import_all()
        self.assertEqual(result.authorities_created, 1)
        self.assertTrue(Authority.objects.filter(name="my-ca").exists())
        auth = Authority.objects.get(name="my-ca")
        self.assertIn("crl.example.com", auth.crl_uris)

    def test_idempotent_reimport(self):
        self.engine.import_all()
        result2 = self.engine.import_all()
        self.assertEqual(result2.connections_created, 0)
        self.assertEqual(result2.connections_skipped, 1)
        self.assertEqual(result2.pools_created, 0)
        self.assertEqual(result2.authorities_created, 0)


class TestImportEngineImportResult(TestCase):
    fixtures = ['initial_data.json']

    def test_import_result_str(self):
        from strongswan_manager.services.importers import ImportResult
        r = ImportResult(
            connections_created=2, connections_skipped=1,
            secrets_created=1, pools_created=1, authorities_created=0,
        )
        text = str(r)
        self.assertIn("2 created", text)
        self.assertIn("1 skipped", text)

    def test_missing_files_no_error(self):
        engine = ConfigImportEngine(
            ipsec_conf="/nonexistent/ipsec.conf",
            ipsec_secrets="/nonexistent/ipsec.secrets",
            swanctl_conf="/nonexistent/swanctl.conf",
        )
        result = engine.import_all()
        self.assertEqual(result.connections_created, 0)
        self.assertEqual(result.errors, [])
