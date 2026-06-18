"""
Unit tests for SwanctlConfParser — covers the UCL-like format.
"""
import textwrap
import unittest

from strongswan_manager.services.importers.swanctl_conf_parser import SwanctlConfParser


FULL_CONF = textwrap.dedent("""\
    connections {
        rw {
            version = 2
            local_addrs = 10.0.0.1
            remote_addrs = %any
            proposals = aes128gcm128-ecp256, aes256gcm128-ecp384

            local {
                auth = pubkey
                certs = serverCert.pem
                id = server@example.com
            }

            remote {
                auth = eap-mschapv2
                eap_id = %any
            }

            children {
                home {
                    local_ts = 10.1.0.0/16
                    remote_ts = dynamic
                    esp_proposals = aes128gcm128-ecp256
                    mode = tunnel
                    start_action = trap
                    dpd_action = clear
                }
            }
        }

        site-to-site {
            version = 2
            local_addrs = 10.0.0.1
            remote_addrs = 10.0.0.2
            rekey_time = 4h
            dpd_delay = 30s

            local {
                auth = psk
                id = 10.0.0.1
            }

            remote {
                auth = psk
                id = 10.0.0.2
            }

            children {
                net {
                    local_ts = 192.168.1.0/24
                    remote_ts = 192.168.2.0/24
                    esp_proposals = aes256-sha256
                    mode = tunnel
                }
            }
        }
    }

    secrets {
        ike-1 {
            id = %any
            secret = "myPSK"
        }
        eap-alice {
            id = alice
            secret = "alice-pass"
        }
    }

    pools {
        pool-1 {
            addrs = 10.10.0.0/24
            dns = 8.8.8.8
        }
    }

    authorities {
        my-ca {
            cacert = caCert.pem
            crl_uris = http://crl.example.com/crl
            ocsp_uris = http://ocsp.example.com
        }
    }
""")


class TestSwanctlConfParserBasic(unittest.TestCase):
    def setUp(self):
        self.tree = SwanctlConfParser.parse_text(FULL_CONF)

    def test_top_level_sections(self):
        self.assertIn("connections", self.tree)
        self.assertIn("secrets", self.tree)
        self.assertIn("pools", self.tree)
        self.assertIn("authorities", self.tree)

    def test_two_connections(self):
        conns = self.tree["connections"]
        self.assertIn("rw", conns)
        self.assertIn("site-to-site", conns)

    def test_rw_version(self):
        self.assertEqual(self.tree["connections"]["rw"]["version"], "2")

    def test_rw_local_addrs(self):
        self.assertEqual(self.tree["connections"]["rw"]["local_addrs"], "10.0.0.1")

    def test_comma_list_proposals(self):
        props = self.tree["connections"]["rw"]["proposals"]
        self.assertIsInstance(props, list)
        self.assertEqual(len(props), 2)
        self.assertIn("aes128gcm128-ecp256", props)

    def test_local_auth_section(self):
        local = self.tree["connections"]["rw"]["local"]
        self.assertEqual(local["auth"], "pubkey")
        self.assertEqual(local["id"], "server@example.com")

    def test_remote_auth_section(self):
        remote = self.tree["connections"]["rw"]["remote"]
        self.assertEqual(remote["auth"], "eap-mschapv2")

    def test_child_sa(self):
        children = self.tree["connections"]["rw"]["children"]
        self.assertIn("home", children)
        home = children["home"]
        self.assertEqual(home["mode"], "tunnel")
        self.assertEqual(home["start_action"], "trap")
        self.assertEqual(home["dpd_action"], "clear")

    def test_s2s_rekey_time(self):
        s2s = self.tree["connections"]["site-to-site"]
        self.assertEqual(s2s["rekey_time"], "4h")
        self.assertEqual(s2s["dpd_delay"], "30s")

    def test_secrets(self):
        secrets = self.tree["secrets"]
        self.assertIn("ike-1", secrets)
        self.assertIn("eap-alice", secrets)
        self.assertEqual(secrets["ike-1"]["secret"], "myPSK")
        self.assertEqual(secrets["eap-alice"]["id"], "alice")

    def test_pools(self):
        pool = self.tree["pools"]["pool-1"]
        self.assertEqual(pool["addrs"], "10.10.0.0/24")

    def test_authorities(self):
        auth = self.tree["authorities"]["my-ca"]
        self.assertEqual(auth["cacert"], "caCert.pem")
        self.assertEqual(auth["crl_uris"], "http://crl.example.com/crl")
        self.assertEqual(auth["ocsp_uris"], "http://ocsp.example.com")


class TestSwanctlConfParserEdgeCases(unittest.TestCase):
    def test_empty_text(self):
        tree = SwanctlConfParser.parse_text("")
        self.assertEqual(tree, {})

    def test_comments_ignored(self):
        conf = textwrap.dedent("""\
            # Top-level comment
            connections {
                # conn comment
                test {
                    version = 2  # inline comment
                }
            }
        """)
        tree = SwanctlConfParser.parse_text(conf)
        self.assertIn("test", tree["connections"])
        self.assertEqual(tree["connections"]["test"]["version"], "2")

    def test_quoted_values(self):
        conf = 'secrets { ike-1 { secret = "my secret with spaces" } }'
        tree = SwanctlConfParser.parse_text(conf)
        self.assertEqual(tree["secrets"]["ike-1"]["secret"], "my secret with spaces")

    def test_single_quoted_values(self):
        conf = "secrets { ike-1 { secret = 'singlequoted' } }"
        tree = SwanctlConfParser.parse_text(conf)
        self.assertEqual(tree["secrets"]["ike-1"]["secret"], "singlequoted")

    def test_nested_children(self):
        conf = textwrap.dedent("""\
            connections {
                vpn {
                    version = 2
                    children {
                        child1 { mode = tunnel }
                        child2 { mode = transport }
                    }
                }
            }
        """)
        tree = SwanctlConfParser.parse_text(conf)
        children = tree["connections"]["vpn"]["children"]
        self.assertIn("child1", children)
        self.assertIn("child2", children)

    def test_multiple_auth_rounds(self):
        """Multiple local{}/remote{} sections with different names."""
        conf = textwrap.dedent("""\
            connections {
                dual {
                    local-cert { auth = pubkey }
                    local-eap { auth = eap-mschapv2 }
                }
            }
        """)
        tree = SwanctlConfParser.parse_text(conf)
        dual = tree["connections"]["dual"]
        self.assertIn("local-cert", dual)
        self.assertIn("local-eap", dual)

    def test_single_proposal_not_a_list(self):
        conf = "connections { c { proposals = aes128gcm128 } }"
        tree = SwanctlConfParser.parse_text(conf)
        self.assertEqual(tree["connections"]["c"]["proposals"], "aes128gcm128")

    def test_deeply_nested_ah_esp(self):
        conf = textwrap.dedent("""\
            connections {
                vpn {
                    children {
                        c1 {
                            esp_proposals = aes256-sha256
                            ah_proposals = sha256
                            local_ts = 10.0.0.0/8
                            remote_ts = 10.1.0.0/8, 10.2.0.0/8
                        }
                    }
                }
            }
        """)
        tree = SwanctlConfParser.parse_text(conf)
        c1 = tree["connections"]["vpn"]["children"]["c1"]
        self.assertEqual(c1["esp_proposals"], "aes256-sha256")
        remote_ts = c1["remote_ts"]
        self.assertIsInstance(remote_ts, list)
        self.assertEqual(len(remote_ts), 2)
