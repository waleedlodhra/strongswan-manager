"""
Unit tests for IpsecConfParser — covers all major ipsec.conf features.
"""
import textwrap
import unittest

from strongswan_manager.services.importers.ipsec_conf_parser import IpsecConfParser


BASIC_CONF = textwrap.dedent("""\
    # basic configuration
    config setup
        charondebug="all"

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

    conn hq-host2
        auto=add
        keyexchange=ikev1
        authby=secret
        left=10.10.10.3
        leftsubnet=192.168.30.20/32
        right=10.10.10.1
        rightsubnet=192.168.10.20/32
        ike=aes256-sha1-modp2048
        esp=aes256-sha1
""")


class TestIpsecConfParserBasic(unittest.TestCase):
    def setUp(self):
        self.specs = IpsecConfParser.parse_text(BASIC_CONF)

    def test_parses_two_conns(self):
        self.assertEqual(len(self.specs), 2)

    def test_conn_names(self):
        names = [s.name for s in self.specs]
        self.assertIn("hq-host1", names)
        self.assertIn("hq-host2", names)

    def test_auto_start(self):
        spec = next(s for s in self.specs if s.name == "hq-host1")
        self.assertEqual(spec.auto, "start")

    def test_auto_add(self):
        spec = next(s for s in self.specs if s.name == "hq-host2")
        self.assertEqual(spec.auto, "add")

    def test_keyexchange(self):
        spec = self.specs[0]
        self.assertEqual(spec.keyexchange, "ikev1")

    def test_authby_secret(self):
        spec = self.specs[0]
        self.assertEqual(spec.authby, "secret")

    def test_addresses(self):
        spec = next(s for s in self.specs if s.name == "hq-host1")
        self.assertEqual(spec.left, "10.10.10.3")
        self.assertEqual(spec.leftsubnet, "192.168.30.10/32")
        self.assertEqual(spec.right, "10.10.10.1")
        self.assertEqual(spec.rightsubnet, "192.168.10.10/32")

    def test_proposals(self):
        spec = self.specs[0]
        self.assertEqual(spec.ike, "aes256-sha1-modp2048")
        self.assertEqual(spec.esp, "aes256-sha1")


class TestIpsecConfParserDefaults(unittest.TestCase):
    def test_percent_default_applied(self):
        conf = textwrap.dedent("""\
            conn %default
                keyexchange=ikev1
                authby=secret
                ike=aes128-sha256-modp2048

            conn first
                left=10.0.0.1
                right=10.0.0.2

            conn second
                left=10.0.0.3
                right=10.0.0.4
                ike=aes256-sha1-modp1024
        """)
        specs = IpsecConfParser.parse_text(conf)
        self.assertEqual(len(specs), 2)
        # first inherits from %default
        first = next(s for s in specs if s.name == "first")
        self.assertEqual(first.keyexchange, "ikev1")
        self.assertEqual(first.ike, "aes128-sha256-modp2048")
        # second overrides ike
        second = next(s for s in specs if s.name == "second")
        self.assertEqual(second.ike, "aes256-sha1-modp1024")

    def test_config_setup_not_returned_as_conn(self):
        conf = textwrap.dedent("""\
            config setup
                charondebug="all"
            conn test
                auto=start
        """)
        specs = IpsecConfParser.parse_text(conf)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].name, "test")

    def test_percent_default_not_returned(self):
        conf = textwrap.dedent("""\
            conn %default
                keyexchange=ikev2
            conn real
                left=1.2.3.4
        """)
        specs = IpsecConfParser.parse_text(conf)
        names = [s.name for s in specs]
        self.assertNotIn("%default", names)
        self.assertIn("real", names)


class TestIpsecConfParserOptions(unittest.TestCase):
    def test_aggressive_yes(self):
        conf = "conn test\n    aggressive=yes\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertTrue(spec.aggressive)

    def test_aggressive_no(self):
        conf = "conn test\n    aggressive=no\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertFalse(spec.aggressive)

    def test_mobike(self):
        conf = "conn test\n    mobike=no\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertFalse(spec.mobike)

    def test_keyingtries(self):
        conf = "conn test\n    keyingtries=3\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertEqual(spec.keyingtries, 3)

    def test_dpd_fields(self):
        conf = "conn test\n    dpddelay=30s\n    dpdtimeout=150s\n    dpdaction=restart\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertEqual(spec.dpddelay, "30s")
        self.assertEqual(spec.dpdtimeout, "150s")
        self.assertEqual(spec.dpdaction, "restart")

    def test_transport_mode(self):
        conf = "conn test\n    type=transport\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertEqual(spec.type, "transport")

    def test_comments_stripped(self):
        conf = "conn test  # inline comment\n    auto=start  # another comment\n"
        specs = IpsecConfParser.parse_text(conf)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].auto, "start")

    def test_xauth_authby(self):
        conf = "conn test\n    authby=xauthpsk\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertEqual(spec.authby, "xauthpsk")

    def test_extra_unknown_keys_stored(self):
        conf = "conn test\n    mark=42\n    someunknown=value\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertIn("mark", spec.extra)
        self.assertIn("someunknown", spec.extra)

    def test_empty_text(self):
        specs = IpsecConfParser.parse_text("")
        self.assertEqual(specs, [])

    def test_only_comments(self):
        conf = "# just a comment\n# another one\n"
        specs = IpsecConfParser.parse_text(conf)
        self.assertEqual(specs, [])

    def test_ikev2_default_version(self):
        conf = "conn test\n    auto=start\n"
        spec = IpsecConfParser.parse_text(conf)[0]
        self.assertEqual(spec.keyexchange, "ikev2")
