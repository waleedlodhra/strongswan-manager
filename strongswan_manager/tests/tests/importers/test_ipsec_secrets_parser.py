"""
Unit tests for IpsecSecretsParser.
"""
import textwrap
import unittest

from strongswan_manager.services.importers.ipsec_secrets_parser import IpsecSecretsParser


class TestIpsecSecretsParser(unittest.TestCase):

    def test_psk_with_two_selectors(self):
        text = '10.10.10.1 10.10.10.3 : PSK "mypassword123"\n'
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(len(specs), 1)
        s = specs[0]
        self.assertEqual(s.type, "IKE")
        self.assertEqual(s.secret, "mypassword123")
        self.assertEqual(s.left_id, "10.10.10.1")
        self.assertEqual(s.right_id, "10.10.10.3")

    def test_psk_wildcard(self):
        text = '%any %any : PSK "shared"\n'
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(specs[0].left_id, "%any")
        self.assertEqual(specs[0].right_id, "%any")
        self.assertEqual(specs[0].secret, "shared")

    def test_psk_no_selector(self):
        text = ': PSK "noselect"\n'
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].type, "IKE")
        self.assertEqual(specs[0].secret, "noselect")
        self.assertEqual(specs[0].left_id, "%any")

    def test_eap_secret(self):
        text = 'alice : EAP "alice-password"\n'
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(specs[0].type, "EAP")
        self.assertEqual(specs[0].username, "alice")
        self.assertEqual(specs[0].secret, "alice-password")

    def test_xauth_secret(self):
        text = 'bob : XAUTH "bob-pass"\n'
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(specs[0].type, "XAUTH")
        self.assertEqual(specs[0].username, "bob")
        self.assertEqual(specs[0].secret, "bob-pass")

    def test_rsa_keyfile(self):
        text = ': RSA /etc/ipsec.d/private/mykey.pem\n'
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(specs[0].type, "RSA")
        self.assertEqual(specs[0].keyfile, "/etc/ipsec.d/private/mykey.pem")
        self.assertEqual(specs[0].secret, "")

    def test_comments_skipped(self):
        text = textwrap.dedent("""\
            # This file holds shared secrets
            # RSA private key for this host
            10.0.0.1 10.0.0.2 : PSK "s3cr3t"
        """)
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(len(specs), 1)

    def test_multiple_secrets(self):
        text = textwrap.dedent("""\
            10.0.0.1 10.0.0.2 : PSK "psk1"
            alice : EAP "pass1"
            bob : XAUTH "pass2"
        """)
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(len(specs), 3)

    def test_unquoted_secret(self):
        text = ': PSK s3cr3t_no_quotes\n'
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(specs[0].secret, "s3cr3t_no_quotes")

    def test_single_quoted_secret(self):
        text = ": PSK 'singlequoted'\n"
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(specs[0].secret, "singlequoted")

    def test_empty_text(self):
        specs = IpsecSecretsParser.parse_text("")
        self.assertEqual(specs, [])

    def test_only_comments(self):
        text = "# just comments\n# another line\n"
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(specs, [])

    def test_live_format(self):
        """Test parsing the actual format from the VM's ipsec.secrets."""
        text = '10.10.10.1 10.10.10.3 : PSK "mypassword123"\n'
        specs = IpsecSecretsParser.parse_text(text)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].secret, "mypassword123")
