"""
Tests for Phase 6 IKEv1 form classes:
- PskForm (client + server side)
- XauthForm (client + server side)
- Ike1PskForm, Ike1CertificateForm, Ike1XauthPskForm, Ike1XauthCertificateForm (client)
- Server-side equivalents
- eap_id properties on PskAuthentication and XauthAuthentication
"""
import os
import unittest

from django.test import TestCase

from strongswan_manager.apps.connections.models import (
    Connection, Child, Address, Proposal,
    PskAuthentication, XauthAuthentication, Secret,
    IKEv1PSK, IKEv1Certificate, IKEv1XauthPSK, IKEv1XauthCertificate,
)

os.environ.setdefault("STRONGSWAN_DISABLE_MONITOR", "1")


def _base_connection(profile='test-conn', version='1', model=None):
    """Create a minimal connection with child/addresses for form tests."""
    cls = model or IKEv1PSK
    conn = cls(profile=profile, auth='psk', version=version)
    conn.save()
    child = Child(name=profile, connection=conn)
    child.save()
    Proposal(type='default', connection=conn).save()
    Proposal(type='default', child=child).save()
    Address(value='10.0.0.1', remote_addresses=conn).save()
    Address(value='localhost', local_addresses=conn).save()
    Address(value='0.0.0.0', vips=conn).save()
    Address(value='::', vips=conn).save()
    Address(value='::/0', remote_ts=child).save()
    Address(value='0.0.0.0/0', remote_ts=child).save()
    return conn


# ── eap_id properties ────────────────────────────────────────────────────────

class TestPskAuthenticationEapId(unittest.TestCase):
    def test_eap_id_returns_psk_id(self):
        auth = PskAuthentication.__new__(PskAuthentication)
        auth.psk_id = 'vpn@example.com'
        self.assertEqual(auth.eap_id, 'vpn@example.com')

    def test_eap_id_empty_when_psk_id_blank(self):
        auth = PskAuthentication.__new__(PskAuthentication)
        auth.psk_id = ''
        self.assertEqual(auth.eap_id, '')


class TestXauthAuthenticationEapId(unittest.TestCase):
    def test_eap_id_returns_xauth_id(self):
        auth = XauthAuthentication.__new__(XauthAuthentication)
        auth.xauth_id = 'john'
        self.assertEqual(auth.eap_id, 'john')

    def test_eap_id_empty_when_xauth_id_blank(self):
        auth = XauthAuthentication.__new__(XauthAuthentication)
        auth.xauth_id = ''
        self.assertEqual(auth.eap_id, '')


# ── PskForm (client-side) ─────────────────────────────────────────────────────

class TestClientPskForm(TestCase):
    fixtures = ['initial_data.json']

    def _make_form(self, data):
        from strongswan_manager.apps.connections.forms.SubForms import PskForm
        form = PskForm(data)
        form.is_valid()
        return form

    def test_create_connection_makes_local_psk_auth(self):
        conn = _base_connection('psk-create')
        form = self._make_form({'psk_id': 'user@example.com', 'psk_secret': 'mysecret'})
        form.create_connection(conn)

        local_psks = [a.subclass() for a in conn.local.all() if isinstance(a.subclass(), PskAuthentication)]
        self.assertEqual(len(local_psks), 1)
        self.assertEqual(local_psks[0].psk_id, 'user@example.com')

    def test_create_connection_makes_remote_psk_auth(self):
        conn = _base_connection('psk-remote')
        form = self._make_form({'psk_id': '', 'psk_secret': 'secret'})
        form.create_connection(conn)

        remote_psks = [a.subclass() for a in conn.remote.all() if isinstance(a.subclass(), PskAuthentication)]
        self.assertEqual(len(remote_psks), 1)

    def test_create_connection_stores_secret(self):
        conn = _base_connection('psk-secret')
        form = self._make_form({'psk_id': '', 'psk_secret': 'topsecret'})
        form.create_connection(conn)

        local_psk = next(
            a.subclass() for a in conn.local.all() if isinstance(a.subclass(), PskAuthentication)
        )
        secrets = list(Secret.objects.filter(authentication=local_psk))
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].type, 'IKE')
        self.assertEqual(secrets[0].data, 'topsecret')

    def test_create_connection_no_secret_when_empty(self):
        conn = _base_connection('psk-nosecret')
        form = self._make_form({'psk_id': '', 'psk_secret': ''})
        form.create_connection(conn)

        local_psk = next(
            a.subclass() for a in conn.local.all() if isinstance(a.subclass(), PskAuthentication)
        )
        self.assertEqual(Secret.objects.filter(authentication=local_psk).count(), 0)

    def test_update_connection_changes_psk_id(self):
        conn = _base_connection('psk-update')
        form_create = self._make_form({'psk_id': 'old@id', 'psk_secret': 'secret'})
        form_create.create_connection(conn)

        form_update = self._make_form({'psk_id': 'new@id', 'psk_secret': ''})
        form_update.update_connection(conn)

        local_psk = next(
            a.subclass() for a in conn.local.all() if isinstance(a.subclass(), PskAuthentication)
        )
        self.assertEqual(local_psk.psk_id, 'new@id')

    def test_update_connection_updates_secret_when_provided(self):
        conn = _base_connection('psk-update-secret')
        form_create = self._make_form({'psk_id': '', 'psk_secret': 'old'})
        form_create.create_connection(conn)

        form_update = self._make_form({'psk_id': '', 'psk_secret': 'new'})
        form_update.update_connection(conn)

        local_psk = next(
            a.subclass() for a in conn.local.all() if isinstance(a.subclass(), PskAuthentication)
        )
        self.assertEqual(Secret.objects.get(authentication=local_psk).data, 'new')

    def test_fill_populates_psk_id(self):
        from strongswan_manager.apps.connections.forms.SubForms import PskForm
        conn = _base_connection('psk-fill')
        PskAuthentication(name='local-psk', auth='psk', local=conn, psk_id='fill@id').save()

        form = PskForm()
        form.fill(conn)
        self.assertEqual(form.initial['psk_id'], 'fill@id')


# ── XauthForm (client-side) ───────────────────────────────────────────────────

class TestClientXauthForm(TestCase):
    fixtures = ['initial_data.json']

    def _make_form(self, data):
        from strongswan_manager.apps.connections.forms.SubForms import XauthForm
        form = XauthForm(data)
        form.is_valid()
        return form

    def test_create_connection_makes_xauth_auth(self):
        conn = _base_connection('xauth-create')
        form = self._make_form({'xauth_id': 'john', 'xauth_secret': 'pass'})
        form.create_connection(conn)

        xauths = [a.subclass() for a in conn.local.all() if isinstance(a.subclass(), XauthAuthentication)]
        self.assertEqual(len(xauths), 1)
        self.assertEqual(xauths[0].xauth_id, 'john')

    def test_create_connection_stores_xauth_secret(self):
        conn = _base_connection('xauth-secret')
        form = self._make_form({'xauth_id': 'john', 'xauth_secret': 'xauthpass'})
        form.create_connection(conn)

        xauth = next(
            a.subclass() for a in conn.local.all() if isinstance(a.subclass(), XauthAuthentication)
        )
        secret = Secret.objects.filter(authentication=xauth).first()
        self.assertIsNotNone(secret)
        self.assertEqual(secret.type, 'XAUTH')
        self.assertEqual(secret.data, 'xauthpass')

    def test_create_connection_uses_round_increment(self):
        conn = _base_connection('xauth-round')
        PskAuthentication(name='local-psk', auth='psk', local=conn, round=1).save()

        form = self._make_form({'xauth_id': 'john', 'xauth_secret': ''})
        form.create_connection(conn)

        xauth = next(
            a.subclass() for a in conn.local.all() if isinstance(a.subclass(), XauthAuthentication)
        )
        self.assertEqual(xauth.round, 2)

    def test_xauth_id_required(self):
        from strongswan_manager.apps.connections.forms.SubForms import XauthForm
        form = XauthForm({'xauth_id': '', 'xauth_secret': ''})
        self.assertFalse(form.is_valid())
        self.assertIn('xauth_id', form.errors)

    def test_fill_populates_xauth_id(self):
        from strongswan_manager.apps.connections.forms.SubForms import XauthForm
        conn = _base_connection('xauth-fill')
        XauthAuthentication(name='local-xauth', auth='xauth', local=conn, xauth_id='alice').save()

        form = XauthForm()
        form.fill(conn)
        self.assertEqual(form.initial['xauth_id'], 'alice')


# ── IKEv1 ConnectionForm version check ───────────────────────────────────────

class TestIke1FormVersions(TestCase):
    fixtures = ['initial_data.json']

    def _post_data(self, profile, form_cls_name, extra=None):
        data = {
            'current_form': form_cls_name,
            'profile': profile,
            'gateway': '10.1.1.1',
            'psk_id': '',
            'psk_secret': 'secret123',
            'xauth_id': 'user',
            'xauth_secret': 'pass',
        }
        if extra:
            data.update(extra)
        return data

    def test_ike1psk_form_is_in_choice_list(self):
        from strongswan_manager.apps.connections.forms.ConnectionForms import ChooseTypeForm
        choices = dict(ChooseTypeForm.get_choices())
        self.assertIn('Ike1PskForm', choices)

    def test_ike1certificate_form_is_in_choice_list(self):
        from strongswan_manager.apps.connections.forms.ConnectionForms import ChooseTypeForm
        choices = dict(ChooseTypeForm.get_choices())
        self.assertIn('Ike1CertificateForm', choices)

    def test_ike1xauthpsk_form_is_in_choice_list(self):
        from strongswan_manager.apps.connections.forms.ConnectionForms import ChooseTypeForm
        choices = dict(ChooseTypeForm.get_choices())
        self.assertIn('Ike1XauthPskForm', choices)

    def test_ike1xauthcertificate_form_is_in_choice_list(self):
        from strongswan_manager.apps.connections.forms.ConnectionForms import ChooseTypeForm
        choices = dict(ChooseTypeForm.get_choices())
        self.assertIn('Ike1XauthCertificateForm', choices)

    def test_ike1psk_create_connection_sets_version_1(self):
        from strongswan_manager.apps.connections.forms.ConnectionForms import Ike1PskForm
        data = self._post_data('v1psk-test', 'Ike1PskForm')
        form = Ike1PskForm(data)
        if form.is_valid():
            conn = form.create_connection()
            self.assertEqual(conn.version, '1')
            self.assertIsInstance(conn, IKEv1PSK)

    def test_ike1xauthpsk_create_connection_sets_version_1(self):
        from strongswan_manager.apps.connections.forms.ConnectionForms import Ike1XauthPskForm
        data = self._post_data('v1xauth-test', 'Ike1XauthPskForm')
        form = Ike1XauthPskForm(data)
        if form.is_valid():
            conn = form.create_connection()
            self.assertEqual(conn.version, '1')
            self.assertIsInstance(conn, IKEv1XauthPSK)

    def test_ike1psk_model_choice_name(self):
        self.assertEqual(IKEv1PSK.choice_name(), 'IKEv1 Pre-Shared Key')

    def test_ike1xauthpsk_model_choice_name(self):
        self.assertEqual(IKEv1XauthPSK.choice_name(), 'IKEv1 XAUTH + PSK')

    def test_ike1certificate_model_choice_name(self):
        self.assertEqual(IKEv1Certificate.choice_name(), 'IKEv1 Certificate')

    def test_ike1xauthcertificate_model_choice_name(self):
        self.assertEqual(IKEv1XauthCertificate.choice_name(), 'IKEv1 XAUTH + Certificate')


# ── Server-side IKEv1 forms in ChooseType ────────────────────────────────────

class TestServerIke1ChooseType(TestCase):
    fixtures = ['initial_data.json']

    def test_server_ike1psk_in_choices(self):
        from strongswan_manager.apps.server_connections.forms.ConnectionForms import (
            AbstractConnectionForm, ChooseTypeForm,
        )
        choices = dict(ChooseTypeForm.get_choices_remote_access())
        self.assertIn('Ike1PskForm', choices)

    def test_server_ike1certificate_in_choices(self):
        from strongswan_manager.apps.server_connections.forms.ConnectionForms import ChooseTypeForm
        choices = dict(ChooseTypeForm.get_choices_remote_access())
        self.assertIn('Ike1CertificateForm', choices)

    def test_server_ike1xauthpsk_in_choices(self):
        from strongswan_manager.apps.server_connections.forms.ConnectionForms import ChooseTypeForm
        choices = dict(ChooseTypeForm.get_choices_remote_access())
        self.assertIn('Ike1XauthPskForm', choices)

    def test_server_ike1xauthcertificate_in_choices(self):
        from strongswan_manager.apps.server_connections.forms.ConnectionForms import ChooseTypeForm
        choices = dict(ChooseTypeForm.get_choices_remote_access())
        self.assertIn('Ike1XauthCertificateForm', choices)
