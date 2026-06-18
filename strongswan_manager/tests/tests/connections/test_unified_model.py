"""
Unit tests for Phase 1 unified data model.
Covers all new fields, new auth types, new connection types, and dict() serialization.
"""
import pytest
from django.test import TestCase

from strongswan_manager.apps.connections.models import (
    Connection, IKEv2Certificate, IKEv1PSK, IKEv1Certificate,
    IKEv1XauthPSK, IKEv1XauthCertificate,
    Child, Address, Proposal, Authentication,
    PskAuthentication, XauthAuthentication, EapAuthentication,
    EapTlsAuthentication,
)
from strongswan_manager.apps.connections.models.common import State


def make_connection(**kwargs):
    defaults = dict(profile='test-conn', version='2', connection_type='client')
    defaults.update(kwargs)
    conn = Connection(**defaults)
    conn.save()
    return conn


def add_child(connection, name='child1', mode='tunnel'):
    child = Child(name=name, mode=mode, connection=connection)
    child.save()
    return child


class TestConnectionNewFields(TestCase):
    def test_defaults_are_empty(self):
        conn = make_connection()
        self.assertEqual(conn.dpd_delay, '')
        self.assertEqual(conn.dpd_timeout, '')
        self.assertEqual(conn.rekey_time, '')
        self.assertEqual(conn.reauth_time, '')
        self.assertIsNone(conn.keyingtries)
        self.assertIsNone(conn.mobike)
        self.assertIsNone(conn.encap)
        self.assertIsNone(conn.aggressive)
        self.assertEqual(conn.if_id_in, '')
        self.assertEqual(conn.if_id_out, '')
        self.assertEqual(conn.ppk_id, '')
        self.assertIsNone(conn.ppk_required)
        self.assertEqual(conn.source_file, '')

    def test_connection_types(self):
        c1 = make_connection(profile='c1', connection_type='client')
        c2 = make_connection(profile='c2', connection_type='server')
        c3 = make_connection(profile='c3', connection_type='site_to_site')
        self.assertTrue(c1.is_client())
        self.assertTrue(c2.is_server())
        self.assertTrue(c2.is_remote_access())
        self.assertTrue(c3.is_site_to_site())

    def test_dict_includes_dpd(self):
        conn = make_connection(dpd_delay='30s', dpd_timeout='150s')
        d = conn.dict()
        ike_sa = d['test-conn']
        self.assertEqual(ike_sa['dpd_delay'], '30s')
        self.assertEqual(ike_sa['dpd_timeout'], '150s')

    def test_dict_includes_timers(self):
        conn = make_connection(
            rekey_time='4h', reauth_time='0s',
            over_time='10m', rand_time='5m', keyingtries=3
        )
        d = conn.dict()['test-conn']
        self.assertEqual(d['rekey_time'], '4h')
        self.assertEqual(d['keyingtries'], 3)

    def test_dict_includes_flags(self):
        conn = make_connection(
            mobike=True, encap=False, aggressive=True,
            fragmentation='yes', unique='replace'
        )
        d = conn.dict()['test-conn']
        self.assertEqual(d['mobike'], 'yes')
        self.assertEqual(d['encap'], 'no')
        self.assertEqual(d['aggressive'], 'yes')
        self.assertEqual(d['fragmentation'], 'yes')
        self.assertEqual(d['unique'], 'replace')

    def test_dict_includes_xfrm(self):
        conn = make_connection(if_id_in='10', if_id_out='10')
        d = conn.dict()['test-conn']
        self.assertEqual(d['if_id_in'], '10')
        self.assertEqual(d['if_id_out'], '10')

    def test_dict_includes_ppk(self):
        conn = make_connection(ppk_id='my-ppk', ppk_required=True)
        d = conn.dict()['test-conn']
        self.assertEqual(d['ppk_id'], 'my-ppk')
        self.assertEqual(d['ppk_required'], 'yes')

    def test_dict_skips_empty_optional_fields(self):
        conn = make_connection()
        d = conn.dict()['test-conn']
        self.assertNotIn('dpd_delay', d)
        self.assertNotIn('rekey_time', d)
        self.assertNotIn('mobike', d)
        self.assertNotIn('ppk_id', d)


class TestIKEv1ConnectionTypes(TestCase):
    def test_ikev1_psk_subclass(self):
        c = IKEv1PSK(profile='psk-conn', version='1', connection_type='client')
        c.save()
        self.assertEqual(c.choice_name(), "IKEv1 Pre-Shared Key")
        self.assertEqual(Connection.objects.get(pk=c.pk).subclass().get_typ(), 'IKEv1PSK')

    def test_ikev1_xauth_psk_subclass(self):
        c = IKEv1XauthPSK(profile='xauth-conn', version='1', connection_type='client')
        c.save()
        self.assertEqual(c.choice_name(), "IKEv1 XAUTH + PSK")

    def test_ikev1_certificate_subclass(self):
        c = IKEv1Certificate(profile='cert-conn', version='1', connection_type='site_to_site')
        c.save()
        self.assertEqual(c.choice_name(), "IKEv1 Certificate")


class TestChildSANewFields(TestCase):
    def setUp(self):
        self.conn = make_connection()

    def test_transport_mode(self):
        child = add_child(self.conn, mode='transport')
        d = child.dict()
        self.assertEqual(d['mode'], 'transport')

    def test_tunnel_mode_not_in_dict(self):
        child = add_child(self.conn, mode='tunnel')
        d = child.dict()
        self.assertNotIn('mode', d)

    def test_close_action(self):
        child = add_child(self.conn)
        child.close_action = 'restart'
        child.save()
        self.assertEqual(child.dict()['close_action'], 'restart')

    def test_dpd_action(self):
        child = add_child(self.conn)
        child.dpd_action = 'hold'
        child.save()
        self.assertEqual(child.dict()['dpd_action'], 'hold')

    def test_timers(self):
        child = add_child(self.conn)
        child.rekey_time = '1h'
        child.life_time = '2h'
        child.inactivity = '300s'
        child.save()
        d = child.dict()
        self.assertEqual(d['rekey_time'], '1h')
        self.assertEqual(d['life_time'], '2h')
        self.assertEqual(d['inactivity'], '300s')

    def test_marks(self):
        child = add_child(self.conn)
        child.mark_in = '0x42'
        child.mark_out = '0x42'
        child.save()
        d = child.dict()
        self.assertEqual(d['mark_in'], '0x42')
        self.assertEqual(d['mark_out'], '0x42')

    def test_hw_offload(self):
        child = add_child(self.conn)
        child.hw_offload = 'yes'
        child.save()
        self.assertEqual(child.dict()['hw_offload'], 'yes')

    def test_hw_offload_default_not_in_dict(self):
        child = add_child(self.conn)
        self.assertNotIn('hw_offload', child.dict())

    def test_copy_df(self):
        child = add_child(self.conn)
        child.copy_df = True
        child.save()
        self.assertEqual(child.dict()['copy_df'], 'yes')

    def test_updown(self):
        child = add_child(self.conn)
        child.updown = '/usr/lib/ipsec/updown'
        child.save()
        self.assertEqual(child.dict()['updown'], '/usr/lib/ipsec/updown')

    def test_ah_proposals(self):
        child = add_child(self.conn)
        Proposal.objects.create(ah_child=child, type='sha256')
        self.assertEqual(child.dict()['ah_proposals'], ['sha256'])


class TestNewAuthTypes(TestCase):
    def setUp(self):
        self.conn = make_connection()

    def test_psk_auth_dict(self):
        auth = PskAuthentication(
            local=self.conn, name='local', auth='psk',
            psk_id='10.0.0.1'
        )
        auth.save()
        d = auth.dict()
        self.assertEqual(d['local']['auth'], 'psk')
        self.assertEqual(d['local']['id'], '10.0.0.1')

    def test_psk_auth_no_id(self):
        auth = PskAuthentication(local=self.conn, name='local', auth='psk')
        auth.save()
        d = auth.dict()
        self.assertNotIn('id', d['local'])

    def test_xauth_auth_dict(self):
        auth = XauthAuthentication(
            local=self.conn, name='local', auth='xauth',
            xauth_id='vpnuser1'
        )
        auth.save()
        d = auth.dict()
        self.assertEqual(d['local']['xauth_id'], 'vpnuser1')


class TestStateEnum(TestCase):
    def test_all_states_available(self):
        states = [s.value for s in State]
        self.assertIn('DOWN', states)
        self.assertIn('CONNECTING', states)
        self.assertIn('ESTABLISHED', states)
        self.assertIn('LOADED', states)
        self.assertIn('UNLOADED', states)
