"""
Extended tests for the connections app:
  - Client connections overview (GET)
  - IKEv1 PSK create/update via HTTP views
  - IKEv1 XAUTH PSK create via HTTP views
  - StateHandler (JSON response shape)
  - ToggleHandler (JSON response)
  - LogHandler (POST)
  - PskAuthentication.dict() / eap_id
  - XauthAuthentication.dict() / eap_id
  - EapRadiusAuthentication.dict()
  - Connection.subclass() polymorphism
"""
from collections import OrderedDict
from unittest.mock import patch, MagicMock

from django.contrib.auth.models import User
from django.test import TestCase, Client
from django.urls import reverse

from strongswan_manager.apps.connections.models.connections import (
    Connection, IKEv1PSK, IKEv1XauthPSK,
)
from strongswan_manager.apps.connections.models.authentication import (
    PskAuthentication, XauthAuthentication, EapRadiusAuthentication,
)


# ── Auth model unit tests ─────────────────────────────────────────────────────

class PskAuthenticationTest(TestCase):
    def setUp(self):
        conn = IKEv1PSK(profile="psk-auth-test", auth="psk", version="1")
        conn.save()
        self.conn = conn

    def test_eap_id_returns_psk_id(self):
        auth = PskAuthentication(name="local-psk", auth="psk", local=self.conn, psk_id="my-identity")
        self.assertEqual(auth.eap_id, "my-identity")

    def test_eap_id_empty_when_blank(self):
        auth = PskAuthentication(name="local-psk", auth="psk", local=self.conn, psk_id="")
        self.assertEqual(auth.eap_id, "")

    def test_dict_without_psk_id(self):
        auth = PskAuthentication(name="local-psk", auth="psk", local=self.conn, psk_id="")
        auth.save()
        d = auth.dict()
        self.assertIsInstance(d, dict)
        self.assertNotIn("id", d.get("local-psk", {}))

    def test_dict_with_psk_id(self):
        auth = PskAuthentication(name="local-psk", auth="psk", local=self.conn, psk_id="vpnclient")
        auth.save()
        d = auth.dict()
        self.assertEqual(d["local-psk"]["id"], "vpnclient")

    def test_dict_auth_key_is_psk(self):
        auth = PskAuthentication(name="local-psk", auth="psk", local=self.conn, psk_id="")
        auth.save()
        d = auth.dict()
        self.assertEqual(d["local-psk"]["auth"], "psk")


class XauthAuthenticationTest(TestCase):
    def setUp(self):
        conn = IKEv1XauthPSK(profile="xauth-auth-test", auth="psk", version="1")
        conn.save()
        self.conn = conn

    def test_eap_id_returns_xauth_id(self):
        auth = XauthAuthentication(name="local-xauth", auth="xauth", local=self.conn, xauth_id="jdoe")
        self.assertEqual(auth.eap_id, "jdoe")

    def test_eap_id_empty_when_blank(self):
        auth = XauthAuthentication(name="local-xauth", auth="xauth", local=self.conn, xauth_id="")
        self.assertEqual(auth.eap_id, "")

    def test_dict_without_xauth_id(self):
        auth = XauthAuthentication(name="local-xauth", auth="xauth", local=self.conn, xauth_id="")
        auth.save()
        d = auth.dict()
        self.assertNotIn("xauth_id", d.get("local-xauth", {}))

    def test_dict_with_xauth_id(self):
        auth = XauthAuthentication(name="local-xauth", auth="xauth", local=self.conn, xauth_id="jdoe")
        auth.save()
        d = auth.dict()
        self.assertEqual(d["local-xauth"]["xauth_id"], "jdoe")

    def test_dict_auth_key_is_xauth(self):
        auth = XauthAuthentication(name="local-xauth", auth="xauth", local=self.conn, xauth_id="")
        auth.save()
        d = auth.dict()
        self.assertEqual(d["local-xauth"]["auth"], "xauth")


class EapRadiusAuthenticationTest(TestCase):
    def setUp(self):
        from strongswan_manager.apps.connections.models.connections import IKEv2EAP
        conn = IKEv2EAP(profile="eap-radius-test", auth="eap", version="2")
        conn.save()
        self.conn = conn

    def test_dict_without_eap_id(self):
        auth = EapRadiusAuthentication(name="remote-eap", auth="eap-radius", remote=self.conn, eap_id="")
        auth.save()
        d = auth.dict()
        self.assertNotIn("eap_id", d.get("remote-eap", {}))

    def test_dict_with_eap_id(self):
        auth = EapRadiusAuthentication(name="remote-eap", auth="eap-radius", remote=self.conn, eap_id="radius-id")
        auth.save()
        d = auth.dict()
        self.assertEqual(d["remote-eap"]["eap_id"], "radius-id")


# ── Connection model tests ────────────────────────────────────────────────────

class ConnectionSubclassTest(TestCase):
    def test_ike1psk_subclass_returns_ike1psk(self):
        conn = IKEv1PSK(profile="subclass-test", auth="psk", version="1")
        conn.save()
        fetched = Connection.objects.get(profile="subclass-test").subclass()
        self.assertIsInstance(fetched, IKEv1PSK)

    def test_ike1xauthpsk_subclass_returns_ike1xauthpsk(self):
        conn = IKEv1XauthPSK(profile="xauth-subclass-test", auth="psk", version="1")
        conn.save()
        fetched = Connection.objects.get(profile="xauth-subclass-test").subclass()
        self.assertIsInstance(fetched, IKEv1XauthPSK)


# ── Connection view tests ─────────────────────────────────────────────────────

class ConnectionsOverviewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("conn_ov_user", password="pass")
        self.client.login(username="conn_ov_user", password="pass")

    def test_overview_get_returns_200(self):
        response = self.client.get(reverse("connections:index"))
        self.assertEqual(response.status_code, 200)

    def test_overview_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("connections:index"))
        self.assertNotEqual(response.status_code, 200)

    def test_overview_empty_shows_no_table(self):
        response = self.client.get(reverse("connections:index"))
        self.assertIsNone(response.context["table"])

    def test_overview_with_connection_shows_table(self):
        IKEv1PSK(profile="cli-overview", auth="psk", version="1").save()
        response = self.client.get(reverse("connections:index"))
        self.assertIsNotNone(response.context["table"])


class ConnectionsIke1PskViewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("ike1psk_user", password="pass")
        self.client.login(username="ike1psk_user", password="pass")

    def _post_data(self, profile="cli-ike1-psk"):
        return {
            "current_form": "Ike1PskForm",
            "profile": profile,
            "gateway": "10.0.0.1",
            "psk_id": "",
            "psk_secret": "mysecret",
            "form_name": "Ike1PskForm",
        }

    def test_choose_type_post_renders_ike1psk_form(self):
        response = self.client.post(
            reverse("connections:choose"),
            {"current_form": "ChooseTypeForm", "typ": "Ike1PskForm", "form_name": "Ike1PskForm"},
        )
        self.assertEqual(response.status_code, 200)

    def test_ike1psk_create_saves_connection(self):
        self.client.post(reverse("connections:choose"), self._post_data("cli-ike1-psk"))
        self.assertEqual(Connection.objects.filter(profile="cli-ike1-psk").count(), 1)

    def test_ike1psk_create_sets_version_1(self):
        self.client.post(reverse("connections:choose"), self._post_data("cli-ike1-psk-v1"))
        conn = Connection.objects.get(profile="cli-ike1-psk-v1")
        self.assertEqual(conn.version, "1")

    def test_ike1psk_create_redirects(self):
        response = self.client.post(reverse("connections:choose"), self._post_data("cli-ike1-redir"))
        self.assertRedirects(response, reverse("connections:index"), fetch_redirect_response=False)

    def test_ike1psk_update_changes_profile(self):
        self.client.post(reverse("connections:choose"), self._post_data("cli-ike1-upd"))
        conn = Connection.objects.get(profile="cli-ike1-upd")

        update_data = self._post_data("cli-ike1-renamed")
        update_data["wizard_step"] = "configure"
        self.client.post(reverse("connections:update", kwargs={"id": conn.id}), update_data)

        conn.refresh_from_db()
        self.assertEqual(conn.profile, "cli-ike1-renamed")


class ConnectionsStateViewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("state_user", password="pass")
        self.client.login(username="state_user", password="pass")
        conn = IKEv1PSK(profile="state-view", auth="psk", version="1")
        conn.save()
        self.conn = conn

    @patch("strongswan_manager.apps.connections.views.StateHandler.StateHandler.handle")
    def test_state_returns_json_200(self, mock_handle):
        from django.http import JsonResponse
        mock_handle.return_value = JsonResponse({"id": self.conn.id, "success": True, "state": "DOWN"})
        response = self.client.post(
            reverse("connections:state", kwargs={"id": self.conn.id})
        )
        self.assertEqual(response.status_code, 200)


class ConnectionsLogViewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("log_user", password="pass")
        self.client.login(username="log_user", password="pass")

    @patch("strongswan_manager.apps.connections.views.LogHandler.LogHandler.handle")
    def test_log_returns_200(self, mock_handle):
        from django.http import JsonResponse
        mock_handle.return_value = JsonResponse({"log": []})
        response = self.client.post(reverse("connections:log"), {"id": "1"})
        self.assertEqual(response.status_code, 200)


class ConnectionsToggleViewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("toggle_user", password="pass")
        self.client.login(username="toggle_user", password="pass")
        conn = IKEv1PSK(profile="toggle-view", auth="psk", version="1")
        conn.save()
        self.conn = conn

    @patch("strongswan_manager.apps.connections.views.ToggleHandler.ToggleHandler.handle")
    def test_toggle_returns_json(self, mock_handle):
        from django.http import JsonResponse
        mock_handle.return_value = JsonResponse({"id": str(self.conn.id), "success": True})
        response = self.client.post(reverse("connections:toggle"), {"id": str(self.conn.id)})
        self.assertEqual(response.status_code, 200)


class ConnectionsDeleteViewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("del_conn_user", password="pass")
        self.client.login(username="del_conn_user", password="pass")
        conn = IKEv1PSK(profile="to-delete-cli", auth="psk", version="1")
        conn.save()
        self.conn_id = conn.id

    def test_delete_removes_connection(self):
        self.client.get(
            reverse("connections:delete", kwargs={"id": self.conn_id})
        )
        self.assertFalse(Connection.objects.filter(id=self.conn_id).exists())

    def test_delete_redirects_to_overview(self):
        response = self.client.get(
            reverse("connections:delete", kwargs={"id": self.conn_id})
        )
        self.assertRedirects(response, reverse("connections:index"), fetch_redirect_response=False)
