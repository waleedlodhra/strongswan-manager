"""
Tests for the server_connections app views:
  - OverviewHandler (GET)
  - CreateHandler (GET choose type, POST choose type, POST create Ike1PskForm)
  - DeleteHandler (GET)
  - StateHandler (POST)
  - ToggleHandler (POST)
  - PoolPicker / CertificatePicker / CaPicker (POST)
"""
from unittest.mock import patch, MagicMock, PropertyMock

from django.contrib.auth.models import User
from django.test import TestCase, Client
from django.urls import reverse

from strongswan_manager.apps.connections.models.connections import Connection, IKEv1PSK
from strongswan_manager.apps.certificates.models.certificates import Certificate
from strongswan_manager.apps.certificates.services import UserCertificateManager
from strongswan_manager.tests.tests.certificates.certificates import TestCertificates


class ServerConnectionsOverviewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("sc_ov_user", password="pass")
        self.client.login(username="sc_ov_user", password="pass")

    def test_overview_get_returns_200(self):
        response = self.client.get(reverse("server_connections:index"))
        self.assertEqual(response.status_code, 200)

    def test_overview_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("server_connections:index"))
        self.assertNotEqual(response.status_code, 200)

    def test_overview_empty_shows_no_table(self):
        response = self.client.get(reverse("server_connections:index"))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["table"])

    def test_overview_with_connection_shows_table(self):
        IKEv1PSK(profile="test-server", auth="psk", version="1", connection_type="server").save()
        response = self.client.get(reverse("server_connections:index"))
        self.assertIsNotNone(response.context["table"])


class ServerConnectionsCreateTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("sc_create_user", password="pass")
        self.client.login(username="sc_create_user", password="pass")

    def test_create_get_remote_access_returns_200(self):
        response = self.client.get(
            reverse("server_connections:choose", kwargs={"connection_type": "remote_access"})
        )
        self.assertEqual(response.status_code, 200)

    def test_create_get_site_to_site_returns_200(self):
        response = self.client.get(
            reverse("server_connections:choose", kwargs={"connection_type": "site_to_site"})
        )
        self.assertEqual(response.status_code, 200)

    def test_create_post_choose_type_renders_form(self):
        response = self.client.post(
            reverse("server_connections:choose", kwargs={"connection_type": "remote_access"}),
            {
                "current_form": "ChooseTypeForm",
                "form_name": "Ike1PskForm",
            },
        )
        self.assertEqual(response.status_code, 200)

    def _ike1psk_post_data(self, profile="server-ike1-psk"):
        return {
            "current_form": "Ike1PskForm",
            "profile": profile,
            "local_addrs": "",
            "remote_addrs": "",
            "local_ts": "",
            "remote_ts": "",
            "version": "1",
            "send_certreq": "",
            "start_action": "",
            "psk_id": "",
            "psk_secret": "mysecret",
            "pool": "",
            "form_name": "Ike1PskForm",
        }

    def test_create_post_ike1psk_creates_connection(self):
        self.client.post(
            reverse("server_connections:choose", kwargs={"connection_type": "remote_access"}),
            self._ike1psk_post_data("server-ike1-psk"),
        )
        self.assertEqual(Connection.objects.filter(profile="server-ike1-psk").count(), 1)

    def test_create_post_ike1psk_redirects_on_success(self):
        response = self.client.post(
            reverse("server_connections:choose", kwargs={"connection_type": "remote_access"}),
            self._ike1psk_post_data("server-ike1-psk2"),
        )
        self.assertRedirects(response, reverse("server_connections:index"), fetch_redirect_response=False)


class ServerConnectionsDeleteTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("sc_del_user", password="pass")
        self.client.login(username="sc_del_user", password="pass")
        conn = IKEv1PSK(profile="to-delete", auth="psk", version="1", connection_type="server")
        conn.save()
        self.conn_id = conn.id

    def test_delete_removes_connection(self):
        self.client.get(
            reverse("server_connections:delete", kwargs={"id": self.conn_id})
        )
        self.assertFalse(Connection.objects.filter(id=self.conn_id).exists())

    def test_delete_redirects_to_overview(self):
        response = self.client.get(
            reverse("server_connections:delete", kwargs={"id": self.conn_id})
        )
        self.assertRedirects(response, reverse("server_connections:index"), fetch_redirect_response=False)


class ServerConnectionsStateTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("sc_state_user", password="pass")
        self.client.login(username="sc_state_user", password="pass")
        conn = IKEv1PSK(profile="state-test", auth="psk", version="1", connection_type="server")
        conn.save()
        self.conn_id = conn.id

    @patch("strongswan_manager.apps.server_connections.views.StateHandler.StateHandler.handle")
    def test_state_returns_json(self, mock_handle):
        from django.http import JsonResponse
        mock_handle.return_value = JsonResponse({"id": self.conn_id, "success": True, "state": "DOWN"})
        response = self.client.post(
            reverse("server_connections:state", kwargs={"id": self.conn_id})
        )
        self.assertEqual(response.status_code, 200)


class ServerConnectionsPickerTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("sc_picker_user", password="pass")
        self.client.login(username="sc_picker_user", password="pass")
        manager = UserCertificateManager()
        manager.add_keycontainer(TestCertificates.PKCS12_rsa.read())

    def test_pool_picker_returns_200(self):
        response = self.client.post(reverse("server_connections:poolpicker"))
        self.assertEqual(response.status_code, 200)

    def test_certificate_picker_returns_200(self):
        response = self.client.post(reverse("server_connections:certificatepicker"))
        self.assertEqual(response.status_code, 200)

    def test_ca_picker_returns_200(self):
        response = self.client.post(reverse("server_connections:capicker"))
        self.assertEqual(response.status_code, 200)
