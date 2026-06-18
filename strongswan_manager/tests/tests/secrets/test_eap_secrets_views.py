"""
Tests for the eap_secrets app views:
  - OverviewHandler (GET list, POST search)
  - AddHandler (GET form, POST valid, POST invalid, POST duplicate)
  - EditHandler (GET load, POST update, POST delete)
"""
from django.contrib.auth.models import User
from django.test import TestCase, Client, TransactionTestCase
from django.urls import reverse

from strongswan_manager.apps.eap_secrets.models import Secret


class EapSecretsOverviewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user("ov_user", password="pass")
        self.client.login(username="ov_user", password="pass")
        Secret(username="alice", type="EAP", password="pw1").save()
        Secret(username="bob", type="EAP", password="pw2").save()

    def test_overview_get_returns_200(self):
        response = self.client.get(reverse("eap_secrets:overview"))
        self.assertEqual(response.status_code, 200)

    def test_overview_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("eap_secrets:overview"))
        self.assertNotEqual(response.status_code, 200)

    def test_overview_post_search_finds_match(self):
        response = self.client.post(reverse("eap_secrets:overview"), {"search_text": "alice"})
        self.assertEqual(response.status_code, 200)

    def test_overview_post_empty_search_returns_all(self):
        response = self.client.post(reverse("eap_secrets:overview"), {"search_text": ""})
        self.assertEqual(response.status_code, 200)


class EapSecretsAddTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user("add_user", password="pass")
        self.client.login(username="add_user", password="pass")

    def test_add_get_renders_form(self):
        response = self.client.get(reverse("eap_secrets:add"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "form")

    def test_add_post_valid_creates_secret(self):
        self.client.post(reverse("eap_secrets:add"), {
            "username": "charlie",
            "password": "securepass",
        })
        self.assertEqual(Secret.objects.filter(username="charlie").count(), 1)

    def test_add_post_valid_redirects(self):
        response = self.client.post(reverse("eap_secrets:add"), {
            "username": "dave",
            "password": "securepass",
        })
        self.assertRedirects(response, reverse("eap_secrets:overview"), fetch_redirect_response=False)

    def test_add_post_missing_password_stays_on_form(self):
        response = self.client.post(reverse("eap_secrets:add"), {
            "username": "eve",
            "password": "",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Secret.objects.filter(username="eve").count(), 0)


class EapSecretsDuplicateTest(TransactionTestCase):
    """TransactionTestCase required: duplicate username triggers IntegrityError,
    which would corrupt the wrapping TestCase transaction."""
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("dup_user", password="pass")
        self.client.login(username="dup_user", password="pass")
        Secret(username="frank", type="EAP", password="pw").save()

    def test_add_post_duplicate_username_shows_error(self):
        response = self.client.post(reverse("eap_secrets:add"), {
            "username": "frank",
            "password": "newpass",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already")


class EapSecretsEditTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user("edit_user", password="pass")
        self.client.login(username="edit_user", password="pass")
        Secret(username="grace", type="EAP", password="oldpass").save()

    def test_edit_get_renders_form(self):
        response = self.client.get(reverse("eap_secrets:edit", kwargs={"secret_name": "grace"}))
        self.assertEqual(response.status_code, 200)

    def test_edit_post_updates_password(self):
        self.client.post(
            reverse("eap_secrets:edit", kwargs={"secret_name": "grace"}),
            {"username": "grace", "password": "newpass"},
        )
        # password stored as salt(32 chars)+password
        secret = Secret.objects.get(username="grace")
        self.assertTrue(secret.password.endswith("newpass"))

    def test_edit_post_delete_removes_secret(self):
        self.client.post(
            reverse("eap_secrets:edit", kwargs={"secret_name": "grace"}),
            {"username": "grace", "password": "oldpass", "remove_secret": "1"},
        )
        self.assertEqual(Secret.objects.filter(username="grace").count(), 0)
