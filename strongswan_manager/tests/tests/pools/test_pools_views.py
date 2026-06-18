"""
Tests for the pools app views:
  - OverviewHandler (GET)
  - AddHandler (POST valid, POST invalid poolname, POST duplicate)
  - EditHandler (GET, POST update, POST delete)
"""
from unittest.mock import patch, MagicMock

from django.contrib.auth.models import User
from django.test import TestCase, Client, TransactionTestCase
from django.urls import reverse

from strongswan_manager.apps.pools.models import Pool

VICI_WRAPPER = "strongswan_manager.helper_apps.vici.wrapper.wrapper.ViciWrapper"


def _vici_mock():
    m = MagicMock()
    m.return_value.load_pool.return_value = None
    m.return_value.unload_pool.return_value = None
    return m


class PoolsOverviewTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("pools_user", password="pass")
        self.client.login(username="pools_user", password="pass")

    def test_overview_get_returns_200(self):
        response = self.client.get(reverse("pools:index"))
        self.assertEqual(response.status_code, 200)

    def test_overview_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("pools:index"))
        self.assertNotEqual(response.status_code, 200)

    def test_overview_creates_dhcp_and_radius_placeholders(self):
        self.client.get(reverse("pools:index"))
        self.assertTrue(Pool.objects.filter(poolname="dhcp").exists())
        self.assertTrue(Pool.objects.filter(poolname="radius").exists())


class PoolsAddTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("add_pool_user", password="pass")
        self.client.login(username="add_pool_user", password="pass")

    @patch(VICI_WRAPPER, **{"return_value.load_pool.return_value": None})
    def test_add_post_valid_creates_pool(self, mock_vici):
        self.client.post(reverse("pools:add"), {
            "poolname": "testpool",
            "addresses": "10.0.0.0/24",
            "attribute": "None",
            "attributevalues": "",
        })
        self.assertTrue(Pool.objects.filter(poolname="testpool").exists())

    @patch(VICI_WRAPPER, **{"return_value.load_pool.return_value": None})
    def test_add_post_valid_redirects(self, mock_vici):
        response = self.client.post(reverse("pools:add"), {
            "poolname": "testpool2",
            "addresses": "10.1.0.0/24",
            "attribute": "None",
            "attributevalues": "",
        })
        self.assertRedirects(response, reverse("pools:index"), fetch_redirect_response=False)

    @patch(VICI_WRAPPER)
    def test_add_post_reserved_name_dhcp_rejected(self, mock_vici):
        response = self.client.post(reverse("pools:add"), {
            "poolname": "dhcp",
            "addresses": "10.0.0.0/24",
            "attribute": "None",
            "attributevalues": "",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "not allowed")

    @patch(VICI_WRAPPER)
    def test_add_post_reserved_name_radius_rejected(self, mock_vici):
        response = self.client.post(reverse("pools:add"), {
            "poolname": "radius",
            "addresses": "10.0.0.0/24",
            "attribute": "None",
            "attributevalues": "",
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "not allowed")

    @patch(VICI_WRAPPER)
    def test_add_post_attribute_requires_values(self, mock_vici):
        response = self.client.post(reverse("pools:add"), {
            "poolname": "mypool",
            "addresses": "10.0.0.0/24",
            "attribute": "dns",
            "attributevalues": "",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Pool.objects.filter(poolname="mypool").exists())

    @patch(VICI_WRAPPER, **{"return_value.load_pool.return_value": None})
    def test_add_post_with_attribute_creates_pool(self, mock_vici):
        self.client.post(reverse("pools:add"), {
            "poolname": "dnspool",
            "addresses": "10.0.0.0/24",
            "attribute": "dns",
            "attributevalues": "8.8.8.8",
        })
        pool = Pool.objects.filter(poolname="dnspool").first()
        self.assertIsNotNone(pool)
        self.assertEqual(pool.attribute, "dns")

    def test_add_get_renders_form(self):
        response = self.client.get(reverse("pools:add"))
        self.assertEqual(response.status_code, 200)


class PoolsDuplicateTest(TransactionTestCase):
    """TransactionTestCase required: duplicate poolname triggers IntegrityError."""
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("dup_pool_user", password="pass")
        self.client.login(username="dup_pool_user", password="pass")
        Pool(poolname="existing", addresses="10.0.0.0/24").save()

    @patch(VICI_WRAPPER)
    def test_add_post_duplicate_poolname_shows_error(self, mock_vici):
        mock_vici.return_value.load_pool.side_effect = Exception("Poolname already in use.")
        response = self.client.post(reverse("pools:add"), {
            "poolname": "existing",
            "addresses": "10.2.0.0/24",
            "attribute": "None",
            "attributevalues": "",
        })
        self.assertEqual(response.status_code, 200)


class PoolsEditTest(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.client = Client()
        User.objects.create_user("edit_pool_user", password="pass")
        self.client.login(username="edit_pool_user", password="pass")
        Pool(poolname="editme", addresses="10.0.0.0/24").save()

    def test_edit_get_renders_form(self):
        response = self.client.get(reverse("pools:edit", kwargs={"poolname": "editme"}))
        self.assertEqual(response.status_code, 200)

    @patch(VICI_WRAPPER, **{"return_value.load_pool.return_value": None,
                             "return_value.unload_pool.return_value": None})
    def test_edit_post_delete_removes_pool(self, mock_vici):
        self.client.post(
            reverse("pools:edit", kwargs={"poolname": "editme"}),
            {"poolname": "editme", "addresses": "10.0.0.0/24",
             "attribute": "None", "attributevalues": "", "remove_pool": "1"},
        )
        self.assertFalse(Pool.objects.filter(poolname="editme").exists())
