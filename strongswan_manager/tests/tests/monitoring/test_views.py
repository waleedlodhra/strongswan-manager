"""
Tests for the monitoring HTTP views.
"""
import os

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

os.environ.setdefault("STRONGSWAN_DISABLE_MONITOR", "1")

User = get_user_model()


class TestDashboardView(TestCase):
    fixtures = ["initial_data.json"]

    def setUp(self):
        self.user = User.objects.create_user("monitor_user", password="testpass123")

    def test_dashboard_requires_login(self):
        url = reverse("monitoring:dashboard")
        response = self.client.get(url)
        self.assertRedirects(response, f"/login/?next={url}", fetch_redirect_response=False)

    def test_dashboard_accessible_when_logged_in(self):
        self.client.login(username="monitor_user", password="testpass123")
        response = self.client.get(reverse("monitoring:dashboard"))
        self.assertEqual(response.status_code, 200)

    def test_dashboard_uses_correct_template(self):
        self.client.login(username="monitor_user", password="testpass123")
        response = self.client.get(reverse("monitoring:dashboard"))
        self.assertTemplateUsed(response, "monitoring/dashboard.html")

    def test_dashboard_contains_sa_table(self):
        self.client.login(username="monitor_user", password="testpass123")
        response = self.client.get(reverse("monitoring:dashboard"))
        self.assertContains(response, "sa-table")
        self.assertContains(response, "ws/monitoring/")

    def test_dashboard_post_not_allowed(self):
        self.client.login(username="monitor_user", password="testpass123")
        response = self.client.post(reverse("monitoring:dashboard"))
        self.assertEqual(response.status_code, 405)
