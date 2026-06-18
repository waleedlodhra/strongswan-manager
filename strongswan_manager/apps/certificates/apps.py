from django.apps import AppConfig


class CertificatesConfig(AppConfig):
    name = "strongswan_manager.apps.certificates"
    verbose_name = "Certificates"

    def ready(self):
        from .signals import connect_signals
        connect_signals()
