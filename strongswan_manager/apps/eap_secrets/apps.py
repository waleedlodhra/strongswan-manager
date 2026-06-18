from django.apps import AppConfig


class EapSecretsConfig(AppConfig):
    name = "strongswan_manager.apps.eap_secrets"
    verbose_name = "Secrets"

    def ready(self):
        from .signals import connect_signals
        connect_signals()
