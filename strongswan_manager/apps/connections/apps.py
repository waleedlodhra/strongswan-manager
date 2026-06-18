from django.apps import AppConfig


class ConnectionsConfig(AppConfig):
    name = "strongswan_manager.apps.connections"
    verbose_name = "Connections"

    def ready(self):
        from .signals import connect_signals
        connect_signals()
