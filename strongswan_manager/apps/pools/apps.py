from django.apps import AppConfig


class PoolsConfig(AppConfig):
    name = "strongswan_manager.apps.pools"
    verbose_name = "Address Pools"

    def ready(self):
        from .signals import connect_signals
        connect_signals()
