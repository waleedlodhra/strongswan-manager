import logging
import os

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class MonitoringConfig(AppConfig):
    name = "strongswan_manager.apps.monitoring"
    verbose_name = "Monitoring"

    _sa_monitor = None  # singleton, accessible as MonitoringConfig._sa_monitor

    def ready(self):
        # Skip in test runs or when explicitly suppressed (e.g. manage.py commands
        # that don't need a live monitor thread).
        if os.environ.get("STRONGSWAN_DISABLE_MONITOR"):
            logger.info("SaMonitor disabled via STRONGSWAN_DISABLE_MONITOR")
            return

        from strongswan_manager.apps.monitoring.consumers import broadcast_sa_event
        from strongswan_manager.services.vici_events import SaMonitor

        monitor = SaMonitor()
        for event in ("ike-updown", "ike-rekey", "child-updown", "child-rekey"):
            monitor.add_listener(event, broadcast_sa_event)
        monitor.start()

        MonitoringConfig._sa_monitor = monitor
        logger.info("SaMonitor started from MonitoringConfig.ready()")
