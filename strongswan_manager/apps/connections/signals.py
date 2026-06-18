"""
Django signals for the connections app.

GUI → StrongSwan synchronization:
  - post_save  on Connection: load into charon if enabled
  - post_delete on Connection: unload from charon
"""
import logging

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)


def _sync():
    from strongswan_manager.services.sync_engine import SyncEngine
    return SyncEngine()


# ── Connection signals ─────────────────────────────────────────────────────

def on_connection_saved(sender, instance, created, **kwargs):
    """Load or unload from charon whenever a Connection is saved."""
    from strongswan_manager.apps.connections.models import Connection
    if not isinstance(instance, Connection):
        return
    svc = _sync()
    if instance.enabled:
        svc.load_connection(instance.subclass())
    else:
        svc.unload_connection(instance.profile)


def on_connection_deleted(sender, instance, **kwargs):
    """Unload connection from charon on delete."""
    from strongswan_manager.apps.connections.models import Connection
    if not isinstance(instance, Connection):
        return
    _sync().unload_connection(instance.profile)


def connect_signals():
    """
    Register all connection signals.
    Called from AppConfig.ready() to avoid import-time circular dependencies.

    No sender= specified: signals fire for all models.  on_connection_saved /
    on_connection_deleted filter by isinstance(instance, Connection) so only
    Connection subclasses (IKEv2Certificate, IKEv1PSK, etc.) are handled.
    MTI subclass saves do NOT fire post_save with sender=Connection so we must
    leave sender open and filter manually.
    """
    post_save.connect(on_connection_saved,
                      dispatch_uid="connections.sync.post_save")
    post_delete.connect(on_connection_deleted,
                        dispatch_uid="connections.sync.post_delete")
    logger.debug("connections sync signals registered")
