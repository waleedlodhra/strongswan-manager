"""
Django signals for the eap_secrets app.
Syncs Secret saves/deletes to charon via SyncEngine.
"""
import logging

from django.db.models.signals import post_delete, post_save

logger = logging.getLogger(__name__)


def on_secret_saved(sender, instance, created, **kwargs):
    from strongswan_manager.services.sync_engine import SyncEngine
    SyncEngine().load_secret(instance)


def on_secret_deleted(sender, instance, **kwargs):
    # Shared secrets can't be individually unloaded by username in VICI;
    # reload_all will re-push remaining secrets on next full reload.
    logger.debug("Secret %r deleted — will be absent on next reload_all", instance.username)


def connect_signals():
    from strongswan_manager.apps.eap_secrets.models import Secret

    post_save.connect(on_secret_saved, sender=Secret,
                      dispatch_uid="eap_secrets.sync.post_save")
    post_delete.connect(on_secret_deleted, sender=Secret,
                        dispatch_uid="eap_secrets.sync.post_delete")
    logger.debug("eap_secrets sync signals registered")
