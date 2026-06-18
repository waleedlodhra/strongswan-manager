"""
Django signals for the certificates app.
Syncs Authority saves/deletes to charon via SyncEngine.
"""
import logging

from django.db.models.signals import post_delete, post_save

logger = logging.getLogger(__name__)


def on_authority_saved(sender, instance, created, **kwargs):
    from strongswan_manager.services.sync_engine import SyncEngine
    SyncEngine().load_authority(instance)


def on_authority_deleted(sender, instance, **kwargs):
    from strongswan_manager.services.sync_engine import SyncEngine
    SyncEngine().unload_authority(instance.name)


def connect_signals():
    from strongswan_manager.apps.certificates.models import Authority

    post_save.connect(on_authority_saved, sender=Authority,
                      dispatch_uid="certificates.authority.sync.post_save")
    post_delete.connect(on_authority_deleted, sender=Authority,
                        dispatch_uid="certificates.authority.sync.post_delete")
    logger.debug("certificates sync signals registered")
