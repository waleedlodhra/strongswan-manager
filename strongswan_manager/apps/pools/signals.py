"""
Django signals for the pools app.
Syncs Pool saves/deletes to charon via SyncEngine.
"""
import logging

from django.db.models.signals import post_delete, post_save

logger = logging.getLogger(__name__)


def on_pool_saved(sender, instance, created, **kwargs):
    from strongswan_manager.services.sync_engine import SyncEngine
    SyncEngine().load_pool(instance)


def on_pool_deleted(sender, instance, **kwargs):
    from strongswan_manager.services.sync_engine import SyncEngine
    SyncEngine().unload_pool(instance.poolname)


def connect_signals():
    from strongswan_manager.apps.pools.models import Pool

    post_save.connect(on_pool_saved, sender=Pool,
                      dispatch_uid="pools.sync.post_save")
    post_delete.connect(on_pool_deleted, sender=Pool,
                        dispatch_uid="pools.sync.post_delete")
    logger.debug("pools sync signals registered")
