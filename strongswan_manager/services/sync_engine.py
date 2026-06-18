"""
SyncEngine — two-way synchronization between the Django DB and charon.

GUI → StrongSwan:
  Call load_connection(), load_secret(), etc. whenever a model is saved
  or deleted.  Wraps ViciService calls with graceful ViciUnavailable handling
  so a save never crashes even when charon is down.

StrongSwan → GUI:
  handle_file_changed(path) is called by the file watcher when a config file
  is modified on disk.  It re-runs the import engine for that file so the DB
  stays in sync with what's on disk.

reload_all():
  Unload everything from charon then re-load the full DB state. Used on
  startup and after bulk operations (e.g. after a full import).
"""
import logging
import os
import re

from strongswan_manager.services.exceptions import ViciUnavailable
from strongswan_manager.services.vici_service import ViciService

logger = logging.getLogger(__name__)


class SyncEngine:
    """
    Central coordinator for DB ↔ charon synchronization.

    Uses a singleton ViciService so the socket is shared across calls.
    All VICI operations fail gracefully when charon is unreachable — the
    in-DB state is always authoritative; the VICI state is best-effort.
    """

    def __init__(self, socket_path: str | None = None):
        self._socket_path = socket_path

    @property
    def _vici(self) -> ViciService:
        return ViciService.get_instance(
            *(self._socket_path,) if self._socket_path else ()
        )

    # ─── GUI → StrongSwan ─────────────────────────────────────────────────────

    def load_connection(self, connection) -> bool:
        """
        Load a Connection into charon. Returns True on success.
        Does nothing if connection.enabled is False.
        """
        if not connection.enabled:
            return False
        try:
            conn_dict = connection.dict()
            self._vici.load_connection(conn_dict)
            logger.info("Loaded connection %r into charon", connection.profile)
            return True
        except ViciUnavailable:
            logger.warning("charon unavailable — connection %r not loaded", connection.profile)
            return False
        except Exception as exc:
            logger.error("Failed to load connection %r: %s", connection.profile, exc)
            return False

    def unload_connection(self, profile: str) -> bool:
        """Unload a connection from charon by profile name."""
        try:
            self._vici.unload_connection(profile)
            logger.info("Unloaded connection %r from charon", profile)
            return True
        except ViciUnavailable:
            logger.warning("charon unavailable — connection %r not unloaded", profile)
            return False
        except Exception as exc:
            logger.error("Failed to unload connection %r: %s", profile, exc)
            return False

    def load_secret(self, secret) -> bool:
        """Load a global Secret into charon."""
        try:
            self._vici.load_shared(secret.dict())
            logger.info("Loaded secret %r into charon", secret.username)
            return True
        except ViciUnavailable:
            logger.warning("charon unavailable — secret not loaded")
            return False
        except Exception as exc:
            logger.error("Failed to load secret %r: %s", secret.username, exc)
            return False

    def load_authority(self, authority) -> bool:
        """Load a CA Authority configuration into charon."""
        try:
            self._vici.load_authority(authority.dict())
            logger.info("Loaded authority %r into charon", authority.name)
            return True
        except ViciUnavailable:
            logger.warning("charon unavailable — authority %r not loaded", authority.name)
            return False
        except Exception as exc:
            logger.error("Failed to load authority %r: %s", authority.name, exc)
            return False

    def unload_authority(self, name: str) -> bool:
        """Unload a CA Authority from charon."""
        try:
            self._vici.unload_authority(name)
            logger.info("Unloaded authority %r from charon", name)
            return True
        except ViciUnavailable:
            logger.warning("charon unavailable — authority %r not unloaded", name)
            return False
        except Exception as exc:
            logger.error("Failed to unload authority %r: %s", name, exc)
            return False

    def load_pool(self, pool) -> bool:
        """Load an IP address pool into charon."""
        try:
            self._vici.load_pool(pool.dict())
            logger.info("Loaded pool %r into charon", pool.poolname)
            return True
        except ViciUnavailable:
            logger.warning("charon unavailable — pool %r not loaded", pool.poolname)
            return False
        except Exception as exc:
            logger.error("Failed to load pool %r: %s", pool.poolname, exc)
            return False

    def unload_pool(self, poolname: str) -> bool:
        """Unload an IP address pool from charon."""
        try:
            self._vici.unload_pool(poolname)
            logger.info("Unloaded pool %r from charon", poolname)
            return True
        except ViciUnavailable:
            logger.warning("charon unavailable — pool %r not unloaded", poolname)
            return False
        except Exception as exc:
            logger.error("Failed to unload pool %r: %s", poolname, exc)
            return False

    # ─── Full reload ──────────────────────────────────────────────────────────

    def reload_all(self) -> dict:
        """
        Clear all charon credentials then push the full DB state.

        Order: clear_creds → load certs/keys → load authorities →
               load connections → load pools → load secrets.

        Returns a summary dict with counts and any errors.
        """
        from strongswan_manager.apps.connections.models import Connection
        from strongswan_manager.apps.certificates.models import Authority
        from strongswan_manager.apps.eap_secrets.models import Secret
        from strongswan_manager.apps.pools.models import Pool

        summary = {
            "connections": 0, "secrets": 0, "pools": 0,
            "authorities": 0, "errors": [],
        }

        try:
            self._vici.clear_creds()
        except ViciUnavailable:
            logger.warning("charon unavailable during reload_all")
            summary["errors"].append("charon unavailable")
            return summary

        for conn in Connection.objects.filter(enabled=True):
            sub = conn.subclass()
            if self.load_connection(sub):
                summary["connections"] += 1

        for secret in Secret.objects.all():
            if self.load_secret(secret):
                summary["secrets"] += 1

        for auth in Authority.objects.all():
            if self.load_authority(auth):
                summary["authorities"] += 1

        for pool in Pool.objects.all():
            if self.load_pool(pool):
                summary["pools"] += 1

        logger.info(
            "reload_all: %d connections, %d secrets, %d authorities, %d pools",
            summary["connections"], summary["secrets"],
            summary["authorities"], summary["pools"],
        )
        return summary

    # ─── StrongSwan → GUI ────────────────────────────────────────────────────

    def handle_file_changed(self, path: str) -> int:
        """
        Re-import a config file that changed on disk.

        Only imports NEW connections/secrets (idempotent engine skips existing).
        For deletions from the file, marks connections whose source_file matches
        but whose profile is no longer in the file as disabled.

        Returns the number of new objects created.
        """
        from strongswan_manager.services.importers import (
            ConfigImportEngine, IpsecConfParser, IpsecSecretsParser,
            SwanctlConfParser,
        )
        from strongswan_manager.apps.connections.models import Connection

        if not os.path.exists(path):
            self._handle_file_deleted(path)
            return 0

        created = 0

        try:
            fmt = self._detect_config_format(path)
            if fmt == "ipsec_conf":
                engine = ConfigImportEngine(
                    ipsec_conf=path,
                    ipsec_secrets="/nonexistent",
                    swanctl_conf="/nonexistent",
                )
                result = engine.import_all()
                created += result.connections_created + result.secrets_created

            elif fmt == "ipsec_secrets":
                engine = ConfigImportEngine(
                    ipsec_conf="/nonexistent",
                    ipsec_secrets=path,
                    swanctl_conf="/nonexistent",
                )
                result = engine.import_all()
                created += result.secrets_created

            elif fmt == "swanctl":
                engine = ConfigImportEngine(
                    ipsec_conf="/nonexistent",
                    ipsec_secrets="/nonexistent",
                    swanctl_conf=path,
                )
                result = engine.import_all()
                created += result.connections_created + result.secrets_created

            # Reload any newly-imported connections
            if created > 0:
                for conn in Connection.objects.filter(source_file=path, enabled=True):
                    self.load_connection(conn.subclass())

        except Exception as exc:
            logger.error("handle_file_changed(%r) failed: %s", path, exc)

        return created

    @staticmethod
    def _detect_config_format(path: str) -> str:
        """
        Detect config file format by path pattern then by content.

        Returns: 'ipsec_conf' | 'ipsec_secrets' | 'swanctl' | 'unknown'
        """
        basename = os.path.basename(path)

        # Path-based detection first (fastest, most reliable)
        if basename == "ipsec.secrets" or path.endswith(".secrets"):
            return "ipsec_secrets"
        if basename == "ipsec.conf":
            return "ipsec_conf"
        if "swanctl" in path:
            return "swanctl"

        # Content-based detection for unknown paths (e.g., tests, custom locations)
        try:
            with open(path) as fh:
                head = fh.read(4096)
        except OSError:
            return "unknown"

        # ipsec.conf has bare "conn <name>" lines; swanctl uses "section { }"
        if re.search(r"^\s*conn\s+\S", head, re.MULTILINE):
            return "ipsec_conf"
        if re.search(r"^\s*connections\s*\{", head, re.MULTILINE):
            return "swanctl"
        # Secrets file: lines with ": PSK" / ": EAP" etc.
        if re.search(r":\s*(PSK|EAP|XAUTH|RSA)\s", head, re.IGNORECASE):
            return "ipsec_secrets"

        # Default: assume swanctl for .conf files
        if path.endswith(".conf"):
            return "swanctl"
        return "unknown"

    def _handle_file_deleted(self, path: str) -> None:
        """
        When a source config file is deleted, disable all connections that
        were imported from it so they appear as 'inactive' in the GUI.
        """
        from strongswan_manager.apps.connections.models import Connection
        affected = Connection.objects.filter(source_file=path, enabled=True)
        count = affected.count()
        if count:
            for conn in affected:
                self.unload_connection(conn.profile)
            affected.update(enabled=False)
            logger.info(
                "Disabled %d connection(s) from deleted file: %r", count, path
            )
