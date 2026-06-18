"""
ViciService — complete VICI protocol service layer.

Wraps every command exposed by the vici Python library with:
  - Automatic reconnection on socket failure
  - Thread-safe access via a reentrant lock
  - Typed exceptions for clean error handling by callers
  - Graceful ViciUnavailable when charon is not running

Usage (singleton):
    from strongswan_manager.services.vici_service import ViciService
    svc = ViciService.get_instance()
    svc.load_connection(conn.dict())
    sas = svc.list_sas()
"""
import logging
import os
import socket
import stat
import threading
from collections import OrderedDict

import vici

from .exceptions import (
    ViciAuthenticationError,
    ViciError,
    ViciLoadError,
    ViciOperationError,
    ViciUnavailable,
)

logger = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = "/var/run/charon.vici"


class ViciService:
    """
    Thread-safe, auto-reconnecting VICI service.

    Keeps a single persistent socket open.  On any socket-level failure the
    call is retried once after a fresh connection is made; if that second
    attempt also fails, ViciUnavailable is raised so callers can degrade
    gracefully (show a "daemon offline" badge, skip live-state polling, etc.).
    """

    _instance = None
    _instance_lock = threading.Lock()

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH):
        self._socket_path = socket_path
        self._lock = threading.RLock()
        self._sock: socket.socket | None = None
        self._session: vici.Session | None = None

    # ─── Singleton access ────────────────────────────────────────────────────

    @classmethod
    def get_instance(cls, socket_path: str = DEFAULT_SOCKET_PATH) -> "ViciService":
        """Return the process-wide singleton instance."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls(socket_path)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Discard the singleton (used in tests to inject a fresh mock)."""
        with cls._instance_lock:
            if cls._instance is not None:
                cls._instance._close()
                cls._instance = None

    # ─── Connection management ────────────────────────────────────────────────

    def _close(self) -> None:
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._session = None

    def _connect(self) -> None:
        """Open a new UNIX socket to charon and create a vici.Session."""
        self._close()
        if not os.path.exists(self._socket_path):
            raise ViciUnavailable(f"VICI socket not found: {self._socket_path}")
        mode = os.stat(self._socket_path).st_mode
        if not stat.S_ISSOCK(mode):
            raise ViciUnavailable(f"Path is not a socket: {self._socket_path}")
        try:
            self._sock = socket.socket(socket.AF_UNIX)
            self._sock.connect(self._socket_path)
            self._session = vici.Session(self._sock)
        except OSError as exc:
            self._close()
            raise ViciUnavailable(f"Cannot connect to charon VICI socket: {exc}") from exc

    def _session_or_connect(self) -> vici.Session:
        """Return an active session, connecting if necessary."""
        if self._session is None:
            self._connect()
        return self._session  # type: ignore[return-value]

    def _call(self, fn, *args, **kwargs):
        """
        Execute fn(*args, **kwargs) against the VICI session.
        Only reconnects on socket-level OSError; protocol errors propagate immediately.
        """
        with self._lock:
            try:
                sess = self._session_or_connect()
                return fn(sess, *args, **kwargs)
            except ViciUnavailable:
                raise
            except OSError as exc:
                # Socket-level failure — reconnect once and retry
                logger.debug("VICI socket error (%s), attempting reconnect", exc)
                try:
                    self._connect()
                    return fn(self._session, *args, **kwargs)
                except ViciUnavailable:
                    raise
                except Exception as exc2:
                    raise ViciUnavailable(f"VICI unreachable after reconnect: {exc2}") from exc2

    # ─── Streaming helpers ────────────────────────────────────────────────────

    def _collect(self, method_name: str, *args, **kwargs) -> list:
        """Exhaust a streamed VICI response and return a list. Reconnects on OSError only."""
        with self._lock:
            try:
                sess = self._session_or_connect()
                return list(getattr(sess, method_name)(*args, **kwargs))
            except ViciUnavailable:
                raise
            except OSError as exc:
                logger.debug("VICI socket error in %s (%s), reconnecting", method_name, exc)
                try:
                    self._connect()
                    return list(getattr(self._session, method_name)(*args, **kwargs))
                except ViciUnavailable:
                    raise
                except Exception as exc2:
                    raise ViciUnavailable(f"VICI unreachable: {exc2}") from exc2

    # ─── Connection management commands ──────────────────────────────────────

    def load_connection(self, connection: dict) -> None:
        """Load an IKE connection definition (swanctl connections{} format)."""
        try:
            self._call(lambda s: s.load_conn(connection))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciLoadError(f"load_conn failed: {exc}") from exc

    def unload_connection(self, name: str) -> None:
        """Unload an IKE connection by name. No-op if not loaded."""
        if name in self.get_connection_names():
            try:
                self._call(lambda s: s.unload_conn(OrderedDict(name=name)))
            except ViciUnavailable:
                raise
            except Exception as exc:
                raise ViciLoadError(f"unload_conn failed for {name!r}: {exc}") from exc

    def get_connection_names(self) -> list[str]:
        """Return list of currently-loaded IKE connection names."""
        names = []
        for entry in self._collect("list_conns"):
            names.extend(entry.keys())
        return names

    def is_connection_loaded(self, name: str) -> bool:
        return name in self.get_connection_names()

    def unload_all_connections(self) -> None:
        for name in self.get_connection_names():
            self.unload_connection(name)

    def get_conns(self) -> dict:
        """Return all loaded connections as a single dict (get_conns command)."""
        return self._call(lambda s: dict(s.get_conns()))

    # ─── SA commands ─────────────────────────────────────────────────────────

    def list_sas(self, ike: str | None = None, child: str | None = None,
                 ike_id: int | None = None, noblock: bool = False) -> list[dict]:
        """
        List active IKE Security Associations.
        Optionally filter by connection name, child SA name, or IKE SA id.
        """
        filters: dict = {}
        if ike:
            filters["ike"] = ike
        if child:
            filters["child"] = child
        if ike_id is not None:
            filters["ike-id"] = str(ike_id)
        if noblock:
            filters["noblock"] = "yes"
        result = self._collect("list_sas", filters if filters else {})
        return [dict(sa) for sa in result]

    def get_connection_state(self, name: str) -> str:
        """Return the IKE state string for a connection, or 'DOWN' if not active."""
        try:
            sas = self.list_sas(ike=name)
            if sas and name in sas[0]:
                return sas[0][name].get("state", b"DOWN").decode("ascii")
        except ViciUnavailable:
            pass
        return "DOWN"

    def initiate(self, child: str, ike: str) -> list[dict]:
        """
        Initiate an IKE/Child SA.  Returns log messages.
        Callers may iterate lazily; this method exhausts the generator.
        """
        req = OrderedDict(ike=ike, child=child)
        try:
            msgs = self._collect("initiate", req)
            return [OrderedDict(message=m["msg"].decode("ascii")) for m in msgs if "msg" in m]
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"initiate failed for {ike}/{child}: {exc}") from exc

    def terminate(self, ike: str | None = None, child: str | None = None,
                  ike_id: int | None = None, child_id: int | None = None) -> list[dict]:
        """Terminate an IKE or Child SA. Returns log messages."""
        req: OrderedDict = OrderedDict()
        if ike:
            req["ike"] = ike
        if child:
            req["child"] = child
        if ike_id is not None:
            req["ike-id"] = str(ike_id)
        if child_id is not None:
            req["child-id"] = str(child_id)
        try:
            msgs = self._collect("terminate", req)
            return [OrderedDict(message=m["msg"].decode("ascii")) for m in msgs if "msg" in m]
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"terminate failed: {exc}") from exc

    def rekey(self, ike: str | None = None, child: str | None = None,
              ike_id: int | None = None, child_id: int | None = None) -> None:
        """Trigger a rekey of an IKE or Child SA."""
        req: OrderedDict = OrderedDict()
        if ike:
            req["ike"] = ike
        if child:
            req["child"] = child
        if ike_id is not None:
            req["ike-id"] = str(ike_id)
        if child_id is not None:
            req["child-id"] = str(child_id)
        try:
            self._call(lambda s: s.rekey(req))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"rekey failed: {exc}") from exc

    def redirect(self, ike_id: int, peer_ip: str) -> None:
        """Redirect an IKE SA to a different gateway (cluster migration)."""
        req = OrderedDict([("ike-id", str(ike_id)), ("peer-ip", peer_ip)])
        try:
            self._call(lambda s: s.redirect(req))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"redirect failed: {exc}") from exc

    # ─── Credential management commands ──────────────────────────────────────

    def load_shared(self, secret: dict) -> None:
        """Load a shared secret (PSK / EAP / XAUTH)."""
        try:
            self._call(lambda s: s.load_shared(secret))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciAuthenticationError(f"load_shared failed: {exc}") from exc

    def load_key(self, key: dict) -> None:
        """Load a private key."""
        try:
            self._call(lambda s: s.load_key(key))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciAuthenticationError(f"load_key failed: {exc}") from exc

    def unload_key(self, key_id: str) -> None:
        """Unload a private key by its id."""
        try:
            self._call(lambda s: s.unload_key(OrderedDict(id=key_id)))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciAuthenticationError(f"unload_key failed: {exc}") from exc

    def get_keys(self) -> list[str]:
        """Return list of loaded private-key ids."""
        return list(self._call(lambda s: s.get_keys()))

    def unload_shared(self, shared_id: str, type_: str | None = None) -> None:
        """Unload a shared secret by id and optional type."""
        req: OrderedDict = OrderedDict(id=shared_id)
        if type_:
            req["type"] = type_
        try:
            self._call(lambda s: s.unload_shared(req))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciAuthenticationError(f"unload_shared failed: {exc}") from exc

    def get_shared(self, type_: str | None = None) -> list[dict]:
        """Return loaded shared secrets (optionally filtered by type)."""
        req = OrderedDict(type=type_) if type_ else {}
        return list(self._call(lambda s: s.get_shared(req)))

    def load_certificate(self, cert: dict) -> None:
        """Load an X.509 or other certificate."""
        try:
            self._call(lambda s: s.load_cert(cert))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciAuthenticationError(f"load_cert failed: {exc}") from exc

    def list_certificates(self, type_: str = "X509") -> list[dict]:
        """List loaded certificates of a given type."""
        return self._collect("list_certs", OrderedDict(type=type_))

    def load_token(self, handle: str, pin: str | None = None) -> None:
        """Load a private key from a PKCS#11 token."""
        req: OrderedDict = OrderedDict(handle=handle)
        if pin is not None:
            req["pin"] = pin
        try:
            self._call(lambda s: s.load_token(req))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciAuthenticationError(f"load_token failed: {exc}") from exc

    def clear_creds(self) -> None:
        """Clear all loaded credentials (keys, certs, shared secrets)."""
        try:
            self._call(lambda s: s.clear_creds())
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciAuthenticationError(f"clear_creds failed: {exc}") from exc

    def flush_certs(self, type_: str | None = None) -> None:
        """Flush the certificate cache (optionally by type)."""
        req = OrderedDict(type=type_) if type_ else {}
        try:
            self._call(lambda s: s.flush_certs(req))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"flush_certs failed: {exc}") from exc

    # ─── Authority management ─────────────────────────────────────────────────

    def load_authority(self, authority: dict) -> None:
        """Load a CA configuration (cacert, crl_uris, ocsp_uris, etc.)."""
        try:
            self._call(lambda s: s.load_authority(authority))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciLoadError(f"load_authority failed: {exc}") from exc

    def unload_authority(self, name: str) -> None:
        """Unload a CA configuration by name."""
        try:
            self._call(lambda s: s.unload_authority(OrderedDict(name=name)))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciLoadError(f"unload_authority failed: {exc}") from exc

    def list_authorities(self) -> list[dict]:
        """Return loaded CA configurations."""
        return self._collect("list_authorities")

    def get_authorities(self) -> dict:
        """Return all loaded authority configs as a dict (get_authorities command)."""
        return dict(self._call(lambda s: s.get_authorities()))

    # ─── Pool management ─────────────────────────────────────────────────────

    def load_pool(self, pool: dict) -> None:
        try:
            self._call(lambda s: s.load_pool(pool))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciLoadError(f"load_pool failed: {exc}") from exc

    def unload_pool(self, name: str) -> None:
        try:
            self._call(lambda s: s.unload_pool(OrderedDict(name=name)))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciLoadError(f"unload_pool failed: {exc}") from exc

    def get_pools(self, include_leases: bool = False) -> dict:
        req = OrderedDict(leases="yes" if include_leases else "no")
        return dict(self._call(lambda s: s.get_pools(req)))

    # ─── Policy management ────────────────────────────────────────────────────

    def install_policy(self, policy: dict) -> None:
        """Install a shunt/trap/pass policy (swanctl equivalent of 'install')."""
        try:
            self._call(lambda s: s.install(policy))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"install policy failed: {exc}") from exc

    def uninstall_policy(self, policy: dict) -> None:
        try:
            self._call(lambda s: s.uninstall(policy))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"uninstall policy failed: {exc}") from exc

    def list_policies(self, trap: bool = True, drop: bool = True,
                      pass_: bool = True) -> list[dict]:
        """Return installed trap/drop/pass policies."""
        req = OrderedDict()
        if trap:
            req["trap"] = "yes"
        if drop:
            req["drop"] = "yes"
        if pass_:
            req["pass"] = "yes"
        return self._collect("list_policies", req)

    # ─── Counter management ───────────────────────────────────────────────────

    def get_counters(self, name: str | None = None) -> dict:
        """
        Return IKE event counters (packets, errors) for all connections
        or a specific connection name.
        """
        req = OrderedDict(name=name) if name else {}
        result = self._call(lambda s: s.get_counters(req))
        return dict(result) if result else {}

    def reset_counters(self, name: str | None = None) -> None:
        """Reset IKE event counters, optionally for a single connection."""
        req = OrderedDict(name=name) if name else {}
        try:
            self._call(lambda s: s.reset_counters(req))
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"reset_counters failed: {exc}") from exc

    # ─── Daemon management ────────────────────────────────────────────────────

    def reload_settings(self) -> None:
        """Tell charon to re-read strongswan.conf (does NOT reload swanctl.conf)."""
        try:
            self._call(lambda s: s.reload_settings())
        except ViciUnavailable:
            raise
        except Exception as exc:
            raise ViciOperationError(f"reload_settings failed: {exc}") from exc

    def get_version(self) -> dict:
        """Return daemon version information."""
        return dict(self._call(lambda s: s.version()))

    def get_stats(self) -> dict:
        """Return daemon statistics (uptime, worker threads, scheduler)."""
        return dict(self._call(lambda s: s.stats()))

    def get_plugins(self) -> list[str]:
        """Return list of loaded plugin names."""
        stats = self.get_stats()
        return list(stats.get("plugins", {}).keys())

    def get_algorithms(self) -> dict:
        """Return supported cryptographic algorithms."""
        return dict(self._call(lambda s: s.get_algorithms()))

    # ─── Bulk-load helpers ────────────────────────────────────────────────────

    def load_all_connections(self, connections) -> None:
        """
        Load all Connection queryset rows into charon.
        Skips rows where connection.dict() raises an exception.
        """
        for conn in connections:
            try:
                self.load_connection(conn.dict())
            except (ViciLoadError, ViciUnavailable):
                raise
            except Exception as exc:
                logger.warning("Skipping connection %r: %s", conn.profile, exc)

    def load_all_secrets(self, secrets) -> None:
        """Load all Secret queryset rows into charon."""
        for secret in secrets:
            try:
                self.load_shared(secret.dict())
            except (ViciAuthenticationError, ViciUnavailable):
                raise
            except Exception as exc:
                logger.warning("Skipping secret %r: %s", secret, exc)

    def load_all_authorities(self, authorities) -> None:
        """Load all Authority queryset rows into charon."""
        for auth in authorities:
            try:
                self.load_authority(auth.dict())
            except (ViciLoadError, ViciUnavailable):
                raise
            except Exception as exc:
                logger.warning("Skipping authority %r: %s", auth.name, exc)
