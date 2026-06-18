"""
ConfigImportEngine — converts parsed config specs into Django model objects.

Orchestration:
  1. Parse /etc/ipsec.conf + /etc/ipsec.secrets (legacy)
  2. Parse /etc/swanctl/swanctl.conf + conf.d/*.conf (modern)
  3. For each connection spec, create the correct Connection subclass
  4. For each secret spec, create or update a Secret
  5. For each pool/authority in swanctl tree, create Pool/Authority objects
  6. Skip any profile that already exists in the DB (no overwrite)

Returns an ImportResult with counts and skipped profiles.
"""
import logging
import os
from dataclasses import dataclass, field

from django.db import transaction

from strongswan_manager.apps.connections.models import (
    Connection, IKEv2Certificate, IKEv2EAP, IKEv2CertificateEAP,
    IKEv1PSK, IKEv1Certificate, IKEv1XauthPSK, IKEv1XauthCertificate,
    Child, Address, Proposal,
    PskAuthentication, EapAuthentication, CertificateAuthentication,
    CaCertificateAuthentication,
)
from strongswan_manager.apps.certificates.models import Authority
from strongswan_manager.apps.eap_secrets.models import Secret
from strongswan_manager.apps.pools.models import Pool

from .ipsec_conf_parser import IpsecConfParser, IpsecConnSpec
from .ipsec_secrets_parser import IpsecSecretsParser, IpsecSecretSpec
from .swanctl_conf_parser import SwanctlConfParser

logger = logging.getLogger(__name__)


@dataclass
class ImportResult:
    connections_created: int = 0
    connections_skipped: int = 0
    secrets_created: int = 0
    secrets_skipped: int = 0
    pools_created: int = 0
    authorities_created: int = 0
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            f"Connections: {self.connections_created} created, "
            f"{self.connections_skipped} skipped (already exist)",
            f"Secrets:     {self.secrets_created} created, "
            f"{self.secrets_skipped} skipped",
            f"Pools:       {self.pools_created} created",
            f"Authorities: {self.authorities_created} created",
        ]
        if self.errors:
            lines.append(f"Errors ({len(self.errors)}):")
            lines.extend(f"  - {e}" for e in self.errors)
        return "\n".join(lines)


class ConfigImportEngine:
    """
    Import all StrongSwan configuration into the Django database.

    Usage:
        engine = ConfigImportEngine()
        result = engine.import_all()
    """

    IPSEC_CONF = "/etc/ipsec.conf"
    IPSEC_SECRETS = "/etc/ipsec.secrets"
    SWANCTL_CONF = "/etc/swanctl/swanctl.conf"

    def __init__(
        self,
        ipsec_conf: str | None = None,
        ipsec_secrets: str | None = None,
        swanctl_conf: str | None = None,
    ):
        self._ipsec_conf = ipsec_conf or self.IPSEC_CONF
        self._ipsec_secrets = ipsec_secrets or self.IPSEC_SECRETS
        self._swanctl_conf = swanctl_conf or self.SWANCTL_CONF

    @transaction.atomic
    def import_all(self) -> ImportResult:
        result = ImportResult()

        # ── Legacy ipsec.conf ────────────────────────────────────────────────
        if os.path.exists(self._ipsec_conf):
            try:
                specs = IpsecConfParser.parse_file(self._ipsec_conf)
                for spec in specs:
                    try:
                        self._import_ipsec_conn(spec, result)
                    except Exception as exc:
                        msg = f"ipsec.conf conn {spec.name!r}: {exc}"
                        logger.warning(msg)
                        result.errors.append(msg)
            except Exception as exc:
                msg = f"Failed to parse {self._ipsec_conf}: {exc}"
                logger.error(msg)
                result.errors.append(msg)

        # ── Legacy ipsec.secrets ──────────────────────────────────────────────
        if os.path.exists(self._ipsec_secrets):
            try:
                secret_specs = IpsecSecretsParser.parse_file(self._ipsec_secrets)
                for spec in secret_specs:
                    try:
                        self._import_ipsec_secret(spec, result)
                    except Exception as exc:
                        msg = f"ipsec.secrets entry: {exc}"
                        logger.warning(msg)
                        result.errors.append(msg)
            except Exception as exc:
                msg = f"Failed to parse {self._ipsec_secrets}: {exc}"
                logger.error(msg)
                result.errors.append(msg)

        # ── Modern swanctl.conf ───────────────────────────────────────────────
        if os.path.exists(self._swanctl_conf):
            try:
                tree = SwanctlConfParser.parse_file(self._swanctl_conf)
                self._import_swanctl_tree(tree, self._swanctl_conf, result)
            except Exception as exc:
                msg = f"Failed to parse {self._swanctl_conf}: {exc}"
                logger.error(msg)
                result.errors.append(msg)

        return result

    # ─── ipsec.conf → Connection ──────────────────────────────────────────────

    def _import_ipsec_conn(self, spec: IpsecConnSpec, result: ImportResult) -> None:
        if Connection.objects.filter(profile=spec.name).exists():
            result.connections_skipped += 1
            return

        conn_class = self._ipsec_conn_class(spec)
        conn = conn_class(
            profile=spec.name,
            version="1" if spec.keyexchange.lower() == "ikev1" else "2",
            connection_type=self._ipsec_conn_type(spec),
            enabled=spec.auto not in ("ignore", ""),
            initiate=(True if spec.auto == "start" else
                      False if spec.auto in ("add", "route") else None),
            aggressive=(True if spec.aggressive else None),
            mobike=(spec.mobike if spec.mobike is not None else None),
            fragmentation=spec.fragmentation,
            dpd_delay=spec.dpddelay,
            dpd_timeout=spec.dpdtimeout,
            rekey_time=spec.ikelifetime,
            reauth_time="",
            source_file=spec.source_file,
        )
        if spec.keyingtries is not None:
            conn.keyingtries = spec.keyingtries
        if spec.type == "transport":
            conn.save()
        else:
            conn.save()

        # Local address
        local_addr = spec.left if spec.left != "%defaultroute" else ""
        if local_addr:
            Address(value=local_addr, local_addresses=conn).save()

        # Remote address
        if spec.right:
            Address(value=spec.right, remote_addresses=conn).save()

        # Child SA
        child_mode = "transport" if spec.type == "transport" else "tunnel"
        child = Child(name=f"{spec.name}-child", mode=child_mode, connection=conn,
                      start_action="start" if spec.auto == "start" else "none")
        child.save()

        # Traffic selectors
        leftsubnet = spec.leftsubnet or spec.leftsourceip
        if leftsubnet:
            Address(value=leftsubnet, local_ts=child).save()

        rightsubnet = spec.rightsubnet
        if rightsubnet:
            Address(value=rightsubnet, remote_ts=child).save()

        # IKE proposals
        if spec.ike:
            for p in spec.ike.split("!")[0].split(","):
                p = p.strip()
                if p:
                    Proposal(type=p, connection=conn).save()

        # ESP proposals → Child SA esp_proposals
        if spec.esp:
            for p in spec.esp.split("!")[0].split(","):
                p = p.strip()
                if p:
                    Proposal(type=p, child=child).save()

        # Authentication
        self._add_ipsec_auth(conn, spec)

        result.connections_created += 1
        logger.info("Imported ipsec.conf connection: %s", spec.name)

    @staticmethod
    def _ipsec_conn_class(spec: IpsecConnSpec):
        authby = spec.authby.lower()
        if spec.keyexchange.lower() == "ikev1":
            if authby in ("xauthpsk", "xauth-psk"):
                return IKEv1XauthPSK
            elif authby in ("xauthrsasig", "xauth-rsasig", "xauthpubkey"):
                return IKEv1XauthCertificate
            elif authby in ("secret", "psk"):
                return IKEv1PSK
            else:
                return IKEv1Certificate
        else:
            return IKEv2Certificate

    @staticmethod
    def _ipsec_conn_type(spec: IpsecConnSpec) -> str:
        # If left=%defaultroute and right is a specific IP → client mode
        # If right=%any or right= is empty → server mode
        if spec.right in ("%any", ""):
            return "server"
        return "client"

    @staticmethod
    def _add_ipsec_auth(conn: Connection, spec: IpsecConnSpec) -> None:
        authby = spec.authby.lower()
        if authby in ("secret", "psk", "xauthpsk", "xauth-psk"):
            PskAuthentication(
                local=conn, name="local-1", auth="psk",
                psk_id=spec.leftid or "",
            ).save()
            PskAuthentication(
                remote=conn, name="remote-1", auth="psk",
                psk_id=spec.rightid or "",
            ).save()
        elif authby in ("pubkey", "rsasig"):
            CertificateAuthentication(local=conn, name="local-1", auth="pubkey").save()
            CaCertificateAuthentication(remote=conn, name="remote-1", auth="pubkey").save()
        # xauthrsasig: cert-based with extra XAUTH round (handled separately in forms)

    # ─── ipsec.secrets → Secret ───────────────────────────────────────────────

    def _import_ipsec_secret(self, spec: IpsecSecretSpec, result: ImportResult) -> None:
        # RSA / P12 file references: we note them but don't store secrets
        if spec.type in ("RSA", "P12"):
            logger.debug("Skipping key file reference: %s", spec.keyfile)
            return

        # Build a unique username key from type + selectors/username
        if spec.type == "EAP":
            username = spec.username or f"eap-{result.secrets_created + result.secrets_skipped}"
        elif spec.type == "XAUTH":
            username = spec.username or f"xauth-{result.secrets_created + result.secrets_skipped}"
        elif spec.type in ("IKE", "ANY"):
            # Use the selector pair as the "username" to keep it unique
            left = spec.left_id or "%any"
            right = spec.right_id or "%any"
            username = f"psk-{left}-{right}"
        else:
            username = f"secret-{result.secrets_created + result.secrets_skipped}"

        if Secret.objects.filter(username=username).exists():
            result.secrets_skipped += 1
            return

        # Fake salt + encode password (the encryption field prepends a 32-char salt)
        import hashlib, os as _os
        salt = _os.urandom(16).hex()  # 32 hex chars
        encoded = salt + spec.secret

        secret = Secret(
            username=username,
            type=spec.type if spec.type in ("EAP", "IKE", "XAUTH", "ANY", "NTLM") else "IKE",
            salt=salt,
            source_file=spec.source_file,
        )
        secret.password = encoded
        if spec.type in ("IKE", "ANY"):
            left = spec.left_id or "%any"
            right = spec.right_id or "%any"
            secret.selector_id = left
            secret.owners = right
        secret.save()
        result.secrets_created += 1

    # ─── swanctl.conf tree → models ───────────────────────────────────────────

    def _import_swanctl_tree(self, tree: dict, source_file: str,
                             result: ImportResult) -> None:
        # Connections
        for name, conf in tree.get("connections", {}).items():
            if not isinstance(conf, dict):
                continue
            try:
                self._import_swanctl_conn(name, conf, source_file, result)
            except Exception as exc:
                msg = f"swanctl conn {name!r}: {exc}"
                logger.warning(msg)
                result.errors.append(msg)

        # Secrets
        for key, conf in tree.get("secrets", {}).items():
            if not isinstance(conf, dict):
                continue
            try:
                self._import_swanctl_secret(key, conf, source_file, result)
            except Exception as exc:
                msg = f"swanctl secret {key!r}: {exc}"
                logger.warning(msg)
                result.errors.append(msg)

        # Pools
        for name, conf in tree.get("pools", {}).items():
            if not isinstance(conf, dict):
                continue
            try:
                self._import_swanctl_pool(name, conf, result)
            except Exception as exc:
                msg = f"swanctl pool {name!r}: {exc}"
                logger.warning(msg)
                result.errors.append(msg)

        # Authorities
        for name, conf in tree.get("authorities", {}).items():
            if not isinstance(conf, dict):
                continue
            try:
                self._import_swanctl_authority(name, conf, source_file, result)
            except Exception as exc:
                msg = f"swanctl authority {name!r}: {exc}"
                logger.warning(msg)
                result.errors.append(msg)

    def _import_swanctl_conn(self, name: str, conf: dict, source_file: str,
                             result: ImportResult) -> None:
        if Connection.objects.filter(profile=name).exists():
            result.connections_skipped += 1
            return

        version = conf.get("version", "2")
        conn = IKEv2Certificate(
            profile=name,
            version=str(version),
            connection_type="client",
            enabled=False,
            source_file=source_file,
        )
        # Scalar fields
        for attr in ("fragmentation", "unique", "rekey_time", "reauth_time",
                     "over_time", "rand_time", "dpd_delay", "dpd_timeout",
                     "if_id_in", "if_id_out", "ppk_id", "dscp"):
            v = conf.get(attr, "")
            if v:
                setattr(conn, attr, str(v))

        if conf.get("keyingtries"):
            try:
                conn.keyingtries = int(conf["keyingtries"])
            except (ValueError, TypeError):
                pass

        for flag in ("mobike", "encap", "aggressive", "ppk_required", "send_certreq",
                     "mediation"):
            v = conf.get(flag)
            if v is not None:
                setattr(conn, flag, v in ("yes", True, "true", "1"))

        conn.save()

        # Addresses
        local_addrs = conf.get("local_addrs", "")
        if local_addrs:
            for addr in _split_list(local_addrs):
                Address(value=addr, local_addresses=conn).save()

        remote_addrs = conf.get("remote_addrs", "")
        if remote_addrs:
            for addr in _split_list(remote_addrs):
                Address(value=addr, remote_addresses=conn).save()

        # IKE proposals
        proposals = conf.get("proposals", "")
        if proposals:
            for p in _split_list(proposals):
                Proposal(type=p, connection=conn).save()

        # Children
        for child_name, child_conf in conf.get("children", {}).items():
            if not isinstance(child_conf, dict):
                continue
            self._import_swanctl_child(child_name, child_conf, conn)

        # Authentication rounds
        for key, auth_conf in conf.items():
            if key.startswith("local") and isinstance(auth_conf, dict):
                self._import_swanctl_local_auth(key, auth_conf, conn)
            elif key.startswith("remote") and isinstance(auth_conf, dict):
                self._import_swanctl_remote_auth(key, auth_conf, conn)

        result.connections_created += 1
        logger.info("Imported swanctl connection: %s", name)

    def _import_swanctl_child(self, name: str, conf: dict, conn: Connection) -> None:
        mode = conf.get("mode", "tunnel").lower()
        start_action = conf.get("start_action", "none")
        child = Child(name=name, mode=mode, connection=conn, start_action=start_action)

        for attr in ("close_action", "dpd_action", "rekey_time", "life_time",
                     "rand_time", "inactivity", "mark_in", "mark_out",
                     "if_id_in", "if_id_out", "tfc_padding", "copy_dscp",
                     "updown", "interface"):
            v = conf.get(attr, "")
            if v:
                setattr(child, attr, str(v))

        hw = conf.get("hw_offload", "no")
        if hw and hw != "no":
            child.hw_offload = str(hw)

        if conf.get("copy_df") is not None:
            child.copy_df = conf["copy_df"] in ("yes", True)

        if conf.get("priority"):
            try:
                child.priority = int(conf["priority"])
            except (ValueError, TypeError):
                pass

        child.save()

        # Traffic selectors
        local_ts = conf.get("local_ts", "")
        if local_ts:
            for ts in _split_list(local_ts):
                Address(value=ts, local_ts=child).save()

        remote_ts = conf.get("remote_ts", "")
        if remote_ts:
            for ts in _split_list(remote_ts):
                Address(value=ts, remote_ts=child).save()

        # ESP proposals
        esp = conf.get("esp_proposals", "")
        if esp:
            for p in _split_list(esp):
                Proposal(type=p, child=child).save()

        # AH proposals
        ah = conf.get("ah_proposals", "")
        if ah:
            for p in _split_list(ah):
                Proposal(type=p, ah_child=child).save()

    def _import_swanctl_local_auth(self, key: str, conf: dict,
                                   conn: Connection) -> None:
        auth_type = conf.get("auth", "pubkey").lower()
        name = key
        if auth_type in ("psk",):
            PskAuthentication(
                local=conn, name=name, auth="psk",
                psk_id=conf.get("id", ""),
            ).save()
        elif auth_type.startswith("xauth"):
            from strongswan_manager.apps.connections.models import XauthAuthentication
            XauthAuthentication(
                local=conn, name=name, auth=auth_type,
                xauth_id=conf.get("xauth_id", ""),
            ).save()
        elif auth_type.startswith("eap"):
            EapAuthentication(
                local=conn, name=name, auth=auth_type,
                round=int(conf.get("round", 1)),
            ).save()
        else:
            CertificateAuthentication(
                local=conn, name=name, auth=auth_type,
            ).save()

    def _import_swanctl_remote_auth(self, key: str, conf: dict,
                                    conn: Connection) -> None:
        auth_type = conf.get("auth", "pubkey").lower()
        name = key
        if auth_type in ("psk",):
            PskAuthentication(
                remote=conn, name=name, auth="psk",
                psk_id=conf.get("id", ""),
            ).save()
        else:
            CaCertificateAuthentication(
                remote=conn, name=name, auth=auth_type,
            ).save()

    def _import_swanctl_secret(self, key: str, conf: dict, source_file: str,
                               result: ImportResult) -> None:
        # Determine type from the key prefix (ike, eap, xauth, ntlm, ppk, etc.)
        prefix = re.match(r"^([a-z]+)", key, re.IGNORECASE)
        type_prefix = prefix.group(1).upper() if prefix else "IKE"
        secret_map = {"IKE": "IKE", "EAP": "EAP", "XAUTH": "XAUTH",
                      "NTLM": "NTLM", "PPK": "IKE"}
        secret_type = secret_map.get(type_prefix, "IKE")

        secret_value = conf.get("secret", "")
        if not secret_value:
            return

        # Build unique username from ids
        ids = [str(v) for k, v in conf.items() if k.startswith("id")]
        username = f"{key}-" + "-".join(ids) if ids else key

        if Secret.objects.filter(username=username).exists():
            result.secrets_skipped += 1
            return

        import os as _os
        salt = _os.urandom(16).hex()
        secret = Secret(
            username=username,
            type=secret_type,
            salt=salt,
            source_file=source_file,
        )
        secret.password = salt + secret_value
        if ids:
            secret.selector_id = ids[0]
            if len(ids) > 1:
                secret.owners = ",".join(ids[1:])
        secret.save()
        result.secrets_created += 1

    def _import_swanctl_pool(self, name: str, conf: dict,
                             result: ImportResult) -> None:
        if Pool.objects.filter(poolname=name).exists():
            return
        addrs = conf.get("addrs", "")
        if not addrs:
            return
        pool = Pool(poolname=name, addresses=str(addrs))
        pool.save()
        result.pools_created += 1
        logger.info("Imported swanctl pool: %s", name)

    def _import_swanctl_authority(self, name: str, conf: dict, source_file: str,
                                  result: ImportResult) -> None:
        if Authority.objects.filter(name=name).exists():
            return

        def _uris(key):
            v = conf.get(key, "")
            return ",".join(_split_list(v)) if v else ""

        auth = Authority(
            name=name,
            cacert=conf.get("cacert", conf.get("file", "")),
            crl_uris=_uris("crl_uris"),
            ocsp_uris=_uris("ocsp_uris"),
            cert_uri_base=conf.get("cert_uri_base", ""),
            source_file=source_file,
        )
        auth.save()
        result.authorities_created += 1
        logger.info("Imported swanctl authority: %s", name)


# ─── helpers ─────────────────────────────────────────────────────────────────

import re


def _split_list(value) -> list[str]:
    """Split a string or list value into individual items."""
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return []
