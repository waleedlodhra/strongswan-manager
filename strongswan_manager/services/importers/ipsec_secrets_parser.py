"""
Parser for the legacy /etc/ipsec.secrets format.

Supported secret types:
  IP1 IP2 : PSK "secret"          → IKE PSK
  %any %any : PSK "secret"        → IKE PSK (wildcard)
  : PSK "secret"                  → IKE PSK (no selector)
  user : EAP "password"           → EAP credential
  user : XAUTH "password"         → XAUTH credential
  : RSA /path/to/key.pem          → RSA key reference (keyfile, not stored)
  : P12 /path/to/bundle.p12       → PKCS#12 key bundle reference

Produces a list of IpsecSecretSpec dataclasses.
"""
import re
import shlex
from dataclasses import dataclass, field


@dataclass
class IpsecSecretSpec:
    type: str             # PSK | EAP | XAUTH | RSA | P12 | ANY
    secret: str           # the plaintext secret (empty for RSA/P12 references)
    left_id: str = ""     # left selector (IP or ID)
    right_id: str = ""    # right selector (IP or ID)
    username: str = ""    # for EAP / XAUTH
    keyfile: str = ""     # for RSA / P12 references
    source_file: str = ""


class IpsecSecretsParser:
    """
    Parse an ipsec.secrets file into a list of IpsecSecretSpec objects.

    Usage:
        specs = IpsecSecretsParser.parse_file("/etc/ipsec.secrets")
    """

    # Matches:  [selectors]  : TYPE  value
    # Selectors are optional — can be IPs, %any, or quoted IDs
    _LINE_RE = re.compile(
        r"^(?P<selectors>[^:]*?)\s*:\s*(?P<type>\w+)\s+(?P<value>.+?)\s*$"
    )

    @classmethod
    def parse_file(cls, path: str) -> list[IpsecSecretSpec]:
        with open(path) as f:
            text = f.read()
        return cls.parse_text(text, source_file=path)

    @classmethod
    def parse_text(cls, text: str, source_file: str = "<string>") -> list[IpsecSecretSpec]:
        specs = []
        # Join continuation lines (backslash-newline)
        text = re.sub(r"\\\n", " ", text)

        for raw_line in text.splitlines():
            # Strip comments
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            m = cls._LINE_RE.match(line)
            if not m:
                continue

            selector_str = m.group("selectors").strip()
            secret_type = m.group("type").upper()
            raw_value = m.group("value").strip()

            spec = cls._build_spec(selector_str, secret_type, raw_value, source_file)
            if spec:
                specs.append(spec)

        return specs

    @classmethod
    def _build_spec(cls, selector_str: str, secret_type: str,
                    raw_value: str, source_file: str) -> IpsecSecretSpec | None:
        # Unquote value
        value = cls._unquote(raw_value)
        selectors = selector_str.split() if selector_str else []

        if secret_type in ("PSK", "IKE"):
            left_id = selectors[0] if len(selectors) > 0 else "%any"
            right_id = selectors[1] if len(selectors) > 1 else "%any"
            return IpsecSecretSpec(
                type="IKE",
                secret=value,
                left_id=left_id,
                right_id=right_id,
                source_file=source_file,
            )

        elif secret_type in ("EAP",):
            username = selectors[0] if selectors else ""
            return IpsecSecretSpec(
                type="EAP",
                secret=value,
                username=username,
                source_file=source_file,
            )

        elif secret_type in ("XAUTH",):
            username = selectors[0] if selectors else ""
            return IpsecSecretSpec(
                type="XAUTH",
                secret=value,
                username=username,
                source_file=source_file,
            )

        elif secret_type in ("RSA", "ECDSA"):
            return IpsecSecretSpec(
                type="RSA",
                secret="",
                keyfile=value,
                source_file=source_file,
            )

        elif secret_type in ("P12", "PKCS12"):
            return IpsecSecretSpec(
                type="P12",
                secret="",
                keyfile=value,
                source_file=source_file,
            )

        else:
            # ANY or unknown — store as generic PSK
            left_id = selectors[0] if len(selectors) > 0 else "%any"
            right_id = selectors[1] if len(selectors) > 1 else "%any"
            return IpsecSecretSpec(
                type="ANY",
                secret=value,
                left_id=left_id,
                right_id=right_id,
                source_file=source_file,
            )

    @staticmethod
    def _unquote(value: str) -> str:
        """Strip surrounding single or double quotes from a secret value."""
        if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
            return value[1:-1]
        return value
