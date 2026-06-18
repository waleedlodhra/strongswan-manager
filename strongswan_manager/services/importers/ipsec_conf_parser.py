"""
Parser for the legacy /etc/ipsec.conf format.

Produces a list of IpsecConnSpec dataclasses, one per conn block.
Handles:
  - config setup section (ignored)
  - conn %default (applied as base to all subsequent conns)
  - Multiple conn blocks
  - Comments (#)
  - auto=start/add/route/ignore
  - Proposal strings (ike=, esp=, ah=)
  - left/right/subnet/id/nexthop fields
  - IKEv1 authby variants → Connection subtype selection
"""
import glob
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IpsecConnSpec:
    """Parsed representation of a single conn block from ipsec.conf."""
    name: str
    source_file: str

    # Connection control
    auto: str = "ignore"          # start | add | route | ignore
    keyexchange: str = "ikev2"    # ikev1 | ikev2
    authby: str = "pubkey"        # secret | pubkey | rsasig | xauthpsk | xauthrsasig | never

    # Addressing
    left: str = "%defaultroute"
    leftsubnet: str = ""
    leftsubnets: str = ""
    leftid: str = ""
    leftsourceip: str = ""
    leftnexthop: str = ""
    right: str = ""
    rightsubnet: str = ""
    rightsubnets: str = ""
    rightid: str = ""
    rightdns: str = ""

    # Proposals
    ike: str = ""                 # IKE proposal string
    esp: str = ""                 # ESP proposal string
    ah: str = ""                  # AH proposal string

    # IKEv1 / IKEv2 common options
    aggressive: Optional[bool] = None
    mobike: Optional[bool] = None
    fragmentation: str = ""
    forceencaps: Optional[bool] = None
    rekey: Optional[bool] = None
    reauth: Optional[bool] = None
    rekeyfuzz: str = ""
    keyingtries: Optional[int] = None
    ikelifetime: str = ""
    lifetime: str = ""           # Child SA lifetime
    margintime: str = ""
    dpdaction: str = ""          # clear | hold | restart
    dpddelay: str = ""
    dpdtimeout: str = ""
    inactivity: str = ""

    # Mode
    type: str = "tunnel"         # tunnel | transport | passthrough | drop

    # Extra raw dict for pass-through of unknown keys
    extra: dict = field(default_factory=dict)


class IpsecConfParser:
    """
    Parse an ipsec.conf file into a list of IpsecConnSpec objects.

    Usage:
        specs = IpsecConfParser.parse_file("/etc/ipsec.conf")
    """

    @classmethod
    def parse_file(cls, path: str) -> list[IpsecConnSpec]:
        """Read path and return parsed conn specs. Includes %include directives."""
        with open(path) as f:
            text = f.read()
        return cls.parse_text(text, source_file=path, base_dir=os.path.dirname(path))

    @classmethod
    def parse_text(cls, text: str, source_file: str = "<string>",
                   base_dir: str = "") -> list[IpsecConnSpec]:
        lines = cls._expand_includes(text, base_dir)
        blocks = cls._split_blocks(lines, source_file)
        return cls._build_specs(blocks)

    # ─── Step 1: expand %include ────────────────────────────────────────────

    @classmethod
    def _expand_includes(cls, text: str, base_dir: str) -> list[str]:
        result = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("%include ") or stripped.startswith("include "):
                pattern = stripped.split(None, 1)[1].strip()
                if not os.path.isabs(pattern) and base_dir:
                    pattern = os.path.join(base_dir, pattern)
                for path in sorted(glob.glob(pattern)):
                    try:
                        with open(path) as f:
                            result.extend(cls._expand_includes(f.read(), os.path.dirname(path)))
                    except OSError:
                        pass
            else:
                result.append(line)
        return result

    # ─── Step 2: split into named blocks ─────────────────────────────────────

    @classmethod
    def _split_blocks(cls, lines: list[str], source_file: str) -> list[tuple[str, str, dict]]:
        """
        Returns list of (section_type, name, {key: value}) tuples.
        section_type is 'config', 'conn', or 'ca'.
        """
        blocks = []
        current_type = None
        current_name = None
        current_kvs: dict = {}

        for line in lines:
            # Strip comment
            if "#" in line:
                line = line[:line.index("#")]
            stripped = line.strip()
            if not stripped:
                continue

            # Section header
            lower = stripped.lower()
            if lower.startswith("config ") or lower.startswith("conn ") or lower.startswith("ca "):
                if current_type:
                    blocks.append((current_type, current_name, current_kvs, source_file))
                parts = stripped.split(None, 1)
                current_type = parts[0].lower()
                current_name = parts[1].strip() if len(parts) > 1 else ""
                current_kvs = {}
            elif "=" in stripped and current_type:
                key, _, value = stripped.partition("=")
                current_kvs[key.strip()] = value.strip()

        if current_type:
            blocks.append((current_type, current_name, current_kvs, source_file))

        return blocks

    # ─── Step 3: build IpsecConnSpec objects ─────────────────────────────────

    @classmethod
    def _build_specs(cls, blocks: list[tuple]) -> list[IpsecConnSpec]:
        defaults: dict = {}
        specs = []

        for block in blocks:
            btype, name, kvs, source_file = block
            if btype != "conn":
                continue
            if name == "%default":
                defaults = dict(kvs)
                continue

            merged = {**defaults, **kvs}
            spec = cls._kvs_to_spec(name, merged, source_file)
            specs.append(spec)

        return specs

    @classmethod
    def _kvs_to_spec(cls, name: str, kvs: dict, source_file: str) -> IpsecConnSpec:
        def b(key, default=None):
            v = kvs.get(key, "").lower()
            if v in ("yes", "true", "1"):
                return True
            if v in ("no", "false", "0"):
                return False
            return default

        def s(key, default=""):
            return kvs.get(key, default).strip()

        def n(key, default=None):
            v = kvs.get(key, "")
            try:
                return int(v)
            except (ValueError, TypeError):
                return default

        spec = IpsecConnSpec(name=name, source_file=source_file)
        spec.auto = s("auto", "ignore")
        spec.keyexchange = s("keyexchange", "ikev2")
        spec.authby = s("authby", "pubkey")
        spec.left = s("left", "%defaultroute")
        spec.leftsubnet = s("leftsubnet")
        spec.leftsubnets = s("leftsubnets")
        spec.leftid = s("leftid")
        spec.leftsourceip = s("leftsourceip")
        spec.leftnexthop = s("leftnexthop")
        spec.right = s("right")
        spec.rightsubnet = s("rightsubnet")
        spec.rightsubnets = s("rightsubnets")
        spec.rightid = s("rightid")
        spec.rightdns = s("rightdns")
        spec.ike = s("ike")
        spec.esp = s("esp")
        spec.ah = s("ah")
        spec.aggressive = b("aggressive")
        spec.mobike = b("mobike")
        spec.fragmentation = s("fragmentation")
        spec.forceencaps = b("forceencaps")
        spec.rekey = b("rekey")
        spec.reauth = b("reauth")
        spec.rekeyfuzz = s("rekeyfuzz")
        spec.keyingtries = n("keyingtries")
        spec.ikelifetime = s("ikelifetime")
        spec.lifetime = s("lifetime")
        spec.margintime = s("margintime")
        spec.dpdaction = s("dpdaction")
        spec.dpddelay = s("dpddelay")
        spec.dpdtimeout = s("dpdtimeout")
        spec.inactivity = s("inactivity")
        spec.type = s("type", "tunnel")

        known = {
            "auto", "keyexchange", "authby", "left", "leftsubnet", "leftsubnets",
            "leftid", "leftsourceip", "leftnexthop", "right", "rightsubnet",
            "rightsubnets", "rightid", "rightdns", "ike", "esp", "ah",
            "aggressive", "mobike", "fragmentation", "forceencaps", "rekey",
            "reauth", "rekeyfuzz", "keyingtries", "ikelifetime", "lifetime",
            "margintime", "dpdaction", "dpddelay", "dpdtimeout", "inactivity", "type",
        }
        spec.extra = {k: v for k, v in kvs.items() if k not in known}
        return spec
