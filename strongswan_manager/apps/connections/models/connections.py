import json
import sys
from collections import OrderedDict
from collections.abc import Iterable

from django.db import models
from django.db.models.signals import pre_delete
from django.dispatch import receiver

from strongswan_manager.apps.connections.models.common import State
from strongswan_manager.helper_apps.vici.wrapper.wrapper import ViciWrapper
from .authentication import Authentication, AutoCaAuthentication
from .specific import Child, Address, Proposal, Secret, LogMessage


class Connection(models.Model):
    """Unified IPsec connection — covers client, server, and site-to-site roles."""

    VERSION_CHOICES = (
        ('0', 'Any IKE version'),
        ('1', 'IKEv1'),
        ('2', 'IKEv2'),
    )
    CONNECTION_TYPE_CHOICES = (
        ('client', 'Client (initiator)'),
        ('server', 'Server (responder)'),
        ('site_to_site', 'Site-to-Site'),
    )

    # Core identity
    profile = models.TextField(unique=True)
    version = models.CharField(max_length=1, choices=VERSION_CHOICES, default='2')
    connection_type = models.CharField(
        max_length=20, choices=CONNECTION_TYPE_CHOICES, default='client'
    )
    enabled = models.BooleanField(default=False)
    initiate = models.BooleanField(null=True, blank=True, default=None)

    # Ports
    local_port = models.IntegerField(null=True, blank=True, default=None)
    remote_port = models.IntegerField(null=True, blank=True, default=None)

    # Pool (server side)
    pool = models.ForeignKey(
        'pools.Pool',
        null=True, blank=True, default=None,
        related_name='connections',
        on_delete=models.PROTECT,
    )

    # Certificate handling
    send_certreq = models.BooleanField(null=True, blank=True, default=None)
    send_cert = models.CharField(
        max_length=10,
        choices=(('ifasked', 'ifasked'), ('always', 'always'), ('never', 'never')),
        default='ifasked',
    )

    # IKE timers
    rekey_time = models.CharField(max_length=20, blank=True, default='')
    reauth_time = models.CharField(max_length=20, blank=True, default='')
    over_time = models.CharField(max_length=20, blank=True, default='')
    rand_time = models.CharField(max_length=20, blank=True, default='')
    keyingtries = models.IntegerField(null=True, blank=True, default=None)

    # DPD
    dpd_delay = models.CharField(max_length=20, blank=True, default='')
    dpd_timeout = models.CharField(max_length=20, blank=True, default='')

    # IKE behaviour flags
    unique = models.CharField(max_length=10, blank=True, default='')
    fragmentation = models.CharField(max_length=10, blank=True, default='')
    mobike = models.BooleanField(null=True, blank=True, default=None)
    encap = models.BooleanField(null=True, blank=True, default=None)
    aggressive = models.BooleanField(null=True, blank=True, default=None)

    # XFRM interfaces
    if_id_in = models.CharField(max_length=20, blank=True, default='')
    if_id_out = models.CharField(max_length=20, blank=True, default='')

    # Post-quantum PSK
    ppk_id = models.CharField(max_length=128, blank=True, default='')
    ppk_required = models.BooleanField(null=True, blank=True, default=None)

    # Mediation
    mediation = models.BooleanField(null=True, blank=True, default=None)
    mediated_by = models.CharField(max_length=128, blank=True, default='')

    # DSCP
    dscp = models.CharField(max_length=6, blank=True, default='')

    # Source config file (for sync engine)
    source_file = models.CharField(max_length=512, blank=True, default='')

    # Legacy field kept for backward compat with old connections-app tests
    auth = models.TextField(blank=True, default='')

    def dict(self):
        children = OrderedDict()
        for child in self.children.all():
            children[child.name] = child.dict()

        ike_sa = OrderedDict()

        remote_addrs = [a.value for a in self.remote_addresses.all() if a.value]
        if remote_addrs:
            ike_sa['remote_addrs'] = remote_addrs
        local_addrs = [a.value for a in self.local_addresses.all() if a.value]
        if local_addrs:
            ike_sa['local_addrs'] = local_addrs
        vips = [v.value for v in self.vips.all() if v.value]
        if vips:
            ike_sa['vips'] = vips

        ike_sa['version'] = self.version
        proposals = [p.type for p in self.proposals.all() if p.type]
        if proposals:
            ike_sa['proposals'] = proposals
        ike_sa['children'] = children

        if self.pool:
            ike_sa['pools'] = [self.pool.poolname]
        if self.local_port:
            ike_sa['local_port'] = self.local_port
        if self.remote_port:
            ike_sa['remote_port'] = self.remote_port
        if self.send_certreq is not None:
            ike_sa['send_certreq'] = 'yes' if self.send_certreq else 'no'
        if self.send_cert and self.send_cert != 'ifasked':
            ike_sa['send_cert'] = self.send_cert
        if self.rekey_time:
            ike_sa['rekey_time'] = self.rekey_time
        if self.reauth_time:
            ike_sa['reauth_time'] = self.reauth_time
        if self.over_time:
            ike_sa['over_time'] = self.over_time
        if self.rand_time:
            ike_sa['rand_time'] = self.rand_time
        if self.keyingtries is not None:
            ike_sa['keyingtries'] = self.keyingtries
        if self.dpd_delay:
            ike_sa['dpd_delay'] = self.dpd_delay
        if self.dpd_timeout:
            ike_sa['dpd_timeout'] = self.dpd_timeout
        if self.unique:
            ike_sa['unique'] = self.unique
        if self.fragmentation:
            ike_sa['fragmentation'] = self.fragmentation
        if self.mobike is not None:
            ike_sa['mobike'] = 'yes' if self.mobike else 'no'
        if self.encap is not None:
            ike_sa['encap'] = 'yes' if self.encap else 'no'
        if self.aggressive is not None:
            ike_sa['aggressive'] = 'yes' if self.aggressive else 'no'
        if self.if_id_in:
            ike_sa['if_id_in'] = self.if_id_in
        if self.if_id_out:
            ike_sa['if_id_out'] = self.if_id_out
        if self.ppk_id:
            ike_sa['ppk_id'] = self.ppk_id
        if self.ppk_required is not None:
            ike_sa['ppk_required'] = 'yes' if self.ppk_required else 'no'
        if self.mediation is not None:
            ike_sa['mediation'] = 'yes' if self.mediation else 'no'
        if self.mediated_by:
            ike_sa['mediated_by'] = self.mediated_by
        if self.dscp:
            ike_sa['dscp'] = self.dscp

        for local in self.local.all():
            ike_sa.update(local.subclass().dict())
        for remote in self.remote.all():
            ike_sa.update(remote.subclass().dict())

        return OrderedDict([(self.profile, ike_sa)])

    def start(self):
        vici_wrapper = ViciWrapper()
        vici_wrapper.unload_connection(self.profile)
        vici_wrapper.load_connection(self.subclass().dict())
        self._load_keys_and_secrets(vici_wrapper)
        for child in self.children.all():
            logs = vici_wrapper.initiate(child.name, self.profile)
            for log in logs:
                LogMessage(connection=self, message=log['message']).save()

    def load(self):
        """Load into charon without initiating (server/responder)."""
        self.enabled = True
        self.save()
        vici_wrapper = ViciWrapper()
        vici_wrapper.unload_connection(self.profile)
        vici_wrapper.load_connection(self.subclass().dict())
        self._load_keys_and_secrets(vici_wrapper)

    def _load_keys_and_secrets(self, vici_wrapper):
        for local in self.local.all():
            local = local.subclass()
            if local.has_private_key():
                vici_wrapper.load_key(local.get_key_dict())
            for secret in Secret.objects.filter(authentication=local):
                vici_wrapper.load_secret(secret.dict())
        for remote in self.remote.all():
            remote = remote.subclass()
            if remote.has_private_key():
                vici_wrapper.load_key(remote.get_key_dict())
            for secret in Secret.objects.filter(authentication=remote):
                vici_wrapper.load_secret(secret.dict())

    def stop(self):
        vici_wrapper = ViciWrapper()
        vici_wrapper.unload_connection(self.profile)
        logs = vici_wrapper.terminate_connection(self.profile)
        for log in logs:
            LogMessage(connection=self, message=log['message']).save()

    def unload(self):
        self.enabled = False
        self.save()
        ViciWrapper().unload_connection(self.profile)

    def is_client(self):
        return self.connection_type == 'client'

    def is_server(self):
        return self.connection_type == 'server'

    def is_site_to_site(self):
        return self.connection_type == 'site_to_site'

    def is_remote_access(self):
        return self.connection_type == 'server'

    @classmethod
    def get_types(cls):
        return [sub().__class__.__name__ for sub in cls.__subclasses__()]

    def get_typ(self):
        return type(self).__name__

    def subclass(self):
        for cls_name in self.get_types():
            cls = getattr(sys.modules[__name__], cls_name)
            obj = cls.objects.filter(id=self.id)
            if obj.exists():
                return obj.first()
        return self

    @classmethod
    def choice_name(cls):
        raise NotImplementedError

    @property
    def state(self):
        try:
            vici_wrapper = ViciWrapper()
            if self.connection_type in ('server',) and not self.initiate:
                loaded = vici_wrapper.is_connection_loaded(self.profile)
                return State.LOADED.value if loaded else State.UNLOADED.value
            state = vici_wrapper.get_connection_state(self.profile)
            return state if state in (
                State.DOWN.value, State.ESTABLISHED.value, State.CONNECTING.value
            ) else State.DOWN.value
        except Exception:
            return State.DOWN.value

    @property
    def has_auto_ca_authentication(self):
        for remote in self.remote.all():
            if isinstance(remote.subclass(), AutoCaAuthentication):
                return True
        return False

    def __str__(self):
        try:
            return json.dumps(self.dict(), indent=4)
        except Exception:
            return self.profile


# ── Connection type subclasses ────────────────────────────────────────────────

class IKEv2Certificate(Connection):
    @classmethod
    def choice_name(cls):
        return "IKEv2 Certificate"


class IKEv2EAP(Connection):
    @classmethod
    def choice_name(cls):
        return "IKEv2 EAP (Username/Password)"


class IKEv2CertificateEAP(Connection):
    @classmethod
    def choice_name(cls):
        return "IKEv2 Certificate + EAP (Username/Password)"


class IKEv2EapTls(Connection):
    @classmethod
    def choice_name(cls):
        return "IKEv2 EAP-TLS (Certificate)"


class IKEv1PSK(Connection):
    @classmethod
    def choice_name(cls):
        return "IKEv1 Pre-Shared Key"


class IKEv1Certificate(Connection):
    @classmethod
    def choice_name(cls):
        return "IKEv1 Certificate"


class IKEv1XauthPSK(Connection):
    @classmethod
    def choice_name(cls):
        return "IKEv1 XAUTH + PSK"


class IKEv1XauthCertificate(Connection):
    @classmethod
    def choice_name(cls):
        return "IKEv1 XAUTH + Certificate"


# ── Cascade cleanup ───────────────────────────────────────────────────────────

@receiver(pre_delete, sender=Connection)
def delete_all_connected_models(sender, instance, **kwargs):
    for child in Child.objects.filter(connection=instance):
        Proposal.objects.filter(child=child).delete()
        Address.objects.filter(local_ts=child).delete()
        Address.objects.filter(remote_ts=child).delete()
        child.delete()
    Proposal.objects.filter(connection=instance).delete()
    Address.objects.filter(local_addresses=instance).delete()
    Address.objects.filter(remote_addresses=instance).delete()
    Address.objects.filter(vips=instance).delete()
    for local in Authentication.objects.filter(local=instance):
        for secret in Secret.objects.filter(authentication=local):
            secret.delete()
        local.delete()
    for remote in Authentication.objects.filter(remote=instance):
        for secret in Secret.objects.filter(authentication=remote):
            secret.delete()
        remote.delete()
