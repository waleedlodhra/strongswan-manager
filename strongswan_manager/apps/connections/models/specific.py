from collections import OrderedDict

from django.db import models
from django.dispatch import receiver

from strongswan_manager.apps.certificates.models import UserCertificate, CertificateDoNotDelete, PrivateKey
from strongswan_manager.helper_apps.encryption import fields
from .authentication import Authentication
from .common import CertConDoNotDeleteMessage, KeyConDoNotDeleteMessage


@receiver(UserCertificate.should_prevent_delete_signal, sender=UserCertificate)
def prevent_cert_delete_if_cert_is_in_use(sender, **kwargs):
    cert = kwargs['instance']
    auths = (
        [i.tls_identity for i in cert.identities]
        + [i.cert_identity for i in cert.identities]
        + [cert.ca_cert_authentication]
    )
    for auth in auths:
        if auth.count() > 0:
            raise CertificateDoNotDelete(CertConDoNotDeleteMessage(auth.first().connection))
    return False, ""


@receiver(PrivateKey.should_prevent_delete_signal, sender=PrivateKey)
def prevent_key_delete_if_cert_is_in_use(sender, **kwargs):
    cert = kwargs['usercertificate']
    auths = (
        [i.tls_identity for i in cert.identities]
        + [i.cert_identity for i in cert.identities]
    )
    for auth in auths:
        if auth.count() > 0:
            raise CertificateDoNotDelete(KeyConDoNotDeleteMessage(auth.first().connection))
    return False, ""


class Child(models.Model):
    """Child SA — represents a single IPsec CHILD_SA configuration."""

    MODE_CHOICES = (
        ('tunnel', 'Tunnel'),
        ('transport', 'Transport'),
        ('beet', 'BEET'),
    )
    START_ACTION_CHOICES = (
        ('', 'none'),
        ('start', 'start'),
        ('trap', 'trap'),
    )
    CLOSE_ACTION_CHOICES = (
        ('', 'none'),
        ('none', 'none'),
        ('clear', 'clear'),
        ('hold', 'hold'),
        ('restart', 'restart'),
    )
    DPD_ACTION_CHOICES = (
        ('', 'none'),
        ('none', 'none'),
        ('clear', 'clear'),
        ('hold', 'hold'),
        ('restart', 'restart'),
    )
    HW_OFFLOAD_CHOICES = (
        ('no', 'no'),
        ('yes', 'yes'),
        ('auto', 'auto'),
        ('packet', 'packet'),
    )

    name = models.TextField()
    mode = models.CharField(max_length=10, choices=MODE_CHOICES, default='tunnel')
    connection = models.ForeignKey(
        'connections.Connection',
        null=True, blank=True, default=None,
        related_name='children',
        on_delete=models.CASCADE,
    )

    # Actions
    start_action = models.CharField(
        max_length=5, choices=START_ACTION_CHOICES, null=True, blank=True, default=None
    )
    close_action = models.CharField(
        max_length=10, choices=CLOSE_ACTION_CHOICES, blank=True, default=''
    )
    dpd_action = models.CharField(
        max_length=10, choices=DPD_ACTION_CHOICES, blank=True, default=''
    )

    # Timers
    rekey_time = models.CharField(max_length=20, blank=True, default='')
    life_time = models.CharField(max_length=20, blank=True, default='')
    rand_time = models.CharField(max_length=20, blank=True, default='')
    inactivity = models.CharField(max_length=20, blank=True, default='')

    # Marks / XFRM
    mark_in = models.CharField(max_length=20, blank=True, default='')
    mark_out = models.CharField(max_length=20, blank=True, default='')
    if_id_in = models.CharField(max_length=20, blank=True, default='')
    if_id_out = models.CharField(max_length=20, blank=True, default='')

    # Traffic processing
    copy_df = models.BooleanField(null=True, blank=True, default=None)
    copy_dscp = models.CharField(max_length=10, blank=True, default='')
    tfc_padding = models.CharField(max_length=20, blank=True, default='')
    hw_offload = models.CharField(
        max_length=10, choices=HW_OFFLOAD_CHOICES, blank=True, default='no'
    )

    # Routing
    priority = models.IntegerField(null=True, blank=True, default=None)
    interface = models.CharField(max_length=64, blank=True, default='')

    # Up/down script
    updown = models.CharField(max_length=512, blank=True, default='')

    def dict(self):
        child = OrderedDict()
        local_ts = [t.value for t in self.local_ts.all() if t.value]
        if local_ts:
            child['local_ts'] = local_ts
        remote_ts = [t.value for t in self.remote_ts.all() if t.value]
        if remote_ts:
            child['remote_ts'] = remote_ts
        esp_proposals = [p.type for p in self.esp_proposals.all() if p.type]
        if esp_proposals:
            child['esp_proposals'] = esp_proposals
        ah_proposals = [p.type for p in self.ah_proposals.all() if p.type]
        if ah_proposals:
            child['ah_proposals'] = ah_proposals
        if self.mode and self.mode != 'tunnel':
            child['mode'] = self.mode
        if self.start_action:
            child['start_action'] = self.start_action
        if self.close_action:
            child['close_action'] = self.close_action
        if self.dpd_action:
            child['dpd_action'] = self.dpd_action
        if self.rekey_time:
            child['rekey_time'] = self.rekey_time
        if self.life_time:
            child['life_time'] = self.life_time
        if self.rand_time:
            child['rand_time'] = self.rand_time
        if self.inactivity:
            child['inactivity'] = self.inactivity
        if self.mark_in:
            child['mark_in'] = self.mark_in
        if self.mark_out:
            child['mark_out'] = self.mark_out
        if self.if_id_in:
            child['if_id_in'] = self.if_id_in
        if self.if_id_out:
            child['if_id_out'] = self.if_id_out
        if self.copy_df is not None:
            child['copy_df'] = 'yes' if self.copy_df else 'no'
        if self.copy_dscp:
            child['copy_dscp'] = self.copy_dscp
        if self.tfc_padding:
            child['tfc_padding'] = self.tfc_padding
        if self.hw_offload and self.hw_offload != 'no':
            child['hw_offload'] = self.hw_offload
        if self.priority is not None:
            child['priority'] = self.priority
        if self.interface:
            child['interface'] = self.interface
        if self.updown:
            child['updown'] = self.updown
        return child


class Address(models.Model):
    value = models.TextField()
    local_ts = models.ForeignKey(
        Child, null=True, blank=True, default=None,
        related_name='local_ts', on_delete=models.CASCADE,
    )
    remote_ts = models.ForeignKey(
        Child, null=True, blank=True, default=None,
        related_name='remote_ts', on_delete=models.CASCADE,
    )
    remote_addresses = models.ForeignKey(
        'connections.Connection', null=True, blank=True, default=None,
        related_name='remote_addresses', on_delete=models.CASCADE,
    )
    local_addresses = models.ForeignKey(
        'connections.Connection', null=True, blank=True, default=None,
        related_name='local_addresses', on_delete=models.CASCADE,
    )
    vips = models.ForeignKey(
        'connections.Connection', null=True, blank=True, default=None,
        related_name='vips', on_delete=models.CASCADE,
    )


class Proposal(models.Model):
    type = models.TextField()
    child = models.ForeignKey(
        Child, null=True, blank=True, default=None,
        related_name='esp_proposals', on_delete=models.CASCADE,
    )
    ah_child = models.ForeignKey(
        Child, null=True, blank=True, default=None,
        related_name='ah_proposals', on_delete=models.CASCADE,
    )
    connection = models.ForeignKey(
        'connections.Connection', null=True, blank=True, default=None,
        related_name='proposals', on_delete=models.CASCADE,
    )


class Secret(models.Model):
    """Per-connection EAP/XAUTH secret (auth-level)."""
    type = models.TextField()
    data = fields.EncryptedCharField(max_length=50)
    authentication = models.ForeignKey(
        Authentication, null=True, blank=True, default=None,
        related_name='authentication', on_delete=models.CASCADE,
    )

    def dict(self):
        eap_id = self.authentication.subclass().eap_id
        return OrderedDict(type=self.type, data=self.data, id=eap_id)


class LogMessage(models.Model):
    connection = models.ForeignKey(
        'connections.Connection', null=True, blank=True, default=None,
        on_delete=models.CASCADE,
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
