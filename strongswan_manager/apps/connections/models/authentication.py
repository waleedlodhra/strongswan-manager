import sys
from collections import OrderedDict

from django.db import models

from strongswan_manager.apps.certificates.models import UserCertificate, AbstractIdentity, DnIdentity


class Authentication(models.Model):
    local = models.ForeignKey(
        'connections.Connection', null=True, blank=True, default=None,
        related_name='local', on_delete=models.CASCADE,
    )
    remote = models.ForeignKey(
        'connections.Connection', null=True, blank=True, default=None,
        related_name='remote', on_delete=models.CASCADE,
    )
    name = models.TextField()
    auth = models.TextField()
    round = models.IntegerField(default=1)

    @property
    def connection(self):
        return self.local or self.remote

    def dict(self):
        auth = OrderedDict()
        auth[self.name] = OrderedDict(auth=self.auth, round=self.round)
        return auth

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

    def has_private_key(self):
        return False

    def get_key_dict(self):
        return None

    def _get_algorithm_type(self, algorithm):
        if algorithm == 'ec':
            return 'ECDSA'
        elif algorithm == 'rsa':
            return 'RSA'
        raise Exception(f'Unsupported key algorithm: {algorithm}')

    # Provide a safe eap_id default for Secret.dict()
    @property
    def eap_id(self):
        return ''


# ── Existing auth types (unchanged behaviour) ─────────────────────────────────

class CaCertificateAuthentication(Authentication):
    ca_cert = models.ForeignKey(
        UserCertificate, null=True, blank=True, default=None,
        related_name='ca_cert_authentication', on_delete=models.CASCADE,
    )
    ca_identity = models.TextField()

    def dict(self):
        auth = super().dict()
        params = auth[self.name]
        params['cacerts'] = [self.ca_cert.der_container]
        params['id'] = self.ca_identity
        return auth


class AutoCaAuthentication(Authentication):
    ca_identity = models.TextField()

    def dict(self):
        auth = super().dict()
        params = auth[self.name]
        params['cacerts'] = [c.der_container for c in UserCertificate.objects.filter(is_CA=True)]
        params['id'] = self.ca_identity
        return auth


class EapAuthentication(Authentication):
    AUTH_CHOICES = (
        ('eap-radius', 'eap-radius'),
        ('eap-md5', 'eap-md5'),
        ('eap-mschapv2', 'eap-mschapv2'),
        ('eap-ttls', 'eap-ttls'),
        ('eap-peap', 'eap-peap'),
    )
    eap_id = models.TextField()

    def dict(self):
        auth = super().dict()
        auth[self.name]['eap_id'] = self.eap_id
        return auth


class CertificateAuthentication(Authentication):
    identity = models.ForeignKey(
        AbstractIdentity, null=True, blank=True, default=None,
        related_name='cert_identity', on_delete=models.CASCADE,
    )

    def dict(self):
        auth = super().dict()
        values = auth[self.name]
        ident = self.identity.subclass()
        if not isinstance(ident, DnIdentity):
            values['id'] = ident.value()
        values['certs'] = [ident.certificate.der_container]
        return auth

    def has_private_key(self):
        return self.identity.subclass().certificate.subclass().has_private_key

    def get_key_dict(self):
        key = self.identity.subclass().certificate.subclass().private_key
        return OrderedDict(type=self._get_algorithm_type(key.algorithm), data=key.der_container)


class EapTlsAuthentication(Authentication):
    AUTH_CHOICES = (
        ('pubkey', 'pubkey'),
        ('eap-tls', 'eap-tls'),
        ('eap-ttls', 'eap-ttls'),
    )
    REMOTE_AUTH_CHOICES = (
        ('eap-tls', 'eap-tls'),
        ('eap-ttls', 'eap-ttls'),
    )
    remote_auth = models.CharField(max_length=56, choices=REMOTE_AUTH_CHOICES, default='eap-tls')
    eap_id = models.TextField()
    identity = models.ForeignKey(
        AbstractIdentity, null=True, blank=True, default=None,
        related_name='tls_identity', on_delete=models.CASCADE,
    )

    def dict(self):
        auth = super().dict()
        values = auth[self.name]
        ident = self.identity.subclass()
        values['certs'] = [ident.certificate.der_container]
        if not isinstance(ident, DnIdentity):
            values['id'] = ident.value()
        values['eap_id'] = self.eap_id
        return auth

    def has_private_key(self):
        return self.identity.subclass().certificate.subclass().has_private_key

    def get_key_dict(self):
        key = self.identity.subclass().certificate.subclass().private_key
        return OrderedDict(type=self._get_algorithm_type(key.algorithm), data=key.der_container)


# ── New auth types ────────────────────────────────────────────────────────────

class PskAuthentication(Authentication):
    """IKEv1/IKEv2 Pre-Shared Key authentication."""
    psk_id = models.TextField(blank=True, default='')

    def dict(self):
        auth = super().dict()
        if self.psk_id:
            auth[self.name]['id'] = self.psk_id
        return auth


class XauthAuthentication(Authentication):
    """IKEv1 XAUTH (extended authentication) — used on the initiator."""
    xauth_id = models.TextField(blank=True, default='')

    def dict(self):
        auth = super().dict()
        if self.xauth_id:
            auth[self.name]['xauth_id'] = self.xauth_id
        return auth


class EapRadiusAuthentication(Authentication):
    """EAP-RADIUS server-side authentication."""
    eap_id = models.TextField(blank=True, default='')

    def dict(self):
        auth = super().dict()
        if self.eap_id:
            auth[self.name]['eap_id'] = self.eap_id
        return auth
