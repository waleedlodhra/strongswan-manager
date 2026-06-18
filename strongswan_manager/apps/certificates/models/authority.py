"""
Certificate Authority configuration (swanctl authorities{} section).
"""
from django.db import models


class Authority(models.Model):
    """Represents a trusted CA and associated revocation/OCSP endpoints."""

    name = models.TextField(unique=True)

    # Path or file reference for the CA certificate.
    # Actual cert data stored in UserCertificate; this is the swanctl name/path.
    cacert = models.TextField(blank=True, default='')
    cacert_ref = models.ForeignKey(
        'certificates.UserCertificate',
        null=True, blank=True, default=None,
        related_name='authority_configs',
        on_delete=models.SET_NULL,
    )

    # Comma-separated CRL URIs
    crl_uris = models.TextField(blank=True, default='')
    # Comma-separated OCSP URIs
    ocsp_uris = models.TextField(blank=True, default='')
    # Base URI for fetching certs
    cert_uri_base = models.TextField(blank=True, default='')

    # Source config file (for sync engine)
    source_file = models.CharField(max_length=512, blank=True, default='')

    def dict(self):
        """Return VICI-compatible dict for load_authority."""
        from collections import OrderedDict
        d = OrderedDict()
        if self.cacert_ref:
            d['cacert'] = self.cacert_ref.der_container
        elif self.cacert:
            d['cacert'] = self.cacert
        if self.crl_uris:
            d['crl_uris'] = [u.strip() for u in self.crl_uris.split(',') if u.strip()]
        if self.ocsp_uris:
            d['ocsp_uris'] = [u.strip() for u in self.ocsp_uris.split(',') if u.strip()]
        if self.cert_uri_base:
            d['cert_uri_base'] = self.cert_uri_base
        return {self.name: d}

    def __str__(self):
        return self.name
