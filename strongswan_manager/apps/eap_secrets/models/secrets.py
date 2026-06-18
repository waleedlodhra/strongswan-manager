from collections import OrderedDict

from django.db import models

from strongswan_manager.helper_apps.encryption import fields


class Secret(models.Model):
    """
    Global shared secret — covers EAP, PSK, and XAUTH credentials.
    Maps to swanctl secrets{} section.
    """

    SECRET_TYPE_CHOICES = (
        ('EAP', 'EAP (username/password)'),
        ('IKE', 'IKE Pre-Shared Key'),
        ('XAUTH', 'XAUTH credential'),
        ('ANY', 'Any (legacy ipsec.secrets)'),
        ('NTLM', 'NTLM'),
    )

    username = models.TextField(unique=True)
    type = models.TextField(choices=SECRET_TYPE_CHOICES, default='EAP')
    password = fields.EncryptedCharField(max_length=50)
    salt = models.TextField()

    # For PSK / XAUTH: optional IP/ID selectors (comma-separated)
    selector_id = models.TextField(blank=True, default='')
    # For PSK: owner IDs (comma-separated) — empty means %any
    owners = models.TextField(blank=True, default='')

    # Source config file (for sync engine)
    source_file = models.CharField(max_length=512, blank=True, default='')

    def dict(self):
        password = self.password[32:]
        if self.type in ('EAP', 'XAUTH', 'NTLM'):
            d = OrderedDict(type=self.type, data=password, owners=[self.username])
        elif self.type in ('IKE', 'ANY'):
            d = OrderedDict(type=self.type, data=password)
            if self.owners:
                d['owners'] = [o.strip() for o in self.owners.split(',') if o.strip()]
            else:
                d['id'] = self.selector_id if self.selector_id else '%any'
        else:
            d = OrderedDict(type=self.type, data=password, owners=[self.username])
        return d

    def __str__(self):
        return f'{self.username} ({self.type})'
