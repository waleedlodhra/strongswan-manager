"""
Compatibility shim: server_connections models are now unified in connections.
Re-export everything so existing code continues to work.
"""
from strongswan_manager.apps.connections.models import (
    Connection,
    IKEv2Certificate,
    IKEv2EAP,
    IKEv2CertificateEAP,
    IKEv2EapTls,
    Authentication,
    CaCertificateAuthentication,
    AutoCaAuthentication,
    EapAuthentication,
    CertificateAuthentication,
    EapTlsAuthentication,
    PskAuthentication,
    XauthAuthentication,
    Child,
    Address,
    Proposal,
    Secret,
    LogMessage,
)

__all__ = [
    'Connection', 'IKEv2Certificate', 'IKEv2EAP', 'IKEv2CertificateEAP',
    'IKEv2EapTls', 'Authentication', 'CaCertificateAuthentication',
    'AutoCaAuthentication', 'EapAuthentication', 'CertificateAuthentication',
    'EapTlsAuthentication', 'PskAuthentication', 'XauthAuthentication',
    'Child', 'Address', 'Proposal', 'Secret', 'LogMessage',
]
