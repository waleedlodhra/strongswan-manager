"""
Typed exceptions for the VICI service layer.
"""


class ViciError(Exception):
    """Base exception for all VICI service errors."""


class ViciUnavailable(ViciError):
    """Raised when the VICI socket is not reachable (charon is down/not running)."""


class ViciLoadError(ViciError):
    """Raised when a load_* command fails."""


class ViciOperationError(ViciError):
    """Raised when an operational command (initiate, terminate, rekey, redirect) fails."""


class ViciAuthenticationError(ViciError):
    """Raised when credentials/certificate cannot be loaded."""
