"""Trusted gateway core (owned by teammate A).

Composition (B) creates one ``GatewayService`` with injected runtime
callbacks, an ``Authenticator`` and, for HTTP, ``make_wsgi_app``.
"""

from .auth import Authenticator, BrowserSession, Principal
from .config import DemoIdentity, GatewayConfig, Limits, Retention, RosterEntry
from .runtime_api import ActionExecutor, RuntimeCallbacks, RuntimeUnavailable
from .service import GatewayService

__all__ = [
    "ActionExecutor",
    "Authenticator",
    "BrowserSession",
    "DemoIdentity",
    "GatewayConfig",
    "GatewayService",
    "Limits",
    "Principal",
    "Retention",
    "RosterEntry",
    "RuntimeCallbacks",
    "RuntimeUnavailable",
]
