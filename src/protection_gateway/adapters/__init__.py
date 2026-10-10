"""D-owned entrypoints; core, authentication and runtime are injected by bootstrap."""

from .http import AdapterApp

__all__ = ["AdapterApp"]
