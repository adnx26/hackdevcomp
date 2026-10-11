"""Design C worker entrypoints. Requires A's contracts and B's restricted runtime."""
from .extraction import extract
from .inspection import inspect

__all__ = ['extract', 'inspect']
