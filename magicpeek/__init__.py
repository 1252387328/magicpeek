"""Public interface for magicpeek."""

from .core import KIND_EXTENSIONS, MagicpeekError, Record, Sniff, audit, scan, sniff

__version__ = "0.1.0"
__all__ = ["KIND_EXTENSIONS", "MagicpeekError", "Record", "Sniff", "audit", "scan", "sniff"]
