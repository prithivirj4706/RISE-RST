"""Platform adapters: OS detection plus the per-platform rule sets."""

from .detector import SUPPORTED, DetectionError, detect

__all__ = ["detect", "DetectionError", "SUPPORTED"]
