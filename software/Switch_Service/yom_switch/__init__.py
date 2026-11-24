"""The stop signal. This package travels inside the worm body (the reader)."""

from .reader import DnsKillSwitch, SwitchUnreachable

__all__ = ["DnsKillSwitch", "SwitchUnreachable"]
