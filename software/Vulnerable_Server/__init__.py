"""Vulnerable_Server: the hole on the victim's side, as a menu of vulnerabilities.

    from software.Vulnerable_Server import MorrisBufferOverflow, VulnerableServer
"""

from .seedemu_service import VulnerableServer
from .vulnerabilities import MorrisBufferOverflow

__all__ = ["MorrisBufferOverflow", "VulnerableServer"]
