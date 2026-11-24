"""Containment: attack code acts only on lab IPs and marked lab folders.

The allowed IP prefixes are injected at build time (``core.install`` writes the
emulator's own network prefixes into ``guard.json``). A folder counts as a lab
folder only if it, or one of its parents, holds the marker file (``.yom-lab``)
that ``core.files.place_files`` / a service drops at build time.

Nothing here can be overridden at run time: a runtime with no guard settings
refuses everything.
"""

import ipaddress
import os
from pathlib import Path

from software.core import settings

MARKER = ".yom-lab"


class ContainmentError(PermissionError):
    pass


class Guard:
    def __init__(self, prefixes=(), marker: str = MARKER):
        self.networks = [ipaddress.ip_network(p, strict=False) for p in prefixes]
        self.marker = marker

    # ---- network --------------------------------------------------------
    def ip_allowed(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in net for net in self.networks)

    def require_ip(self, ip: str) -> str:
        if not self.ip_allowed(ip):
            raise ContainmentError(f"{ip} is outside the lab prefixes {self.prefixes()}")
        return ip

    def prefixes(self):
        return [str(n) for n in self.networks]

    # ---- filesystem -----------------------------------------------------
    def folder_allowed(self, path) -> bool:
        path = Path(os.path.realpath(path))
        for candidate in (path, *path.parents):
            if (candidate / self.marker).is_file():
                return True
        return False

    def require_folder(self, path) -> Path:
        if not self.folder_allowed(path):
            raise ContainmentError(
                f"{path} is not a marked lab folder (no {self.marker} in it or above it)"
            )
        return Path(path)


def load(base: Path = None) -> Guard:
    """The guard for this host. Missing settings = allow nothing."""
    if not settings.exists("guard", base):
        return Guard(())
    cfg = settings.load("guard", base)
    return Guard(cfg.get("prefixes", ()), cfg.get("marker", MARKER))
