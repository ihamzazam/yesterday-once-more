"""Build time: a kill-switch domain that can be switched on and off at run time.

    sinkhole = Sinkhole(domain="kill.example.com").attachTo(emu, asn=151)

Adds, in the given AS: a ``sinkhole`` host with the web responder, and DNS for
the domain through seedemu's own DNS layers.

  * network already has a DomainNameService: the domain's zone is added to it
    (hosted on the sinkhole host's DNS companion ``sinkdns``).
  * network has no DNS: a minimal one is created: root + TLD + the domain's
    zone on ``sinkdns``, and a local resolver (``sinkresolver``) that every
    node in the emulation is pointed at.

The web responder starts ON by default (``initial="on"``): the domain answers,
a worm that checks it stops. ``yom-sinkhole off`` on the sinkhole host makes it
silent again. The worm side (``DomainKillSwitch``) only needs ``.domain``.
"""

import re

from seedemu.core import Binding, Filter, Server, Service
from seedemu.layers import Base
from seedemu.services import DomainNameCachingService, DomainNameService

from software.core import install

PORT = 80
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
LAUNCHERS = {"yom-sinkhole": "software.sinkhole.runtime.responder"}


class Sinkhole:
    def __init__(self, domain: str, initial: str = "on", port: int = PORT, prefix: str = ""):
        domain = domain.strip().rstrip(".").lower()
        if not DOMAIN_RE.match(domain):
            raise ValueError(f"not a usable domain name: {domain!r}")
        if initial not in ("on", "off"):
            raise ValueError("initial is 'on' or 'off'")
        self.domain = domain
        self.initial = initial
        self.port = port
        self.prefix = prefix
        self._attached = False
        self._web = None

    # ---- topology -------------------------------------------------------------
    def _name(self, role: str) -> str:
        return f"{self.prefix}{role}"

    def attachTo(self, emu, asn: int, network: str = "net0"):
        if self._attached:
            raise ValueError("this Sinkhole is already attached")
        lab_as = emu.getLayer("Base").getAutonomousSystem(asn)
        web, dnsname = self._name("sinkhole"), self._name("sinkdns")
        for name in (web, dnsname):
            lab_as.createHost(name).joinNetwork(network)
            emu.addBinding(Binding(name, filter=Filter(asn=asn, nodeName=name)))
        self._web = web

        existing = _find_layer(emu, "DomainNameService")
        dns = existing or DomainNameService()
        tld = self.domain.rsplit(".", 1)[1]
        servers = {}
        if existing is None:
            # Minimal DNS: root, TLD and the domain's zone all on sinkdns,
            # plus a local resolver. One host serving three zones is enough
            # for a lab and keeps the footprint to two extra nodes.
            resolver = self._name("sinkresolver")
            lab_as.createHost(resolver).joinNetwork(network)
            emu.addBinding(Binding(resolver, filter=Filter(asn=asn, nodeName=resolver)))
            server = dns.install(dnsname)
            for zone in (".", f"{tld}.", f"{self.domain}."):
                server.addZone(zone)
            server.setMaster()
            caching = DomainNameCachingService()
            caching.install(resolver)
            emu.addLayer(dns)
            emu.addLayer(caching)
        else:
            dns.install(dnsname).addZone(f"{self.domain}.").setMaster()
        dns.getZone(f"{self.domain}.").resolveToVnode("@", web)
        service = _SinkholeService(self)
        service.install(web)      # a seedemu Server on the vnode, so DNS can resolve it
        emu.addLayer(service)
        self._attached = True
        return self

    # ---- packages -------------------------------------------------------------
    def settings(self, emulator=None) -> dict:
        return {"domain": self.domain, "port": self.port, "initial": self.initial}

    def package(self):
        return install.package("sinkhole", ["sinkhole"], settings={"sinkhole": self.settings},
                               launchers=LAUNCHERS, start="yom-sinkhole run")


def _find_layer(emu, name: str):
    try:
        return emu.getLayer(name)
    except Exception:  # noqa: BLE001 - seedemu asserts when the layer is missing
        return None


class _SinkholeServer(Server):
    def __init__(self, sinkhole: Sinkhole):
        super().__init__()
        self.sinkhole = sinkhole
        self.emulator = None

    def install(self, node):
        install.install_package(self.emulator, node, self.sinkhole.package())


class _SinkholeService(Service):
    """Registers the web vnode with seedemu (needed for DNS vnode resolution)."""

    def __init__(self, sinkhole: Sinkhole):
        super().__init__()
        self.sinkhole = sinkhole
        self.addDependency("Base", False, False)

    def getName(self) -> str:
        return "Sinkhole"

    def _createServer(self) -> Server:
        return _SinkholeServer(self.sinkhole)

    def render(self, emulator):
        for server, _ in self.getTargets():
            server.emulator = emulator
        super().render(emulator)
