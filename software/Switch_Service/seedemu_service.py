"""DnsSwitch: the installer (build time).

    switch = DnsSwitch()
    emu.addLayer(switch)
    emu.addBinding(Binding(switch.vnode, filter=Filter(asn=150, nodeName="switch")))

One machine hosts a real BIND server with one small zone, plus the one-word
tool the teacher uses to change it. Nothing else in the emulation needs to
know about DNS: the worm and the tool talk to this server by its address.
"""

import json
from pathlib import Path

from seedemu.core import Service
from seedemu.services import DomainNameServer, DomainNameService

from software.Core.staging import HOME, add_command, address_of, stage_tree

RUNTIME_DIR = Path(__file__).resolve().parent / "yom_switch"


class DnsSwitch(Service):
    """A DNS server whose records can be flipped while the emulation runs."""

    def __init__(self, zone: str = "yom.test", vnode: str = "yom-switch", value: str = "127.0.0.1"):
        super().__init__()
        self.zone = zone.rstrip(".") + "."
        self.vnode = vnode
        self.value = value
        self.address = None                 # known once the emulator has rendered
        # seedemu's DNS server does the real work; this object only holds the zone.
        self._zones = DomainNameService(autoNameServer=False)
        self.addDependency("Base", False, False)
        self.install(vnode)

    def name(self, label: str) -> str:
        """The full name of one signal on this switch, e.g. name("stop")."""
        return "{}.{}".format(label, self.zone)

    def _createServer(self):
        server = DomainNameServer()
        server.addZone(self.zone)
        return server

    def _doConfigure(self, node, server):
        server.configure(node, self._zones)

    def _doInstall(self, node, server):
        server.install(node, self._zones)       # BIND, its config and its start command
        self.address = address_of(node)
        stage_tree(node, RUNTIME_DIR, "{}/yom_switch".format(HOME))
        node.setFile(
            "{}/switch.json".format(HOME),
            json.dumps(
                {"server": self.address, "zone": self.zone, "ip": self.value}, indent=2
            ),
        )
        add_command(node, "switch", "yom_switch")
        print(
            "DnsSwitch: the stop-signal server is as{}/{} ({}). Flip it from inside that "
            "machine with:  switch stop | go | status".format(
                node.getAsn(), node.getName(), self.address
            )
        )

    def getName(self) -> str:
        return "DnsSwitch"

    def getConflicts(self) -> list:
        return ["DomainNameService", "DomainNameCachingService"]
