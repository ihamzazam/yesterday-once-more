"""DnsSwitch: the installer (build time).

    switch = DnsSwitch()
    emu.addLayer(switch)
    emu.addBinding(Binding(switch.vnode, filter=Filter(asn=150, nodeName="switch")))

    worm = Worm(..., governor=DnsKillSwitch(switch.kill_switch))

One machine plays the internet for one nonsense domain. It runs a real BIND
server (seedemu's own DNS service) for the zone, a small web answer, and the
one-word tool the teacher uses. Nothing else in the emulation needs to know
about DNS: the worm asks this server by its address.
"""

import json
from pathlib import Path

from seedemu.core import Service
from seedemu.services import DomainNameServer, DomainNameService

from software.Core.staging import HOME, add_command, address_of, stage_tree

RUNTIME_DIR = Path(__file__).resolve().parent / "yom_switch"

#: The domain the real WannaCry tried to load over HTTP before it went to
#: work. A researcher registered it during the outbreak, which stopped the
#: spread. In the lab this server is the only one that ever answers for it.
KILL_SWITCH = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"


class DnsSwitch(Service):
    """A kill-switch domain that can be registered and unregistered while the lab runs."""

    def __init__(self, domain: str = KILL_SWITCH, vnode: str = "yom-switch", http_port: int = 80):
        super().__init__()
        self.domain = domain                        # what the worm tries to load
        self.zone = domain.split(".", 1)[1] + "."   # the registered domain, e.g. "example.com."
        self.vnode = vnode
        self.http_port = http_port
        self.address = None                         # known once the emulator has rendered
        # seedemu's DNS server does the real work; this object only holds the zone.
        self._zones = DomainNameService(autoNameServer=False)
        self.addDependency("Base", False, False)
        self.install(vnode)

    def kill_switch(self) -> str:
        """The domain a WannaCry-style worm has to check."""
        return self.domain

    def name(self, label: str) -> str:
        """Another name in the same zone, e.g. name("pause")."""
        return "{}.{}".format(label, self.zone)

    def _createServer(self):
        server = DomainNameServer()
        server.addZone(self.zone)
        return server

    def _doConfigure(self, node, server):
        server.configure(node, self._zones)

    def _doInstall(self, node, server):
        server.install(node, self._zones)           # BIND, its config and its start command
        self.address = address_of(node)
        stage_tree(node, RUNTIME_DIR, "{}/yom_switch".format(HOME))
        node.setFile(
            "{}/switch.json".format(HOME),
            json.dumps(
                {"server": self.address, "zone": self.zone, "ip": self.address,
                 "domain": self.domain, "port": 53, "http_port": self.http_port},
                indent=2,
            ),
        )
        add_command(node, "switch", "yom_switch")
        # The web answer: always up, but reached only once the domain is registered.
        node.appendStartCommand(
            "PYTHONPATH={} python3 -m yom_switch.responder {} > /tmp/yom-responder.log 2>&1".format(
                HOME, self.http_port
            ),
            fork=True,
        )
        print(
            "DnsSwitch: the kill-switch domain {} is served by as{}/{} ({}). From inside that "
            "machine:  switch stop | go | status".format(
                self.domain, node.getAsn(), node.getName(), self.address
            )
        )

    def render(self, emulator):
        super().render(emulator)
        # Every machine in the lab asks this one for names, as machines ask
        # their network's DNS server. So a student can see on any machine that
        # the domain does not exist, and later that it does.
        mine = emulator.getBindingFor(self.vnode)
        scope, kind, _ = mine.getRegistryInfo()
        for node in [mine] + list(emulator.getRegistry().getByType(scope, kind)):
            server = "127.0.0.1" if node is mine else self.address
            # The two start commands seedemu writes for a node's name servers.
            # They are added here because seedemu writes them while it prepares
            # the machines, which is before this switch knows its own address.
            node.insertStartCommand(0, ": > /etc/resolv.conf")
            node.insertStartCommand(1, 'echo "nameserver {}" >> /etc/resolv.conf'.format(server))

    def getName(self) -> str:
        return "DnsSwitch"

    def getConflicts(self) -> list:
        return ["DomainNameService", "DomainNameCachingService"]
