"""Vulnerable_Server: the installer (build time).

    bof = MorrisBufferOverflow()          one vulnerability: the hole and its break-in
    victims = VulnerableServer(bof)       puts the hole on machines
    victims.install("vuln-1")             ...one virtual node per machine

A case picks a vulnerability from the catalogue (see vulnerabilities/) and
installs it on as many machines as it likes. The matching break-in is never
written by the case; the Worm takes it from the same object (bof.exploit()).
"""

from seedemu.core import Server, Service


class VulnerableHost(Server):
    """One installation on ONE machine."""

    def __init__(self, vulnerability):
        super().__init__()
        self.vulnerability = vulnerability

    def use(self, vulnerability) -> "VulnerableHost":
        """Give this one machine a different hole than the others."""
        self.vulnerability = vulnerability
        return self

    def install(self, node):
        self.vulnerability.install(node)
        # Tell the rest of the emulation what this machine now has, the way
        # seedemu's own BotnetService publishes its server address.
        node.setAttribute("yom_vulnerability", self.vulnerability.name)

    def print(self, indent: int) -> str:
        return " " * indent + "Vulnerable host ({})\n".format(self.vulnerability.name)


class VulnerableServer(Service):
    """The catalogue as a seedemu service: install a vulnerability on machines."""

    def __init__(self, *vulnerabilities):
        super().__init__()
        if not vulnerabilities:
            raise ValueError("choose a vulnerability, for example VulnerableServer(MorrisBufferOverflow())")
        self.vulnerabilities = list(vulnerabilities)
        self.addDependency("Base", False, False)

    def _createServer(self) -> Server:
        return VulnerableHost(self.vulnerabilities[0])

    def render(self, emulator):
        for vulnerability in self.vulnerabilities:
            for problem in vulnerability.check_host():
                print("WARNING: " + problem)
        super().render(emulator)

    def getName(self) -> str:
        return "VulnerableServer"
