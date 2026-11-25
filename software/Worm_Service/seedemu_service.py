"""Worm: the installer (build time).

    worm = Worm(entry=bof.exploit(), governor=DnsKillSwitch(switch.name("stop")))
    emu.addLayer(worm)
    worm.launch_from("patient-zero")

This half looks at the rest of the emulation and fills in what the case
should not have to type:

  - who to attack: every machine that has the hole this break-in fits;
  - where the stop-signal server is, if the worm has a stop signal.

It then puts the worm on the launcher's machine: the code of every part, the
settings file, and the one-word `worm` command. Nothing is put on the victims;
the worm reaches them by itself.
"""

import json
from pathlib import Path

from seedemu.core import Server, Service

from software.Core.staging import HOME, RUNTIME_NEEDS, add_command, address_of, runtime_dir, stage_tree
from software.Switch_Service import DnsSwitch
from software.Vulnerable_Server import VulnerableServer
from software.Worm_Service.yom_worm import builtin
from software.Worm_Service.yom_worm.spec import WormPlan, describe

RUNTIME_DIR = Path(__file__).resolve().parent / "yom_worm"

#: What any target needs before the body can run there. The installer adds it
#: to every target, so a victim can never again be missing it.
BODY_NEEDS = RUNTIME_NEEDS


class Launcher(Server):
    """The worm on the machine where the outbreak starts."""

    def __init__(self, service):
        super().__init__()
        self.service = service

    def install(self, node):
        self.service._install_launcher(node)

    def print(self, indent: int) -> str:
        return " " * indent + "Worm launcher\n"


class Worm(WormPlan, Service):
    """The worm as a seedemu service: four slots, started from one machine."""

    def __init__(self, scanner=None, entry=None, payload=None, governor=None,
                 pace=None, autostart=False):
        WormPlan.__init__(self, scanner, entry, payload, governor, pace)
        Service.__init__(self)
        self.autostart = autostart     # False: a person runs `worm launch`
        self.addDependency("Base", False, False)
        # Render after the pieces we look for, when they are in the emulation at all.
        self.addDependency("VulnerableServer", False, True)
        self.addDependency("DnsSwitch", False, True)
        # A part may need a layer of its own to be installed first (the
        # ransomware needs its payment chain before anything is written down).
        for part in self.parts:
            layer = getattr(type(part), "NEEDS_LAYER", None) if part is not None else None
            if layer:
                self.addDependency(layer, False, True)

    def launch_from(self, vnode):
        """The machine where the outbreak starts (patient zero)."""
        return self.install(vnode)

    def getName(self) -> str:
        return "WormService"

    def print(self, indent: int) -> str:
        out = " " * indent + "Worm:\n"
        for slot, part in zip(("scanner", "entry", "payload", "governor"), self.parts):
            out += " " * (indent + 4) + "{}: {}\n".format(
                slot, type(part).__name__ if part is not None else "none"
            )
        return out

    def _createServer(self) -> Server:
        return Launcher(self)

    def render(self, emulator):
        self._fill_targets(emulator)
        self._fill_switch(emulator)
        super().render(emulator)

    def _fill_targets(self, emulator):
        """Aim the worm at every machine that has the hole this break-in fits."""
        wanted = getattr(type(self.entry), "TARGETS", None)
        if wanted is None:
            return                 # this break-in is not tied to a hole: the case lists targets
        targets = []
        for layer in emulator.getLayers():
            if isinstance(layer, VulnerableServer):
                for server, node in layer.getTargets():
                    if server.vulnerability.name == wanted:
                        targets.append(node)
        if not targets:
            raise ValueError(
                "the worm's break-in fits the hole '{}', but no machine has it installed; "
                "install it with VulnerableServer(...) first".format(wanted)
            )
        for node in targets:
            self._provide(node)
        if isinstance(self.scanner, builtin.ShuffleScanner) and not self.scanner.targets:
            self.scanner.targets = [address_of(node) for node in targets]

    def _provide(self, node):
        """Give a machine everything the body needs to run there.

        The worm needs Python. A carried part may need more (the ransomware
        needs its crypto libraries), and says so with TARGET_NEEDS and
        TARGET_BUILD on its class.
        """
        software, build = list(BODY_NEEDS), []
        for part in self.parts:
            if part is None:
                continue
            for name in getattr(type(part), "TARGET_NEEDS", ()):
                if name not in software:
                    software.append(name)
            for command in getattr(type(part), "TARGET_BUILD", ()):
                if command not in build:
                    build.append(command)
        for name in software:
            node.addSoftware(name)
        for command in build:
            node.addBuildCommand(command)

    def _fill_switch(self, emulator):
        """Tell the stop signal where its server is."""
        governor = self.governor
        if governor is None or getattr(governor, "server", None) is not None:
            return
        switches = [layer for layer in emulator.getLayers() if isinstance(layer, DnsSwitch)]
        if len(switches) != 1:
            raise ValueError(
                "the worm's stop signal needs exactly one DnsSwitch in the emulation (found {})"
                .format(len(switches))
            )
        switch = switches[0]
        domain = governor.domain.rstrip(".") + "."
        if not domain.endswith(switch.zone):
            raise ValueError(
                "'{}' is not a name in the switch's zone '{}'".format(domain, switch.zone)
            )
        governor.server = switch.address

    def _install_launcher(self, node):
        packages = []
        for part in self.parts:
            if part is None:
                continue
            folder = runtime_dir(type(part))
            if folder != RUNTIME_DIR and folder.name not in packages:
                packages.append(folder.name)
                stage_tree(node, folder, "{}/{}".format(HOME, folder.name))
            stage = getattr(part, "stage", None)
            if stage:
                stage(node)            # what the part needs on the launcher (tools, a probe program...)
        stage_tree(node, RUNTIME_DIR, "{}/yom_worm".format(HOME))
        self._provide(node)
        node.setFile(
            "{}/worm.json".format(HOME), json.dumps(self.manifest(packages), indent=2) + "\n"
        )
        add_command(node, "worm", "yom_worm")
        if self.autostart:
            node.appendStartCommand("worm launch", fork=True)
