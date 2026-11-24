#!/usr/bin/env python3
"""The smallest worm lab: three victims, one attacker, one stop signal.

Nothing is carried yet. This is the Morris picture, and it shows three of the
pieces working on their own: the hole, the worm, and the switch.

Build and start (from this folder). The project name keeps this lab apart from
anything else built in a folder called `output`:

    ../../../.venv/bin/python morris_picture.py          build ./output
    cd output && docker compose -p yom-morris up -d --build    the first build takes a while

Run (the hole needs ASLR off on the Docker host; the worm says so otherwise):

    docker compose -p yom-morris exec hnode_158_attacker worm launch    start the outbreak
    docker compose -p yom-morris logs hnode_158_attacker                watch it spread
    docker compose -p yom-morris exec hnode_158_switch switch stop      every worm stops
    docker compose -p yom-morris exec hnode_158_switch switch go        they may spread again
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from seedemu import Base, Emulator, Routing  # noqa: E402
from seedemu.compiler import Docker  # noqa: E402
from seedemu.core import Binding, Filter  # noqa: E402

from software.Switch_Service import DnsKillSwitch, DnsSwitch  # noqa: E402
from software.Vulnerable_Server import MorrisBufferOverflow, VulnerableServer  # noqa: E402
from software.Worm_Service import Worm  # noqa: E402

ASN = 158                                   # change it if another lab uses this number
VICTIMS = ["victim1", "victim2", "victim3"]


def build():
    emu = Emulator()
    base = Base()
    lab = base.createAutonomousSystem(ASN)
    lab.createNetwork("net0")
    lab.createRouter("router0").joinNetwork("net0")
    for name in VICTIMS + ["attacker", "switch"]:
        lab.createHost(name).joinNetwork("net0")
    emu.addLayer(base)
    emu.addLayer(Routing())

    def place(vnode, name):
        emu.addBinding(Binding(vnode, filter=Filter(asn=ASN, nodeName=name)))

    # The switch: one machine with the stop signal on it.
    switch = DnsSwitch()
    emu.addLayer(switch)
    place(switch.vnode, "switch")

    # The hole: one vulnerability, on as many machines as we like.
    bof = MorrisBufferOverflow()
    victims = VulnerableServer(bof)
    emu.addLayer(victims)
    for name in VICTIMS:
        victims.install("vuln-" + name)
        place("vuln-" + name, name)

    # The worm: its break-in comes from the same box as the hole, so they match.
    worm = Worm(entry=bof.exploit(), governor=DnsKillSwitch(switch.name("stop")))
    emu.addLayer(worm)
    worm.launch_from("patient-zero")
    place("patient-zero", "attacker")

    emu.render()
    output = Path(__file__).resolve().parent / "output"
    emu.compile(Docker(), str(output), override=True)
    print("Docker configuration written to {}".format(output))


if __name__ == "__main__":
    build()
