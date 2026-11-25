#!/usr/bin/env python3
"""WannaCry on the architecture: the worm carries the ransomware.

The whole picture in one lab. Three victims have documents; the worm breaks in
through the buffer overflow and locks them; the victim pays on the payment
chain and gets the key back; the teacher can stop the worm with the switch.

Build and start (from this folder):

    ../../../.venv/bin/python wannacry.py                 build ./output-wannacry
    cd output-wannacry
    docker compose -p yom-wannacry up -d --build          the first build takes a while
    docker compose -p yom-wannacry logs -f ransom-utility  wait for "Contract deployed"

The hole needs ASLR off on the Docker host (switch it off before the lab
starts, or the vulnerable server waits for it).

Run:

    docker compose -p yom-wannacry exec -d hnode_159_attacker sh -c 'worm launch > /tmp/worm.out 2>&1'
    docker compose -p yom-wannacry logs hnode_159_victim1          watch it arrive and lock

On a victim, open the menu the worm left behind and follow it (wallet,
exchange, pay, receive the key, decrypt):

    docker compose -p yom-wannacry exec -it hnode_159_victim1 ransom

The attacker answers paid requests (do this while the victim waits):

    docker compose -p yom-wannacry exec hnode_159_attacker ransom watch
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from chainseed.compiler import ChainSeedDocker  # noqa: E402
from seedemu import Base, Emulator, Routing  # noqa: E402
from seedemu.compiler import Platform  # noqa: E402
from seedemu.core import Binding, Filter  # noqa: E402

from software.Ransomware_Service import Ransomware  # noqa: E402
from software.Switch_Service import DnsKillSwitch, DnsSwitch  # noqa: E402
from software.Vulnerable_Server import MorrisBufferOverflow, VulnerableServer  # noqa: E402
from software.Worm_Service import Worm  # noqa: E402

ASN = 159                                   # change it if another lab uses this number
VICTIMS = ["victim1", "victim2", "victim3"]

# The story: the documents each victim has before anything happens.
DOCUMENTS = {
    "notes.txt": "Team handover notes\nPrepare the weekly report on Friday.\n"
                 "The next team meeting is on Monday.\n",
    "budget.csv": "department,allocated,spent\noperations,12000,9500\nit,8000,6200\n",
    "report.md": "# Monthly report\n\nThe team completed three training sessions this month.\n",
    "contacts.csv": "name,team,extension\nAlex,Operations,4101\nSam,IT,4102\n",
    "minutes.txt": "Meeting minutes\n1. Review the training schedule.\n"
                   "2. Prepare next month's equipment list.\n",
}
DOCUMENTS_DIR = "/home/seed/Documents"


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

    for name in VICTIMS:
        for document, text in DOCUMENTS.items():
            lab.getHost(name).setFile(f"{DOCUMENTS_DIR}/{document}", text)

    # The switch: one machine with the stop signal on it.
    switch = DnsSwitch()
    emu.addLayer(switch)
    place(switch.vnode, "switch")

    # The ransomware: its payment chain comes with it.
    ransom = Ransomware(in_as=lab, on_network="net0", documents=DOCUMENTS_DIR)
    emu.addLayer(ransom)
    for binding in ransom.bindings:
        emu.addBinding(binding)

    # The hole: one vulnerability, on as many machines as we like.
    bof = MorrisBufferOverflow()
    victims = VulnerableServer(bof)
    emu.addLayer(victims)
    for name in VICTIMS:
        victims.install("vuln-" + name)
        place("vuln-" + name, name)

    # The worm: its break-in comes from the hole, and it carries the ransomware.
    worm = Worm(entry=bof.exploit(), payload=ransom.payload,
                governor=DnsKillSwitch(switch.name("stop")))
    emu.addLayer(worm)
    worm.launch_from("patient-zero")
    place("patient-zero", "attacker")

    emu.render()
    output = Path(__file__).resolve().parent / "output-wannacry"
    emu.compile(ChainSeedDocker(platform=Platform.AMD64), str(output), override=True)
    print("Docker configuration written to {}".format(output))


if __name__ == "__main__":
    build()
