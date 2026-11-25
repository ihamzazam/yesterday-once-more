#!/usr/bin/env python3
"""Y51 WannaCry (2017): a worm that carries ransomware.

The whole picture in one case. Three victims have documents. The worm breaks
in through a buffer overflow, carries the ransomware with it, and locks them.
A victim pays on a private chain and gets its documents back. The teacher can
stop the worm with the kill switch of the real WannaCry.

Needs Docker, and ASLR switched off on the host, as Dr. Du's Morris lab does
too (restore it afterwards with =2):

    sudo sysctl -w kernel.randomize_va_space=0

Build and start, from this folder:

    ../../.venv/bin/python emulator.py                 build ./output
    cd output
    docker compose up -d --build                      the first build takes a while
    docker compose logs hnode_159_ransom-utility      wait for "Contract deployed"
    curl -X POST -H "Content-Type: application/json" -d '{"name": "submit_event"}' \
         http://localhost:8082/api/v1/install          once: lets infected machines
                                                      show themselves on the map
                                                      (the map: http://localhost:8082)

Run:

    docker compose exec -d hnode_159_attacker sh -c 'worm launch > /tmp/worm.out 2>&1'
    docker compose logs hnode_159_victim1             watch it arrive and lock

On a victim, open the menu the worm left behind and follow it (wallet,
exchange, pay, receive the key, decrypt):

    docker compose exec -it hnode_159_victim1 ransom

The attacker answers paid requests (do this while a victim waits):

    docker compose exec hnode_159_attacker ransom watch

Stop the worm, then stop the lab:

    docker compose exec hnode_159_switch switch stop
    docker compose down
"""

import argparse
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))             # the repository root, for `software`

from chainseed.compiler import ChainSeedDocker  # noqa: E402
from seedemu.compiler import Platform  # noqa: E402
from seedemu.containerBundle import InternetMap  # noqa: E402
from seedemu.core import Binding, Emulator, Filter  # noqa: E402
from seedemu.layers import Base, Routing  # noqa: E402

from software.Core.staging import reset_output, stage_tree  # noqa: E402
from software.Ransomware_Service import Ransomware  # noqa: E402
from software.Switch_Service import DnsKillSwitch, DnsSwitch  # noqa: E402
from software.Vulnerable_Server import MorrisBufferOverflow, VulnerableServer  # noqa: E402
from software.Worm_Service import Worm  # noqa: E402

ASN = 159                      # change it if the number is taken on your machine
VICTIMS = ["victim1", "victim2", "victim3"]
DOCUMENTS = "/home/seed/Documents"
MAP_PORTS = list(range(8081, 8089))


def build() -> Emulator:
    """The machines, the story, and the lines that connect the pieces."""
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

    # The story: the documents each victim has before anything happens.
    for name in VICTIMS:
        stage_tree(lab.getHost(name), HERE / "documents", DOCUMENTS)

    # The switch: one machine plays the internet for the kill-switch domain.
    switch = DnsSwitch()
    emu.addLayer(switch)
    place(switch.vnode, "switch")

    # The ransomware: its payment chain comes with it.
    ransom = Ransomware(in_as=lab, on_network="net0", documents=DOCUMENTS)
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
                governor=DnsKillSwitch(switch.kill_switch()))
    emu.addLayer(worm)
    worm.launch_from("patient-zero")
    place("patient-zero", "attacker")

    return emu


def add_map(emu, compiler):
    """The Internet Map, as in the v2 lab.

    Dr. Du's `submit_event` add-on is put into the map's server, so that
    infected machines can show themselves once it is switched on (see the
    command at the top).
    """
    map_bundle = InternetMap(emu, ".map.seed")
    map_bundle.setPorts(MAP_PORTS)
    add_on = HERE.parents[1] / "software" / "Core" / "map" / "submit_event"
    server = map_bundle.getContainer("emulator_api_server")
    for name in ("plugin.json", "submit_event.sh"):
        server.setFile("/usr/src/app/plugin/submit_event/" + name,
                      (add_on / name).read_text(encoding="utf-8"))
    compiler.addContainerBundle(map_bundle)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--platform", choices=["amd", "arm"], default="amd")
    parser.add_argument("--output", type=Path, default=HERE / "output")
    args = parser.parse_args()

    emu = build()
    emu.render()
    compiler = ChainSeedDocker(
        platform=Platform.AMD64 if args.platform == "amd" else Platform.ARM64)
    add_map(emu, compiler)
    output = args.output.expanduser().resolve()
    reset_output(output)       # the map leaves root-owned files in it after a run
    emu.compile(compiler, str(output), override=True)
    print(f"Docker configuration written to {output}")


if __name__ == "__main__":
    main()
