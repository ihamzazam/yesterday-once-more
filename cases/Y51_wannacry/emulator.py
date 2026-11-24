#!/usr/bin/env python3
"""Y51 WannaCry (2017): ransomware with an on-chain ransom exchange.

Phase 1 recipe: no worm yet. The ransomware is installed directly on three
victims with a manual trigger (stand-in for the worm's arrival); payment runs
on a private Ethereum chain in the same AS. See README.md.

    python3 emulator.py                  # writes ./out-y51
    cd out-y51 && docker compose up -d
"""

import argparse
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))  # repo root, for `software`

from seedemu.compiler import Platform  # noqa: E402
from seedemu.core import Binding, Emulator, Filter  # noqa: E402
from seedemu.layers import Base, Routing  # noqa: E402

from software.core import install  # noqa: E402
from software.core.files import place_files  # noqa: E402
from software.core.payload import PayloadPackage  # noqa: E402
from software.ransom_payment.service import RansomPayment  # noqa: E402
from software.ransomware.service import Ransomware  # noqa: E402

ASN = 151                      # AS180 is taken on the lab machine by an older run
VICTIMS = 3
DOCUMENTS = "/home/seed/Documents"
FILES = HERE / "victim_files"


def build_network(victims: int = VICTIMS):
    emu = Emulator()
    base = Base()
    lab = base.createAutonomousSystem(ASN)
    lab.createNetwork("net0")
    lab.createRouter("router0").joinNetwork("net0")
    names = []
    for index in range(1, victims + 1):
        name = f"victim{index}"
        lab.createHost(name).joinNetwork("net0")
        emu.addBinding(Binding(name, filter=Filter(asn=ASN, nodeName=name)))
        names.append(name)
    lab.createHost("attacker").joinNetwork("net0")
    emu.addBinding(Binding("attacker", filter=Filter(asn=ASN, nodeName="attacker")))
    emu.addLayer(base)
    emu.addLayer(Routing())
    return emu, names


def check_state_package(suffix: str) -> PayloadPackage:
    """The case's own read-only checker (baseline lives here, not in software/)."""
    baseline = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in FILES.iterdir()}
    files = install.runtime_files("ransomware", "ransom_payment")
    files["yomcases/__init__.py"] = ""
    files["yomcases/y51_check_state.py"] = (HERE / "check_state.py").read_text(encoding="utf-8")
    files.update(install.launcher("y51-check-state", "yomcases.y51_check_state"))
    return PayloadPackage("y51_check", files,
                          {"y51_check": {"folder": DOCUMENTS, "suffix": suffix,
                                         "baseline": baseline}})


def build():
    emu, victims = build_network()
    place_files(emu, victims, FILES, DOCUMENTS)

    payment = RansomPayment(price_eth=1).attachTo(emu, asn=ASN, attacker="attacker")
    ransom = (Ransomware.preset("wannacry")
              .setTargets([DOCUMENTS])
              .addExtensions([".md"])            # report.md is part of the story
              .setNote("READ_ME.txt", (HERE / "participant_note.txt").read_text(encoding="utf-8"))
              .setTrigger("manual")
              .setPayment(payment))
    for victim in victims:
        ransom.install(victim)
    emu.addLayer(ransom.service())

    checker = check_state_package(".WNCRY")
    from seedemu.core import Layer

    class CheckState(Layer):
        def __init__(self):
            super().__init__()
            self.addDependency("Ransomware", False, False)

        def getName(self):
            return "Y51CheckState"

        def render(self, emulator):
            for victim in victims:
                install.install_package(emulator, victim, checker)

    emu.addLayer(CheckState())
    return emu


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--platform", choices=["amd", "arm"], default="amd")
    parser.add_argument("--output", type=Path, default=HERE / "out-y51")
    parser.add_argument("--no-map", action="store_true", help="skip the Internet Map containers")
    args = parser.parse_args()

    from chainseed.compiler import ChainSeedDocker

    emu = build()
    emu.render()
    compiler = ChainSeedDocker(platform=Platform.AMD64 if args.platform == "amd" else Platform.ARM64)
    install.use_base_image(compiler, emu)
    if not args.no_map:
        # seedemu 2.0.0: the Internet Map is a container bundle.
        from seedemu.containerBundle import InternetMap

        map_bundle = InternetMap(emu, ".y51.map.seed")
        map_bundle.setPorts(list(range(8081, 8089)))
        compiler.addContainerBundle(map_bundle)
    output = args.output.expanduser().resolve()
    emu.compile(compiler, str(output), override=True)
    print(f"Docker configuration written to {output}")


if __name__ == "__main__":
    main()
