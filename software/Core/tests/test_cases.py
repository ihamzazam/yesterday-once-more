"""The WannaCry case builds from the pieces in software/. No Docker."""

import importlib.util
from pathlib import Path

from software.Switch_Service import KILL_SWITCH

CASE = Path(__file__).resolve().parents[3] / "cases" / "Y51_wannacry" / "emulator.py"


def load_case():
    spec = importlib.util.spec_from_file_location("y51_wannacry", CASE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def staged(node):
    return {item.get()[0] for item in node.getFiles()}


def test_the_wannacry_case_builds_from_the_pieces():
    case = load_case()
    emu = case.build()
    emu.render()

    worm, switch, ransom = (emu.getLayer(name) for name in
                            ("WormService", "DnsSwitch", "Ransomware"))
    victims, hole = emu.getLayer("VulnerableServer"), emu.getLayer("VulnerableServer")
    addresses = {str(node.getInterfaces()[0].getAddress()) for _, node in hole.getTargets()}

    assert len(addresses) == len(case.VICTIMS)
    assert set(worm.scanner.targets) == addresses          # the worm attacks exactly the victims
    assert worm.governor.domain == switch.kill_switch() == KILL_SWITCH
    assert worm.governor.server == switch.address
    assert ransom.payload.chain["contract_name"] == "RansomExchange"
    assert ransom.payload.documents == case.DOCUMENTS
    for _, node in victims.getTargets():                    # every victim has the documents
        assert f"{case.DOCUMENTS}/notes.txt" in staged(node)
        assert f"{case.DOCUMENTS}/minutes.txt" in staged(node)
