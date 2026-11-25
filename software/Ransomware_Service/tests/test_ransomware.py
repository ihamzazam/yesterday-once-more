"""The Ransomware box, tested on this machine without Docker.

A victim's disk is a temporary folder: the documents, the infection's files
and the `ransom` command all live there for the duration of a test.
"""

import base64
import json
from pathlib import Path
import re
import socket

import eth_account
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode

from software.Ransomware_Service import Ransomware, RansomwarePayload
from software.Ransomware_Service import seedemu_service
from software.Ransomware_Service.yom_ransomware import chain, files, keys, operator, paths, victim, wallet
from software.Core.testing import FakeWorm

DOCUMENTS = {
    "notes.txt": "Team handover notes\nPrepare the weekly report on Friday.\n",
    "budget.csv": "department,allocated,spent\noperations,12000,9500\n",
    "report.md": "# Monthly report\n\nThe team completed three training sessions.\n",
}


@pytest.fixture
def victim_disk(tmp_path, monkeypatch):
    """Point every path at a temporary folder, and put documents on the disk."""
    documents = tmp_path / "Documents"
    documents.mkdir()
    for name, text in DOCUMENTS.items():
        (documents / name).write_text(text)
    state = tmp_path / "wannacry"
    for name in ("KEYLOG", "RECORD", "WALLET", "REQUEST", "REPLY", "ACCEPTED", "CHAIN"):
        monkeypatch.setattr(paths, name, state / paths.__dict__[name].name)
    operator_dir = tmp_path / "operator"
    for name in ("ATTACKER_KEYS", "CHAIN_KEY", "OPERATOR_CHAIN"):
        monkeypatch.setattr(paths, name, operator_dir / paths.__dict__[name].name)
    monkeypatch.setattr(paths, "MENU", tmp_path / "bin" / "ransom")
    return documents, state


def locked_victim(victim_disk, chain=None):
    """Lock the documents the way the worm does, and return the payload."""
    documents, _ = victim_disk
    operator.init()
    attacker_pub = keys.read_json(paths.ATTACKER_KEYS)["attacker_pub_pem"]
    payload = RansomwarePayload(documents=str(documents), attacker_pub_pem=attacker_pub, chain=chain)
    worm = FakeWorm(home=Path("/tmp/yomw"))
    payload.run(worm)
    return payload, worm


# ---- files ----

def test_lock_then_unlock_round_trip(tmp_path):
    key = AESGCM.generate_key(bit_length=256)
    for name, text in DOCUMENTS.items():
        (tmp_path / name).write_text(text)
    original = {name: (tmp_path / name).read_bytes() for name in DOCUMENTS}

    record = files.encrypt_all(tmp_path, "victim1", key)
    files.apply_lock(tmp_path, record)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(n + ".WNCRY" for n in DOCUMENTS)
    assert files.inspect(tmp_path) == {n: "LOCKED (.WNCRY)" for n in DOCUMENTS}

    restored = files.unlock(tmp_path, "victim1", key, record)
    assert restored == sorted(DOCUMENTS)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == original
    assert files.inspect(tmp_path) == {n: "ORIGINAL" for n in DOCUMENTS}


def test_the_file_key_cannot_open_documents_of_another_victim(tmp_path):
    key = AESGCM.generate_key(bit_length=256)
    (tmp_path / "a.txt").write_text("secret")
    record = files.encrypt_all(tmp_path, "victim1", key)
    with pytest.raises(Exception):
        files.unlock(tmp_path, "victim2", key, record)      # the name is bound to the victim


@pytest.mark.parametrize("folder", ["/", "/home", "/home/seed", "/etc", "/tmp"])
def test_it_refuses_to_lock_system_folders(folder):
    with pytest.raises(ValueError, match="system folder"):
        files.check_folder(folder)


def test_it_leaves_subfolders_and_links_alone(tmp_path):
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "a.txt").write_text("a")
    (tmp_path / "Documents" / "sub").mkdir()
    (tmp_path / "Documents" / "sub" / "b.txt").write_text("b")
    (tmp_path / "outside.txt").write_text("outside")
    (tmp_path / "Documents" / "link.txt").symlink_to(tmp_path / "outside.txt")
    record = files.encrypt_all(tmp_path / "Documents", "v", AESGCM.generate_key(bit_length=256))
    assert list(record) == ["a.txt"]


# ---- what the worm does on arrival ----

def test_arrival_locks_documents_and_leaves_the_menu_and_the_note(victim_disk):
    documents, state = victim_disk
    payload, worm = locked_victim(victim_disk)

    assert sorted(p.name for p in documents.iterdir()) == sorted(
        [*[n + ".WNCRY" for n in DOCUMENTS], paths.NOTE_NAME])
    assert "ransom" in (documents / paths.NOTE_NAME).read_text()
    assert "run the menu" in (documents / paths.NOTE_NAME).read_text()
    assert paths.MENU.read_text() == (
        '#!/bin/bash\nPYTHONPATH=/tmp/yomw exec python3 -m yom_ransomware "$@"\n')
    assert paths.MENU.stat().st_mode & 0o111
    assert worm.events == [("locked", {"documents": 3, "folder": str(documents)})]

    keylog = keys.read_json(paths.KEYLOG)
    assert keylog["participant_id"] == victim.participant_id()
    assert sorted(keylog["files"]) == sorted(DOCUMENTS)
    assert "attacker_priv" not in json.dumps(keylog)          # only the attacker's public half is here
    assert paths.KEYLOG.stat().st_mode & 0o077 == 0           # owner-only


def test_a_machine_is_never_locked_twice(victim_disk):
    locked_victim(victim_disk)
    with pytest.raises(ValueError, match="already locked"):
        locked_victim(victim_disk)


# ---- the exchange, on the manual path (no chain needed) ----

def granted_key(capsys):
    shown = [line for line in capsys.readouterr().out.splitlines() if re.fullmatch(r"  [A-Za-z0-9+/=]{44}", line)]
    assert len(shown) == 1, "exactly one KEY GRANTED line is expected"
    return shown[0].strip()


def test_pay_get_the_key_and_decrypt_restores_every_document(victim_disk, capsys):
    documents, state = victim_disk
    locked_victim(victim_disk)

    victim.recovery_step()                       # no wallet: build the request, explain the rest
    assert keys.read_json(paths.REQUEST)["victim_priv_sealed"]
    assert "ransom reply --request" in capsys.readouterr().out

    reply = operator.reply(paths.REQUEST)        # on the attacker's machine
    paths.REPLY.write_text(json.dumps(reply))
    capsys.readouterr()

    victim.recovery_step()                       # on the victim: accept it
    key = granted_key(capsys)

    assert victim.decrypt(key) == len(DOCUMENTS)
    assert {p.name: p.read_text() for p in documents.iterdir() if p.suffix != ".WNCRY"} == {
        **DOCUMENTS, paths.NOTE_NAME: (documents / paths.NOTE_NAME).read_text()}
    assert not list(documents.glob("*.WNCRY"))
    assert files.inspect(documents, keys.read_json(paths.KEYLOG)["files"]) == {
        n: "ORIGINAL" for n in DOCUMENTS}


def test_a_wrong_key_restores_nothing(victim_disk, capsys):
    documents, _ = victim_disk
    locked_victim(victim_disk)
    victim.recovery_step()
    paths.REPLY.write_text(json.dumps(operator.reply(paths.REQUEST)))
    capsys.readouterr()
    victim.recovery_step()
    good = granted_key(capsys)
    bad = bytearray(base64.b64decode(good)); bad[0] ^= 1

    with pytest.raises(Exception):
        victim.decrypt(keys.b64(bytes(bad)))
    assert not [p for p in documents.iterdir() if p.suffix != ".WNCRY" and p.name != paths.NOTE_NAME]
    victim.decrypt(good)                         # and the right key still works afterwards


def test_an_empty_reply_is_refused(victim_disk):
    locked_victim(victim_disk)
    victim.recovery_step()
    paths.REPLY.write_text(json.dumps({"victim_priv_pem": ""}))
    with pytest.raises(ValueError):
        victim.recovery_step()


def test_a_request_sealed_for_another_attacker_is_refused(victim_disk, tmp_path, monkeypatch):
    """The attacker's private key opens only what was sealed under its public key."""
    locked_victim(victim_disk)
    victim.recovery_step()
    monkeypatch.setattr(paths, "ATTACKER_KEYS", tmp_path / "other-attacker.json")
    operator.init()
    with pytest.raises(ValueError, match="different attacker key"):
        operator.reply(paths.REQUEST)


# ---- the worm part ----

def test_launch_is_refused_without_attacker_keys_or_a_chain(victim_disk, monkeypatch):
    payload = RansomwarePayload()
    assert payload.check_host() == [
        "no payment chain: this ransomware was not installed with its chain "
        "(add the Ransomware service to the emulation)"]
    payload.chain = {"chain_id": 1}
    assert "ransom init" in payload.check_host()[0]
    operator.init()
    assert payload.check_host() == []
    assert payload.attacker_pub_pem.startswith("-----BEGIN PUBLIC KEY-----")


def test_only_the_public_half_travels_in_the_settings(victim_disk):
    payload, _ = locked_victim(victim_disk)
    from software.Worm_Service.yom_worm.spec import describe
    shipped = json.dumps(describe(payload))
    assert "BEGIN PUBLIC KEY" in shipped
    assert "BEGIN PRIVATE KEY" not in shipped


# ---- the installer, on a real emulator ----

def build_lab():
    from seedemu import Base, Emulator, Routing
    from seedemu.core import Binding, Filter
    from software.Switch_Service import DnsSwitch, DnsKillSwitch
    from software.Vulnerable_Server import MorrisBufferOverflow, VulnerableServer
    from software.Worm_Service import Worm

    asn = 159
    emu, base = Emulator(), Base()
    lab = base.createAutonomousSystem(asn)
    lab.createNetwork("net0")
    lab.createRouter("router0").joinNetwork("net0")
    hosts = {name: lab.createHost(name).joinNetwork("net0")
             for name in ("victim1", "attacker", "switch")}

    def place(vnode, name):
        emu.addBinding(Binding(vnode, filter=Filter(asn=asn, nodeName=name)))

    emu.addLayer(base)
    emu.addLayer(Routing())
    switch = DnsSwitch()
    emu.addLayer(switch)
    place(switch.vnode, "switch")
    ransom = Ransomware(in_as=lab, on_network="net0")
    emu.addLayer(ransom)
    for binding in ransom.bindings:
        emu.addBinding(binding)
    bof = MorrisBufferOverflow()
    victims = VulnerableServer(bof)
    emu.addLayer(victims)
    victims.install("vuln-victim1")
    place("vuln-victim1", "victim1")
    worm = Worm(entry=bof.exploit(), payload=ransom.payload,
                governor=DnsKillSwitch(switch.name("stop")))
    emu.addLayer(worm)
    worm.launch_from("zero")
    place("zero", "attacker")
    return emu, hosts, ransom, worm


def texts(node):
    return {item.get()[0]: item.get()[1] for item in node.getFiles()}


def test_installer_brings_the_chain_and_nobody_types_an_address():
    emu, hosts, ransom, worm = build_lab()
    emu.render()
    chain = ransom.payload.chain
    assert chain["chain_id"] == 18000 and chain["contract_name"] == "RansomExchange"
    assert chain["rpc_url"].startswith("http://10.159.0.") and chain["rpc_url"].endswith(":8545")
    assert chain["faucet_url"].endswith("/fundme") and chain["utility_url"].endswith(":8080")
    for name in ("ransom-chain-0", "ransom-chain-1", "ransom-chain-2", "ransom-faucet", "ransom-utility"):
        assert emu.getBindingFor(name).getName() == name


def test_attacker_and_contract_share_one_account_and_victims_never_see_its_key():
    emu, hosts, ransom, worm = build_lab()
    emu.render()
    utility = texts(emu.getBindingFor("ransom-utility"))
    attacker = texts(hosts["attacker"])
    account = json.loads(utility["/utility_server/account.json"])
    assert account["private_key"].startswith("0x") and len(account["private_key"]) == 66
    assert json.loads(attacker["/opt/yom/ransom/chain_key.json"]) == account
    assert "reuseOrCreateAccount()" in utility["/utility_server/fund_account.py"]
    assert json.loads(attacker["/opt/yom/ransom/chain.json"]) == ransom.payload.chain
    # The settings that travel inside the worm body carry no secret.
    shipped = json.loads(attacker["/opt/yom/worm.json"])
    assert account["private_key"] not in json.dumps(shipped)
    assert "yom_ransomware" in shipped["packages"]
    assert "BEGIN" not in json.dumps(shipped["payload"])


def test_attacker_gets_its_tools_and_creates_its_keys_at_boot():
    emu, hosts, _, _ = build_lab()
    emu.render()
    attacker = texts(hosts["attacker"])
    commands = [command for command, _ in hosts["attacker"].getStartCommands()]
    assert "/usr/local/bin/ransom" in attacker and "/opt/yom/yom_ransomware/payload.py" in attacker
    assert commands.index("chmod +x /usr/local/bin/ransom") < commands.index("ransom init")
    for software in ("python3", "python3-cryptography", "python3-pip"):
        assert software in hosts["attacker"].getSoftware()
    assert any("eth-account" in command for command in hosts["attacker"].getBuildCommands())


def test_targets_get_what_the_body_needs_and_nothing_of_the_ransomware():
    emu, hosts, _, _ = build_lab()
    emu.render()
    victim_node = hosts["victim1"]
    for software in ("python3", "python3-cryptography", "python3-pip"):
        assert software in victim_node.getSoftware()
    assert any("eth-account" in command for command in victim_node.getBuildCommands())
    assert not any(path.startswith("/opt/yom") or "ransom" in path for path in texts(victim_node))


def test_worm_waits_for_the_ransomware_layer():
    emu, _, _, worm = build_lab()
    dependencies = worm.getDependencies()[worm.getName()]
    assert ("Ransomware", True) in dependencies


def test_the_chainseed_patch_is_safe_to_apply_more_than_once():
    before = dict(seedemu_service.UtilityServerFileTemplates) if hasattr(
        seedemu_service, "UtilityServerFileTemplates") else None
    seedemu_service._adjust_chainseed_templates()
    from chainseed.services.ethereum.EthTemplates import UtilityServerFileTemplates as templates
    fund = templates["fund_account"]
    assert fund.count("def reuseOrCreateAccount():") == 1
    assert "'gas': 4500000" in templates["deploy_contract"]
    seedemu_service._adjust_chainseed_templates()
    assert templates["fund_account"] == fund


# ---- what is really on the chain ----

def test_the_attacker_answers_the_sealed_blob_that_is_really_on_the_chain(victim_disk, monkeypatch):
    """A live run once failed here.

    The chain carries the sealed blob alone, not the whole request, so the
    attacker must read exactly that. This goes through the real watch code
    against a faked chain.
    """
    documents, _ = victim_disk
    locked_victim(victim_disk)
    victim.recovery_step()
    request = keys.read_json(paths.REQUEST)
    contract_attacker = eth_account.Account.create()
    paths.CHAIN_KEY.write_text(json.dumps(
        {"address": contract_attacker.address, "private_key": contract_attacker.key.hex()}))
    paths.OPERATOR_CHAIN.write_text(json.dumps({"chain_id": 1}))
    keylog = keys.read_json(paths.KEYLOG)

    sent = []

    def rpc(config, method, params):
        assert method == "eth_call"                    # the one question: who is attacker()?
        return "0x" + abi_encode(["address"], [contract_attacker.address]).hex()

    monkeypatch.setattr(chain, "discover_contract", lambda config: "0x" + "11" * 20)
    monkeypatch.setattr(chain, "wait_receipt", lambda config, tx_hash, timeout=120: {"status": "0x1"})
    monkeypatch.setattr(chain, "send_tx",
                        lambda config, account, to, value, data, gas: sent.append(data) or "0xtx")
    monkeypatch.setattr(wallet, "rpc", rpc)
    monkeypatch.setattr(chain, "poll_requests", lambda config, start_id=0: [{
        "id": 0,
        "victim": "0x" + "22" * 20,
        # register_request posts json.dumps(request["victim_priv_sealed"]) and nothing else
        "sealed_blob_json": json.dumps(request["victim_priv_sealed"]),
        "answered": False,
    }])

    assert [entry["id"] for entry in operator.watch()] == [0]

    # What went back on the chain is the victim's private key, and it opens the documents.
    request_id, reply_bytes = abi_decode(["uint256", "bytes"], sent[0][4:])
    assert request_id == 0
    reply = json.loads(reply_bytes)
    file_key = keys.victim_accept_reply(reply, keylog)["file_key"]
    assert len(files.unlock(documents, keylog["participant_id"], file_key, keylog["files"])) == 3


def test_the_attacker_refuses_when_it_is_no_longer_the_contract_s_attacker(victim_disk, monkeypatch):
    """The keys were recreated after the contract was deployed."""
    locked_victim(victim_disk)
    operator_dir = paths.CHAIN_KEY.parent
    stranger = eth_account.Account.create()
    paths.CHAIN_KEY.write_text(json.dumps(
        {"address": eth_account.Account.create().address, "private_key": "0x" + "33" * 32}))
    paths.OPERATOR_CHAIN.write_text(json.dumps({"chain_id": 1}))
    monkeypatch.setattr(chain, "discover_contract", lambda config: "0x" + "11" * 20)
    monkeypatch.setattr(wallet, "rpc", lambda config, method, params: (
        "0x" + abi_encode(["address"], [stranger.address]).hex()))
    with pytest.raises(RuntimeError, match="is not the contract's attacker"):
        operator.watch()


def test_a_victim_is_named_by_its_address():
    """The first live run showed students a container id like 96cebd66071a."""
    name = victim.participant_id()
    assert name == socket.gethostbyname(socket.gethostname()) or name == socket.gethostname()
