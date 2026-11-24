"""Sinkhole: run-time switch (real socket) and build-time DNS wiring."""

import json
import socket
import urllib.request

import pytest
from seedemu.core import Binding, Emulator, Filter
from seedemu.layers import Base, Routing

from software.conftest import write_settings
from software.core import events
from software.sinkhole.runtime import responder
from software.sinkhole.service import Sinkhole


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def get(port):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2).status


def test_switch_opens_and_closes_the_port(yom_root):
    port = free_port()
    write_settings(yom_root, "sinkhole", {"domain": "kill.example.com", "port": port,
                                          "initial": "on"})
    sw = responder.Switchable(responder.settings.load("sinkhole"))
    sw.step()
    assert sw.serving() and get(port) == 200

    responder.set_state("off")
    sw.step()
    assert not sw.serving()
    with pytest.raises(OSError):
        get(port)

    responder.set_state("on")
    sw.step()
    assert get(port) == 200
    sw._close()

    seen = [e["event"] for e in events.read(piece="sinkhole")]
    assert seen.count("switched_off") == 1 and "hit" in seen


def test_initial_state_off_means_silent(yom_root):
    port = free_port()
    write_settings(yom_root, "sinkhole", {"domain": "kill.example.com", "port": port,
                                          "initial": "off"})
    sw = responder.Switchable(responder.settings.load("sinkhole"))
    sw.step()
    assert not sw.serving()


@pytest.mark.parametrize("bad", ["localhost", "a b.com", "-x.com", "", "x"])
def test_domain_is_validated(bad):
    with pytest.raises(ValueError):
        Sinkhole(bad)


def lab():
    emu = Emulator()
    base = Base()
    lab_as = base.createAutonomousSystem(151)
    lab_as.createNetwork("net0")
    lab_as.createRouter("router0").joinNetwork("net0")
    lab_as.createHost("victim1").joinNetwork("net0")
    emu.addBinding(Binding("victim1", filter=Filter(asn=151, nodeName="victim1")))
    emu.addLayer(base)
    emu.addLayer(Routing())
    return emu


def test_minimal_dns_is_created_and_rendered():
    emu = lab()
    sink = Sinkhole("iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com").attachTo(emu, asn=151)
    emu.render()
    web = emu.getRegistry().get("151", "hnode", "sinkhole")
    ip = str(web.getInterfaces()[0].getAddress())

    zone = emu.getLayer("DomainNameService").getZone(f"{sink.domain}.")
    assert any(r.endswith(f"A {ip}") and r.startswith("@") for r in zone.getRecords())
    assert emu.getLayer("DomainNameCachingService")

    files = {f.get()[0]: f.get()[1] for f in web.getFiles()}
    cfg = json.loads(files["/opt/yom/etc/sinkhole.json"])
    assert cfg == {"domain": sink.domain, "port": 80, "initial": "on"}
    assert "/opt/yom/software/sinkhole/runtime/responder.py" in files
    assert any("yom-sinkhole run" in c for c, _ in web.getStartCommands())


def test_existing_dns_is_reused():
    from seedemu.services import DomainNameService
    emu = lab()
    dns = DomainNameService()
    emu.addLayer(dns)
    lab_as = emu.getLayer("Base").getAutonomousSystem(151)
    lab_as.createHost("rootns").joinNetwork("net0")
    emu.addBinding(Binding("rootns", filter=Filter(asn=151, nodeName="rootns")))
    dns.install("rootns").addZone(".").addZone("com.")
    Sinkhole("kill.example.com").attachTo(emu, asn=151)
    emu.render()
    assert emu.getLayer("DomainNameService") is dns
    with pytest.raises(Exception):
        emu.getLayer("DomainNameCachingService")
