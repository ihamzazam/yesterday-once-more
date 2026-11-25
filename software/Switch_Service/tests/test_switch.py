"""The kill switch: its DNS client, the worm's reader and the teacher's tool. No Docker."""

import json
import socket
import struct
import threading

import pytest

from software.Switch_Service import KILL_SWITCH, DnsKillSwitch, SwitchUnreachable
from software.Switch_Service import seedemu_service
from software.Switch_Service.yom_switch import dnsquery
from software.Switch_Service.yom_switch import reader
from software.Switch_Service.yom_switch.__main__ import main


class FakeServer:
    """Answers DNS questions the way the lab's server does, on a free port.

    `code` is the answer code (3 = no such name, 0 = yes, 5 = refused). With
    code 0 and `has_address`, the reply carries one address record.
    """

    def __init__(self, code, has_address=False, address="127.0.0.1"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(2)
        self.port = self.sock.getsockname()[1]
        self.code, self.has_address, self.rdata = code, has_address, address
        self.questions = []

        def serve():
            while True:
                try:
                    query, client = self.sock.recvfrom(4096)
                except OSError:
                    return
                self.questions.append(query)
                flags = 0x8000 | self.code                  # a response, with this code
                answers = int(self.code == 0 and self.has_address)
                header = query[:2] + struct.pack(">HHHHH", flags, 1, answers, 0, 0)
                record = b""
                if answers:
                    record = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 5, 4)
                    record += bytes(int(part) for part in self.rdata.split("."))
                self.sock.sendto(header + query[12:] + record, client)

        threading.Thread(target=serve, daemon=True).start()

    def asked_name(self):
        labels, index = [], 12                  # the first label's length sits right after the header
        question = self.questions[0]
        while question[index]:
            size = question[index]
            labels.append(question[index + 1:index + 1 + size].decode())
            index += size + 1
        return ".".join(labels)


class WebAnswer:
    """Stands in for the server a domain points to. `reply=False` accepts and hangs up."""

    def __init__(self, reply=True):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.requests = []

        def serve():
            while True:
                try:
                    connection, _ = self.sock.accept()
                except OSError:
                    return
                with connection:
                    self.requests.append(connection.recv(1024))
                    if reply:
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

        threading.Thread(target=serve, daemon=True).start()

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def closed_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def worm_reader(server, web, **options):
    return DnsKillSwitch(
        KILL_SWITCH, server="127.0.0.1", port=server.port, http_port=web.port,
        timeout=1, tries=2, **options
    )


# ---- the DNS client ----

@pytest.mark.parametrize(
    "code,has_address,expected",
    [(3, False, ("missing", None)), (0, False, ("missing", None)),
     (5, False, ("refused", None)), (0, True, ("exists", "127.0.0.1"))],
)
def test_query_reads_the_answer(code, has_address, expected):
    server = FakeServer(code, has_address)
    assert dnsquery.query("127.0.0.1", KILL_SWITCH, timeout=1, tries=2, port=server.port) == expected
    assert server.asked_name() == KILL_SWITCH


def test_query_reads_whichever_address_the_record_holds():
    server = FakeServer(0, has_address=True, address="10.159.0.75")
    assert dnsquery.query("127.0.0.1", KILL_SWITCH, timeout=1, tries=2, port=server.port) == (
        "exists", "10.159.0.75")
    assert dnsquery.ask("127.0.0.1", KILL_SWITCH, timeout=1, tries=2, port=server.port) == "exists"


def test_query_is_nothing_when_nobody_answers():
    assert dnsquery.query("127.0.0.1", KILL_SWITCH, timeout=0.2, tries=2, port=closed_port()) == (
        None, None)


def test_answers_is_true_only_when_something_really_answers():
    web = WebAnswer(reply=True)
    assert reader.answers("127.0.0.1", KILL_SWITCH, port=web.port, timeout=1) is True
    web.close()
    assert b"Host: " + KILL_SWITCH.encode() in web.requests[0]     # it asked for the domain
    silent = WebAnswer(reply=False)
    assert reader.answers("127.0.0.1", KILL_SWITCH, port=silent.port, timeout=1) is False
    silent.close()
    assert reader.answers("127.0.0.1", KILL_SWITCH, port=closed_port(), timeout=0.5) is False


# ---- what the worm does ----

def test_the_worm_spreads_while_nobody_registered_the_domain_and_stops_once_it_answers():
    with WebAnswer() as web:
        missing, registered = FakeServer(3), FakeServer(0, has_address=True)
        assert worm_reader(missing, web).allowed() is True
        assert worm_reader(registered, web).allowed() is False


def test_a_registered_domain_that_does_not_answer_does_not_stop_the_worm():
    """What the real worm did: the connection failed, so it went on."""
    with WebAnswer(reply=False) as silent:
        assert worm_reader(FakeServer(0, has_address=True), silent).allowed() is True
    unreachable = DnsKillSwitch(KILL_SWITCH, server="127.0.0.1", port=FakeServer(0, True).port,
                                http_port=closed_port(), timeout=0.5, tries=2)
    assert unreachable.allowed() is True


def test_the_worm_never_guesses_when_the_switch_is_silent():
    reader_ = DnsKillSwitch(KILL_SWITCH, server="127.0.0.1", port=1, timeout=0.2, tries=1)
    with pytest.raises(SwitchUnreachable):
        reader_.allowed()


def test_the_worm_says_so_when_the_switch_refuses_the_name():
    with pytest.raises(SwitchUnreachable, match="inside its zone"):
        worm_reader(FakeServer(5), WebAnswer()).allowed()


def test_by_default_the_worm_checks_before_every_attempt():
    server, web = FakeServer(3), WebAnswer()
    reader_ = worm_reader(server, web)
    assert [reader_.allowed() for _ in range(4)] == [True] * 4
    assert len(server.questions) == 4


def test_the_exact_behaviour_checks_once_when_the_worm_starts():
    """The real worm checked once, so registering the domain later stopped nothing running."""
    server, web = FakeServer(3), WebAnswer()
    reader_ = worm_reader(server, web, every_round=False)
    assert [reader_.allowed() for _ in range(4)] == [True] * 4
    assert len(server.questions) == 1


def test_the_worm_part_shows_how_it_reaches_the_switch():
    reader_ = DnsKillSwitch(KILL_SWITCH, server="10.0.0.5")
    assert reader_.SLOT == "governor"
    assert vars(reader_) == {
        "domain": KILL_SWITCH, "server": "10.0.0.5", "port": 53, "http_port": 80,
        "timeout": 2.0, "tries": 3, "every_round": True, "_checked": False,
    }


def test_the_domain_is_the_real_one():
    assert KILL_SWITCH == "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"


# ---- the installer ----

def test_the_switch_is_one_registered_domain_with_the_www_name_in_front():
    switch = seedemu_service.DnsSwitch()
    assert switch.kill_switch() == KILL_SWITCH
    assert switch.zone == "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com."
    assert switch.name("pause") == "pause." + switch.zone
    assert switch.vnode == "yom-switch"


# ---- the teacher's tool ----

def run_tool(monkeypatch, tmp_path, settings):
    scripts = []
    done = type("Done", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr("subprocess.run", lambda args, **kw: scripts.append(kw["input"]) or done)
    path = tmp_path / "switch.json"
    path.write_text(json.dumps(settings))
    monkeypatch.setattr("software.Switch_Service.yom_switch.__main__.SETTINGS", path)
    return scripts


def test_flip_tool_registers_and_unregisters_the_domain(monkeypatch, tmp_path):
    scripts = run_tool(monkeypatch, tmp_path, {
        "server": "10.0.0.5", "zone": "example.com.", "ip": "10.0.0.5", "port": 53,
        "http_port": 80, "domain": "www.example.com."})
    assert main(["stop"]) == 0
    assert main(["go"]) == 0
    assert main(["set", "pause"]) == 0
    assert main(["unset", "pause"]) == 0
    assert scripts == [
        "server 10.0.0.5\nzone example.com.\nupdate add www.example.com. 5 A 10.0.0.5\nsend\n",
        "server 10.0.0.5\nzone example.com.\nupdate delete www.example.com. A\nsend\n",
        "server 10.0.0.5\nzone example.com.\nupdate add pause.example.com. 5 A 10.0.0.5\nsend\n",
        "server 10.0.0.5\nzone example.com.\nupdate delete pause.example.com. A\nsend\n",
    ]


def test_flip_tool_explains_itself_before_reading_anything():
    for argv in ([], ["frobnicate"], ["set"], ["stop", "extra"], ["status", "x", "y"]):
        assert main(argv) == 2


@pytest.mark.parametrize(
    "code,has_address,web_replies,expected",
    [(3, False, True, "not registered, so nothing answers: the worm spreads"),
     (0, True, True, "registered at 127.0.0.1, and it answers over HTTP: the worm stops"),
     (0, True, False, "registered at 127.0.0.1, but nothing answers over HTTP: the worm spreads"),
     (5, False, True, "not a name in this zone")],
)
def test_flip_tool_reports_what_the_worm_would_conclude(
        monkeypatch, tmp_path, capsys, code, has_address, web_replies, expected):
    server, web = FakeServer(code, has_address), WebAnswer(reply=web_replies)
    run_tool(monkeypatch, tmp_path, {
        "server": "127.0.0.1", "zone": "example.com.", "ip": "127.0.0.1",
        "port": server.port, "http_port": web.port, "domain": "www.example.com."})
    assert main(["status"]) == 0
    assert capsys.readouterr().out == "www.example.com.: {}\n".format(expected)


# ---- the two halves must agree on the name ----

def test_the_tool_registers_exactly_the_name_the_worm_asks_for():
    """A live run once failed here: the tool registered the domain without www.

    and the worm asked for it with www., so the switch was thrown and nothing
    stopped. The installer writes the worm's name into the tool's settings.
    """
    from seedemu import Base, Emulator
    from seedemu.core import Binding, Filter

    switch = seedemu_service.DnsSwitch()
    emu, base = Emulator(), Base()
    lab = base.createAutonomousSystem(170)
    lab.createNetwork("net0")
    lab.createHost("switch").joinNetwork("net0")
    emu.addLayer(base)
    emu.addLayer(switch)
    emu.addBinding(Binding(switch.vnode, filter=Filter(asn=170, nodeName="switch")))
    emu.render()
    node = emu.getBindingFor(switch.vnode)
    settings = json.loads({item.get()[0]: item.get()[1] for item in node.getFiles()}[
        "/opt/yom/switch.json"])
    assert settings["domain"] == switch.kill_switch() == KILL_SWITCH
    assert settings["domain"] == "www." + settings["zone"].rstrip(".")
