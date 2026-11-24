"""The stop signal's DNS client, reader and flip tool, tested without Docker."""

import socket
import struct
import threading

import pytest

from software.Switch_Service import DnsKillSwitch, SwitchUnreachable
from software.Switch_Service.yom_switch import dnsquery
from software.Switch_Service.yom_switch.__main__ import main


class FakeServer:
    """Answers DNS questions with whatever response code we choose, on a free port."""

    def __init__(self, code, answers=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(2)
        self.port = self.sock.getsockname()[1]
        self.code, self.answers, self.seen = code, answers, []

        def serve():
            while True:
                try:
                    query, client = self.sock.recvfrom(4096)
                except OSError:
                    return
                self.seen.append(query)
                flags = 0x8000 | self.code            # a response, with this answer code
                header = query[:2] + struct.pack(">HHHHH", flags, 1, self.answers, 0, 0)
                self.sock.sendto(header + query[12:], client)

        threading.Thread(target=serve, daemon=True).start()

    def asked_name(self):
        labels, index = [], 12                  # the first label's length sits right after the header
        query = self.seen[0]
        while query[index]:
            size = query[index]
            labels.append(query[index + 1:index + 1 + size].decode())
            index += size + 1
        return ".".join(labels)


def ask(server, name):
    return dnsquery.ask("127.0.0.1", name, timeout=1, tries=2, port=server.port)


@pytest.mark.parametrize(
    "code,answers,expected",
    [(3, 0, "missing"), (0, 0, "missing"), (0, 1, "exists"), (5, 0, "refused")],
)
def test_ask_reads_the_answer_code(code, answers, expected):
    server = FakeServer(code, answers)
    assert ask(server, "stop.yom.test") == expected
    assert server.asked_name() == "stop.yom.test"


def test_ask_is_none_when_nobody_answers():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:     # a port nobody listens on
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    assert dnsquery.ask("127.0.0.1", "stop.yom.test", timeout=0.2, tries=2, port=port) is None


def reader(server):
    return DnsKillSwitch("stop.yom.test", server="127.0.0.1", port=server.port,
                         timeout=1, tries=2)


def test_reader_spreads_while_the_name_is_missing_and_stops_once_it_exists():
    server = FakeServer(3)                       # NXDOMAIN: nobody registered the name
    assert reader(server).allowed() is True
    server.code, server.answers = 0, 1           # registered: the stop signal is there
    assert reader(server).allowed() is False


def test_reader_never_guesses_when_the_switch_is_silent():
    with pytest.raises(SwitchUnreachable):
        reader(FakeServer(3)).allowed() if False else DnsKillSwitch(
            "stop.yom.test", server="127.0.0.1", port=1, timeout=0.2, tries=1
        ).allowed()


def test_reader_says_so_when_the_switch_refuses_the_name():
    with pytest.raises(SwitchUnreachable, match="inside its zone"):
        reader(FakeServer(5)).allowed()


def test_reader_is_a_worm_part_and_shows_how_it_reaches_the_switch():
    reader = DnsKillSwitch("stop.yom.test", server="10.0.0.5")
    assert reader.SLOT == "governor"
    assert vars(reader) == {
        "domain": "stop.yom.test", "server": "10.0.0.5", "port": 53,
        "timeout": 2.0, "tries": 3,
    }


def test_flip_tool_speaks_nsupdate(monkeypatch, tmp_path):
    scripts = []
    done = type("Done", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr("subprocess.run", lambda args, **kw: scripts.append(kw["input"]) or done)
    settings = tmp_path / "switch.json"
    settings.write_text('{"server": "10.0.0.5", "zone": "yom.test.", "ip": "127.0.0.1"}')
    monkeypatch.setattr("software.Switch_Service.yom_switch.__main__.SETTINGS", settings)

    assert main(["stop"]) == 0
    assert main(["go"]) == 0
    assert main(["set", "pause"]) == 0
    assert main(["unset", "pause"]) == 0
    assert scripts == [
        "server 10.0.0.5\nzone yom.test.\nupdate add stop.yom.test. 5 A 127.0.0.1\nsend\n",
        "server 10.0.0.5\nzone yom.test.\nupdate delete stop.yom.test. A\nsend\n",
        "server 10.0.0.5\nzone yom.test.\nupdate add pause.yom.test. 5 A 127.0.0.1\nsend\n",
        "server 10.0.0.5\nzone yom.test.\nupdate delete pause.yom.test. A\nsend\n",
    ]


def test_flip_tool_explains_itself_before_reading_anything():
    for argv in ([], ["frobnicate"], ["set"], ["stop", "extra"], ["status", "x", "y"]):
        assert main(argv) == 2


def test_flip_tool_reports_the_status(monkeypatch, tmp_path):
    server = FakeServer(3)
    settings = tmp_path / "switch.json"
    settings.write_text(
        '{{"server": "127.0.0.1", "zone": "yom.test.", "ip": "127.0.0.1", "port": {}}}'.format(
            server.port
        )
    )
    monkeypatch.setattr("software.Switch_Service.yom_switch.__main__.SETTINGS", settings)
    monkeypatch.setattr(
        "software.Switch_Service.yom_switch.__main__.ask",
        lambda addr, name: dnsquery.ask(addr, name, port=server.port),
    )
    assert main(["status"]) == 0
