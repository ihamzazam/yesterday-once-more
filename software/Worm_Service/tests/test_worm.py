"""The worm: its four slots, the spread loop, and the installer. No Docker needed."""

import io
import json
import socket
import sys
import tarfile
from pathlib import Path

import pytest

import software.Worm_Service.yom_worm as yom_worm_package
from software.Switch_Service import DnsKillSwitch, DnsSwitch
from software.Vulnerable_Server import MorrisBufferOverflow, VulnerableServer
from software.Vulnerable_Server.vulnerabilities.morris_bof import MorrisBofEntry
from software.Worm_Service import NoPayload, Pace, ShuffleScanner, Worm
from software.Worm_Service.yom_worm import body, plugs
from software.Worm_Service.yom_worm.engine import Engine
from software.Worm_Service.yom_worm.spec import SLOTS, describe

# Inside a container the runtime package is called yom_worm. Lend it that name
# here so the loader takes the same path it takes there.
sys.modules.setdefault("yom_worm", yom_worm_package)
sys.modules.setdefault("yom_worm.builtin", yom_worm_package.builtin)


# ---- fake parts: the same source the engine will import from a fake package ----

FAKE_PACKAGE = '''
SLOT = "scanner"


class ListScanner:
    """Goes down the list, skips what is excluded, and starts over at the end."""

    SLOT = SLOT

    def __init__(self, targets=None):
        self.targets = list(targets or [])
        self._rest = []

    def next_target(self, exclude=()):
        while True:
            if not self._rest:
                self._rest = list(self.targets)
            target = self._rest.pop(0)
            if target not in exclude:
                return target
            if not self._rest and all(t in exclude for t in self.targets):
                return None


class OneByOne:
    SLOT = "entry"

    def __init__(self, fail=(), refuse=(), measured=None):
        self.fail = list(fail)
        self.refuse = list(refuse)
        # Stands for something the launcher measures before it attacks, such
        # as the addresses of `stack`: it has to travel inside the body.
        self.measured = measured
        self.hits = []

    def check_host(self):
        self.measured = "measured here"
        return list(self.refuse)

    def break_in(self, target, worm_body):
        self.hits.append((target, worm_body))
        return None if target in self.fail else "arrived"


class Signal:
    SLOT = "governor"

    def __init__(self, answer="go"):
        self.answer = answer
        self.asked = 0

    def allowed(self):
        self.asked += 1
        if self.answer == "down":
            raise RuntimeError("no answer from the switch")
        return self.answer == "go"
'''

PACE = dict(attempt_delay=0.05, announce_wait=0.1, body_wait=0.05, max_seconds=0.6,
            startup_wait=0.3, announce_port=0)


class _Fake:
    """Instances built from the fake source, only to write the settings file."""

    def __init__(self, source):
        namespace = {}
        exec(source, namespace)
        for name, obj in namespace.items():
            if isinstance(obj, type):
                setattr(self, name, obj)


FAKE = _Fake(FAKE_PACKAGE)


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_home(tmp_path, entry=None, governor=None, pace=None):
    """A folder laid out like /opt/yom on the launcher, with fake parts."""
    (tmp_path / "fake_parts").mkdir()
    (tmp_path / "fake_parts" / "__init__.py").write_text(FAKE_PACKAGE)
    (tmp_path / "yom_worm").mkdir()
    settings = pace or dict(PACE, announce_port=free_udp_port())
    manifest = {
        "scanner": describe(FAKE.ListScanner(["a", "b", "c"])),
        "entry": describe(entry or FAKE.OneByOne()),
        "payload": describe(NoPayload()),
        "packages": ["fake_parts"],
        "pace": settings,
    }
    if governor is not None:
        manifest["governor"] = describe(governor)
    (tmp_path / "worm.json").write_text(json.dumps(manifest))
    return tmp_path


def events(home):
    return [json.loads(line) for line in (home / "events.jsonl").read_text().splitlines()]


# ---- the slots ----

def test_a_part_needs_a_slot_and_its_method():
    class NoSlot:
        def run(self):
            pass

    class WrongMethod:
        SLOT = "entry"

        def run(self):
            pass

    with pytest.raises(TypeError, match="SLOT"):
        describe(NoSlot())
    with pytest.raises(TypeError, match="break_in"):
        describe(WrongMethod())


def test_describe_writes_the_constructor_arguments_and_nothing_else():
    class Entry:
        SLOT = "entry"

        def __init__(self, port):
            self.port = port
            self.socket = object()          # running state: must stay behind
            self._private = "hidden"

        def break_in(self, target, worm_body):
            pass

    assert describe(Entry(9090)) == {"type": "Entry", "settings": {"port": 9090}}

    class Careless:
        SLOT = "entry"

        def __init__(self, port):           # forgets to keep its argument
            pass

        def break_in(self, target, worm_body):
            pass

    with pytest.raises(TypeError, match="same name"):
        describe(Careless(9090))


def test_scanner_covers_everyone_in_a_new_order_each_pass():
    scanner = ShuffleScanner(["a", "b", "c"], seed=1)
    first_pass = [scanner.next_target() for _ in range(3)]
    assert sorted(first_pass) == ["a", "b", "c"]
    assert scanner.next_target(exclude="abc") is None
    assert scanner.next_target() is not None             # and around again


def test_worm_needs_an_entry_and_checks_its_parts_at_once():
    with pytest.raises(ValueError, match="entry"):
        Worm()
    with pytest.raises(TypeError):
        Worm(entry=object())


def test_worm_without_a_switch_writes_no_governor():
    worm = Worm(entry=MorrisBofEntry(ebp=1, buf=1))
    assert "governor" not in worm.manifest()
    assert set(worm.manifest()) == {"scanner", "entry", "payload", "pace", "packages"}


# ---- the loop ----

def test_launch_packs_a_body_and_attacks_everyone(tmp_path):
    home = make_home(tmp_path)
    engine = Engine(home)
    engine.run("launch")
    log = events(home)
    assert log[0]["event"] == "launch"
    attempts = [record for record in log if record["event"] == "attempt"]
    assert [record["target"] for record in attempts][:3] == ["a", "b", "c"]
    assert all(record["result"] == "arrived" for record in attempts)
    assert log[-1]["event"] == "halted" and log[-1]["reason"] == "time limit"
    assert all(worm_body[:2] == b"\x1f\x8b" for _, worm_body in engine.entry.hits)   # a gzip body each time


def test_a_victim_that_does_not_answer_is_tried_again_later(tmp_path):
    home = make_home(tmp_path, entry=FAKE.OneByOne(fail=["b"]))
    engine = Engine(home)
    engine.run("launch")
    assert engine.done == {"a", "c"}


def test_the_body_is_a_tarball_with_the_settings_inside(tmp_path):
    home = make_home(tmp_path)
    packed = body.pack(home, ["fake_parts"], {"scanner": {"type": "ListScanner"}})
    with tarfile.open(fileobj=io.BytesIO(packed)) as archive:
        names = archive.getnames()
        manifest = json.load(archive.extractfile("worm.json"))
    assert "worm.json" in names
    assert "fake_parts/__init__.py" in names
    assert not any("__pycache__" in name for name in names)
    assert manifest["scanner"] == {"type": "ListScanner"}


def test_an_arrived_worm_answers_its_infector_and_passes_the_body_on(tmp_path, monkeypatch):
    """The other way to run: the body has just landed on a machine."""
    infector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    infector.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    infector.bind(("127.0.0.1", 0))
    infector.settimeout(3)
    home = make_home(tmp_path, pace=dict(PACE, max_seconds=1.5,
                                         announce_port=infector.getsockname()[1]))
    monkeypatch.setenv("FROM", "127.0.0.1")

    engine = Engine(home)
    engine.run("run")

    assert infector.recvfrom(64)[0] == b"ARRIVED"
    log = events(home)
    kinds = [record["event"] for record in log]
    assert kinds[0] == "arrived" and log[0]["infector"] == "127.0.0.1"
    assert kinds[1:-1] == ["attempt"] * 3          # it passed the body on to everyone
    assert kinds[-1] == "halted"
    assert all(worm_body[:2] == b"\x1f\x8b" for _, worm_body in engine.entry.hits)


def test_the_body_carries_what_the_launcher_measured(tmp_path):
    """A live run once shipped empty addresses: the body was packed before measuring."""
    home = make_home(tmp_path)
    engine = Engine(home)
    engine.run("launch")
    with tarfile.open(fileobj=io.BytesIO(engine.entry.hits[0][1])) as archive:
        shipped = json.load(archive.extractfile("worm.json"))
    assert shipped["entry"]["settings"]["measured"] == "measured here"


def test_the_stop_signal_halts_the_worm(tmp_path):
    home = make_home(tmp_path, governor=FAKE.Signal("stop"))
    engine = Engine(home)
    engine.run("launch")
    assert events(home)[-1]["event"] == "halted"
    assert events(home)[-1]["reason"] == "stop signal"
    assert engine.entry.hits == []


def test_a_silent_switch_stops_the_worm_instead_of_letting_it_guess(tmp_path):
    home = make_home(tmp_path, governor=FAKE.Signal("down"))
    with pytest.raises(SystemExit) as stopped:
        Engine(home).run("launch")
    assert stopped.value.code == 1
    assert events(home)[-1]["reason"] == "cannot reach the stop-signal server"


def test_a_break_in_that_cannot_work_here_refuses_to_launch(tmp_path):
    home = make_home(tmp_path, entry=FAKE.OneByOne(refuse=["ASLR is on"]))
    with pytest.raises(SystemExit) as stopped:
        Engine(home).run("launch")
    assert stopped.value.code == 1
    assert events(home)[0]["event"] == "refused"


def test_only_one_worm_per_machine(tmp_path, capsys):
    home = make_home(tmp_path)
    first = Engine(home)
    import fcntl
    lock = (home / ".lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    with pytest.raises(SystemExit) as stopped:
        Engine(home)._lock()
    assert stopped.value.code == 0
    assert "already running" in capsys.readouterr().out


def test_the_loader_finds_parts_by_name_and_says_when_one_is_missing(tmp_path):
    home = make_home(tmp_path)
    registry = plugs.load(home, ["fake_parts"])
    assert registry[("entry", "OneByOne")].__name__ == "OneByOne"
    assert registry[("scanner", "ShuffleScanner")].__name__ == "ShuffleScanner"   # built in
    with pytest.raises(LookupError, match="shipped inside the worm body"):
        plugs.build(registry, "entry", {"type": "NoSuchEntry", "settings": {}})


# ---- the installer, on a real emulator ----

def build_lab(attach_hole=True, domain="stop.yom.test"):
    from seedemu import Base, Emulator, Routing
    from seedemu.core import Binding, Filter

    emu, base = Emulator(), Base()
    lab = base.createAutonomousSystem(158)
    lab.createNetwork("net0")
    lab.createRouter("router0").joinNetwork("net0")
    hosts = {name: lab.createHost(name).joinNetwork("net0")
             for name in ("victim1", "victim2", "attacker", "switch")}
    emu.addLayer(base)
    emu.addLayer(Routing())

    switch = DnsSwitch()
    emu.addLayer(switch)
    emu.addBinding(Binding(switch.vnode, filter=Filter(asn=158, nodeName="switch")))

    bof = MorrisBufferOverflow()
    if attach_hole:
        victims = VulnerableServer(bof)
        emu.addLayer(victims)
        for name in ("victim1", "victim2"):
            victims.install("vuln-" + name)
            emu.addBinding(Binding("vuln-" + name, filter=Filter(asn=158, nodeName=name)))

    worm = Worm(entry=bof.exploit(), governor=DnsKillSwitch(domain))
    emu.addLayer(worm)
    worm.launch_from("patient-zero")
    emu.addBinding(Binding("patient-zero", filter=Filter(asn=158, nodeName="attacker")))
    return emu, hosts, switch, worm


def address(host):
    return str(host.getInterfaces()[0].getAddress())


def staged_text(host):
    """{path: content} of everything written onto a node as text."""
    return {item.get()[0]: item.get()[1] for item in host.getFiles()}


def staged_files(host):
    """Every path put on a node, as text or as a real file."""
    return sorted(staged_text(host)) + sorted(host.getImportedFiles())


def test_installer_fills_in_what_nobody_should_have_to_type():
    emu, hosts, switch, worm = build_lab()
    emu.render()

    # Who to attack: exactly the machines that have the hole.
    assert sorted(worm.scanner.targets) == sorted(
        [address(hosts["victim1"]), address(hosts["victim2"])]
    )
    # Where the stop-signal server is.
    assert worm.governor.server == switch.address == address(hosts["switch"])
    # Every machine that runs one of our commands can run Python. (A live test
    # once found the switch's own tool missing it.)
    for name in ("attacker", "switch", "victim1", "victim2"):
        assert "python3" in hosts[name].getSoftware()


def test_installer_gives_targets_what_the_body_needs_and_nothing_more():
    emu, hosts, _, _ = build_lab()
    emu.render()
    for name in ("victim1", "victim2"):
        assert "python3" in hosts[name].getSoftware()
        staged = staged_files(hosts[name])
        assert "/bof/server" in staged and "/bof/stack" in staged
        assert not any(path.startswith("/opt/yom") or path == "/usr/local/bin/worm" for path in staged)


def test_installer_puts_the_whole_worm_on_the_launcher():
    emu, hosts, _, _ = build_lab()
    emu.render()
    attacker = hosts["attacker"]
    assert {
        "/usr/local/bin/worm",
        "/opt/yom/worm.json",
        "/opt/yom/launcher/morris_bof/stack",       # to measure the addresses
        "/opt/yom/yom_worm/engine.py",
        "/opt/yom/yom_morris_bof/entry.py",         # the break-in it uses
        "/opt/yom/yom_switch/reader.py",            # the stop signal it obeys
    } <= set(staged_files(attacker))
    assert "python3" in attacker.getSoftware()
    assert (attacker.getStartCommands()[-1]) == ("chmod +x /usr/local/bin/worm", False)

    settings = json.loads(staged_text(attacker)["/opt/yom/worm.json"])
    assert settings["packages"] == ["yom_morris_bof", "yom_switch"]
    assert settings["entry"]["type"] == "MorrisBofEntry"
    assert settings["governor"]["settings"]["server"] == address(hosts["switch"])
    assert sorted(settings["scanner"]["settings"]["targets"]) == sorted(
        [address(hosts["victim1"]), address(hosts["victim2"])]
    )


def test_autostart_runs_the_worm_when_the_machine_boots():
    emu, hosts, _, _ = build_lab()
    emu.getLayer("WormService").autostart = True      # set before render installs it
    emu.render()
    assert ("worm launch", True) in hosts["attacker"].getStartCommands()


def test_installer_refuses_a_worm_whose_hole_is_nowhere():
    emu, _, _, _ = build_lab(attach_hole=False)
    with pytest.raises(ValueError, match="no machine has it installed"):
        emu.render()


def test_installer_refuses_a_stop_signal_outside_the_switch_zone():
    emu, _, _, _ = build_lab(domain="stop.example.com")
    with pytest.raises(ValueError, match="not a name in the switch's zone"):
        emu.render()


def test_manifest_round_trips_through_the_loader(tmp_path):
    """What the installer writes must rebuild into the same parts on a new machine."""
    bof = MorrisBufferOverflow()
    worm = Worm(entry=bof.exploit(), governor=DnsKillSwitch("stop.yom.test", server="10.0.0.5"))
    manifest = worm.manifest(["yom_morris_bof", "yom_switch"])

    # Lay the packages out the way they are laid out inside a node, under the
    # names they have there, and load them from that folder.
    import software.Switch_Service.yom_switch as switch_package
    import software.Vulnerable_Server.vulnerabilities.morris_bof.yom_morris_bof as bof_package

    home = tmp_path / "home"
    for name, package in (("yom_worm", yom_worm_package), ("yom_morris_bof", bof_package),
                          ("yom_switch", switch_package)):
        source = Path(package.__file__).parent
        (home / name).mkdir(parents=True)
        for item in source.iterdir():
            if item.is_file() and item.suffix == ".py":
                (home / name / item.name).write_text(item.read_text())
    registry = plugs.load(home, manifest["packages"])

    for slot in SLOTS:
        rebuilt = plugs.build(registry, slot, manifest[slot])
        assert type(rebuilt).__name__ == manifest[slot]["type"]
        assert vars(rebuilt) == manifest[slot]["settings"]
