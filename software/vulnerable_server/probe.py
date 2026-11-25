#!/usr/bin/env python3
"""Measure the vulnerable server's stack frame and write its profile (contract 1).

`stack` prints its own frame pointer and buffer address, so nobody has to
hand-type them. The lab server spawns it as

    execle("stack", "stack", NULL, {"randomstring": "A" * 499})

(one environment variable of that exact length, argv[0] "stack", no PATH
lookup, server.c: generate_random_env) and is itself started under
``setarch i386 -R``, whose no-ASLR personality is inherited across fork and
exec. The probe reproduces that context exactly and reads the two printed
addresses; two runs must agree or it refuses to write anything.

Inside the yom-vuln image (see images/yom-vuln/Dockerfile):

    python3 probe.py <bindir> <out.json>

The no-ASLR personality is set for the measured child, so this works whatever
the host's kernel.randomize_va_space is; the toolkit never changes the host.

Stdlib only: this runs inside the container image build.
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

#: How the server launches `stack` (server.c): argv[0] and one env variable.
LAUNCHER = "import os; os.execve('stack', ['stack'], {'randomstring': 'A' * 499})"
SPAWN_ENV = {"randomstring": "A" * 499}
#: How the toolkit starts the server; the personality is inherited by `stack`.
SETARCH = ["setarch", "i386", "-R"]

#: The badfile, as in the original lab: 500 bytes of sled + shellcode, and the
#: saved return address at ebp - buf + 4 pointing ebp + 40 bytes into the sled.
BADFILE_SIZE = 500
RET_DISTANCE_INTO_SLED = 40

#: Dr. Du's shellcode stub runs one fixed-length command (see worm/runtime):
#: 179 characters of room after its strings, NUL-terminated by the stub.
COMMAND_ROOM = 179

BINARIES = ("server", "stack", "stack-patched")


def measure_once(bindir: Path):
    """One measurement run: (ebp, buf), or an error saying what went wrong."""
    result = subprocess.run([*SETARCH, sys.executable, "-c", LAUNCHER],
                             cwd=str(bindir), input=b"\n", capture_output=True)
    printed = result.stdout.decode("utf-8", errors="replace")
    found = re.findall(r"bof\(\):\s+0x([0-9a-f]+)", printed)
    if len(found) != 2:
        raise RuntimeError(
            "stack did not print its two addresses; output was:\n"
            + printed
            + result.stderr.decode("utf-8", errors="replace")
        )
    return int(found[0], 16), int(found[1], 16)      # frame pointer, buffer


def measure(bindir: Path):
    """The frame the server's spawn context gives `stack`; stable across runs."""
    first, second = measure_once(bindir), measure_once(bindir)
    if first != second:
        raise RuntimeError(f"the addresses moved between runs ({first}, {second}); "
                           "ASLR is not disabled for the measured child")
    return first


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile(bindir: Path) -> dict:
    """The published profile: every measured value an exploit needs."""
    bindir = Path(bindir)
    ebp, buf = measure(bindir)
    return {
        "format": "yom-profile/1",
        "kind": "stack_overflow",
        "spawn": {"argv": ["stack"], "env": SPAWN_ENV, "setarch": SETARCH},
        "measured": {"ebp": ebp, "buf": buf},
        "badfile": {"size": BADFILE_SIZE,
                    "ret_offset": ebp - buf + 4,
                    "ret_target": ebp + RET_DISTANCE_INTO_SLED},
        "command_room": COMMAND_ROOM,
        "protections": {"execstack": True, "canary": False, "static": True,
                        "aslr": "off per process (setarch i386 -R)"},
        "binaries": {name: _sha256(bindir / name) for name in BINARIES},
    }


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(prog="probe", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bindir", type=Path, help="folder holding the compiled binaries")
    parser.add_argument("out", help="profile.json to write, or - for stdout")
    args = parser.parse_args(argv)
    value = profile(args.bindir)
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        Path(args.out).write_text(text, encoding="utf-8")
    ebp, buf = value["measured"]["ebp"], value["measured"]["buf"]
    print(f"ebp=0x{ebp:08x} buf=0x{buf:08x} -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
