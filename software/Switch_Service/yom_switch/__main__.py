"""The teacher's side of the switch. Run it on the switch's own machine.

    switch stop            the stop signal now exists: every worm stops
    switch go              the signal is gone: the worm may spread again
    switch status          is the signal there right now?

`set <name>` and `unset <name>` change any other signal by name.

It changes the DNS record with nsupdate, the same tool Dr. Du's Morris worm
(control_worm.sh) and his first WannaCry example (add_record.sh) use.
"""

import json
import subprocess
import sys
from pathlib import Path

from .dnsquery import ask

SETTINGS = Path("/opt/yom/switch.json")
USAGE = "usage: switch stop | go | status | set <name> | unset <name>"


def update(settings, action, label) -> int:
    """Add or remove one A record on the switch's server."""
    name = "{}.{}".format(label, settings["zone"])
    change = (
        "update add {} 5 A {}".format(name, settings["ip"])
        if action == "set"
        else "update delete {} A".format(name)
    )
    script = "server {}\nzone {}\n{}\nsend\n".format(settings["server"], settings["zone"], change)
    result = subprocess.run(["nsupdate"], input=script, text=True, capture_output=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    return result.returncode


#: verb -> (what it does to the record, the name it does it to unless one is given)
VERBS = {
    "stop": ("set", "stop"),
    "go": ("unset", "stop"),
    "set": ("set", None),
    "unset": ("unset", None),
    "status": ("status", "stop"),
}


def main(argv) -> int:
    verb = argv[0] if argv else ""
    wants_name = verb in ("set", "unset")
    if verb not in VERBS or len(argv) != (2 if wants_name else 1):
        print(USAGE)
        return 2
    settings = json.loads(SETTINGS.read_text())
    action, default = VERBS[verb]
    label = argv[1] if wants_name else default
    name = "{}.{}".format(label, settings["zone"])

    if action == "status":
        answer = ask(settings["server"], name)
        print("{}: {}".format(name, {
            "exists": "present, the worm stops",
            "missing": "absent, the worm spreads",
            "refused": "not a name in this zone",
            None: "the switch did not answer",
        }[answer]))
        return 0
    return update(settings, action, label)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
