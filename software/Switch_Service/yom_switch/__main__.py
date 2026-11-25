"""The teacher's side of the switch. Run it on the switch's own machine.

    switch stop            register the kill-switch domain: it answers, every worm stops
    switch go              unregister it: nothing answers, the worm may spread again
    switch status          is the domain registered, and does it answer right now?

`set <name>` and `unset <name>` register or unregister any other name in the
zone.

It changes the DNS record with nsupdate, the same tool Dr. Du's Morris worm
(control_worm.sh) and his first WannaCry example (add_record.sh) use.
"""

import json
import subprocess
import sys
from pathlib import Path

from .dnsquery import query
from .reader import answers

SETTINGS = Path("/opt/yom/switch.json")
USAGE = "usage: switch stop | go | status | set <name> | unset <name>"
VERBS = {"stop": "set", "go": "unset", "set": "set", "unset": "unset", "status": "status"}


def update(settings, action, name) -> int:
    """Register or unregister one address record on the switch's server."""
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


def describe(settings, name) -> str:
    """What the worm would conclude right now, step by step."""
    state, address = query(settings["server"], name, port=settings.get("port", 53))
    if state is None:
        return "the switch did not answer"
    if state == "refused":
        return "not a name in this zone"
    if address is None:
        return "not registered, so nothing answers: the worm spreads"
    if answers(address, name, settings.get("http_port", 80)):
        return "registered at {}, and it answers over HTTP: the worm stops".format(address)
    return "registered at {}, but nothing answers over HTTP: the worm spreads".format(address)


def main(argv) -> int:
    verb = argv[0] if argv else ""
    wants_name = verb in ("set", "unset")
    if verb not in VERBS or len(argv) != (2 if wants_name else 1):
        print(USAGE)
        return 2
    settings = json.loads(SETTINGS.read_text())
    zone = settings["zone"]
    # The kill switch is the name the worm asks for, www. and all. Other names
    # are labels inside the zone.
    name = "{}.{}".format(argv[1], zone) if wants_name else settings["domain"]
    if verb == "status":
        print("{}: {}".format(name, describe(settings, name)))
        return 0
    return update(settings, VERBS[verb], name)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
