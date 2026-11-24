"""What a worm is made of: four slots and a pace. Plain data, no seedemu.

A slot is filled by any class that follows three rules:

  - a class attribute SLOT naming the slot it fills;
  - a constructor whose arguments are plain data (strings, numbers, lists);
  - the method of its slot.

That is all the worm needs to write a part into its settings file and rebuild
it on the next machine. Nothing has to be registered anywhere.
"""

import inspect

from .builtin import NoPayload, ShuffleScanner

#: slot -> (the method it must have, what the slot decides)
SLOTS = {
    "scanner": ("next_target", "who to attack"),
    "entry": ("break_in", "how to break in"),
    "governor": ("allowed", "when to stop"),
    "payload": ("run", "what to do after breaking in"),
}


class Pace:
    """Small settings of the loop itself."""

    def __init__(self, attempt_delay=2.0, announce_wait=8.0, body_wait=8.0,
                 max_seconds=1800, startup_wait=60, announce_port=9998):
        self.attempt_delay = attempt_delay    # seconds between two attempts
        self.announce_wait = announce_wait    # how long to wait for a victim to answer
        self.body_wait = body_wait            # how long to wait for a victim to take the body
        self.max_seconds = max_seconds        # the worm always stops after this (safety)
        self.startup_wait = startup_wait      # how long to wait for the switch at start
        self.announce_port = announce_port    # UDP port that victims answer on


def describe(part) -> dict:
    """Write one part as plain data: its class name and its constructor arguments.

    Only the constructor's arguments are written. Anything else a part keeps
    (its running state, private helpers) stays behind, because the next
    machine rebuilds the part by calling its constructor again.
    """
    kind = type(part)
    slot = getattr(kind, "SLOT", None)
    if slot not in SLOTS:
        raise TypeError(
            "{} is not a worm part: give the class a SLOT of {}".format(
                kind.__name__, list(SLOTS)
            )
        )
    method = SLOTS[slot][0]
    if not callable(getattr(part, method, None)):
        raise TypeError(
            "{} fills the '{}' slot but has no {}()".format(kind.__name__, slot, method)
        )
    settings = {}
    for name, parameter in inspect.signature(kind.__init__).parameters.items():
        if name == "self" or parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            continue
        if not hasattr(part, name):
            raise TypeError(
                "{} must keep its argument '{}' in an attribute of the same name, "
                "or the next machine cannot rebuild it".format(kind.__name__, name)
            )
        settings[name] = getattr(part, name)
    return {"type": kind.__name__, "settings": settings}


class WormPlan:
    """The four slots and the pace, before any machine is involved."""

    def __init__(self, scanner=None, entry=None, payload=None, governor=None, pace=None):
        if entry is None:
            raise ValueError("a worm needs an entry: how it breaks in (for example bof.exploit())")
        self.scanner = scanner if scanner is not None else ShuffleScanner()
        self.entry = entry
        self.payload = payload if payload is not None else NoPayload()
        self.governor = governor            # None: nothing can stop it but the time limit
        self.pace = pace if pace is not None else Pace()
        for part in (self.scanner, self.entry, self.payload, self.governor):
            if part is not None:
                describe(part)              # complain now, while the case is being written

    @property
    def parts(self):
        return (self.scanner, self.entry, self.payload, self.governor)

    def manifest(self, packages=()) -> dict:
        """The settings file of the worm, as plain data."""
        manifest = {}
        for slot in SLOTS:
            part = getattr(self, slot)
            if part is not None:
                manifest[slot] = describe(part)
        manifest["pace"] = vars(self.pace)
        manifest["packages"] = list(packages)
        return manifest
