"""Base class for one entry of the vulnerability catalogue.

A vulnerability is a PAIR: the hole (what to install on victims) and the
break-in that matches it (what the worm uses). Keeping both halves in one
class is what stops them from drifting apart.
"""


class Vulnerability:
    #: Unique id. A break-in names it to say which hole it fits.
    name = ""
    #: The port the hole listens on.
    port = 0
    #: What the Docker host must provide, in plain words (for the README).
    needs_host = ()

    def install(self, node) -> None:
        """Put the hole on one node: files, software and start commands."""
        raise NotImplementedError

    def exploit(self):
        """The break-in that matches this hole, to be handed to a Worm."""
        raise NotImplementedError

    def check_host(self) -> list:
        """Problems with the machine the emulation runs on. Empty means none.

        Called at build time; each problem is printed as a warning.
        """
        return []
