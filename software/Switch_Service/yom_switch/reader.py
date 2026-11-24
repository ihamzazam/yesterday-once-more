"""The worm's "when to stop" slot, read from the switch: WannaCry style.

The real WannaCry looked up a long nonsense domain before it went to work.
As long as the name did not exist it spread; the moment somebody registered
it, every copy stopped. Here the switch's DNS server plays the registry.

Rules for this file: standard library only, and no import from the worm
package. It has to run on any machine the body lands on.
"""

from .dnsquery import ask

SLOT = "governor"


class SwitchUnreachable(Exception):
    """The switch did not answer. The worm must stop rather than guess."""


class DnsKillSwitch:
    """Stop the worm as soon as `domain` exists on the switch."""

    SLOT = SLOT

    def __init__(self, domain, server=None, port=53, timeout=2.0, tries=3):
        self.domain = domain
        self.server = server          # the switch's address; the Worm installer fills it in
        self.port = port
        self.timeout = timeout
        self.tries = tries

    def allowed(self) -> bool:
        """True while the worm may keep spreading."""
        answer = ask(self.server, self.domain, self.timeout, self.tries, self.port)
        if answer == "missing":
            return True
        if answer == "exists":
            return False
        if answer == "refused":
            raise SwitchUnreachable(
                "the switch at {} refused to answer for {}; is that name inside its zone?".format(
                    self.server, self.domain
                )
            )
        raise SwitchUnreachable(
            "the stop-signal server at {} did not answer ({} tries)".format(self.server, self.tries)
        )
