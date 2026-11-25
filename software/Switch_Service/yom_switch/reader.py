"""The worm's "when to stop" slot, read from the switch: the WannaCry way.

The real WannaCry began by trying to load a long nonsense domain over HTTP.
Nobody had registered the domain, so nothing answered, and it went to work.
When a researcher registered it, new copies got an answer and stopped.

This plug does the same two steps. It asks the lab's DNS server whether the
domain has an address, and if it has one it tries to load it over HTTP. It
stops the worm only if something really answers.

Rules for this file: standard library only, and no import from the worm
package. It has to run on any machine the body lands on.
"""

import socket

from .dnsquery import query

SLOT = "governor"


class SwitchUnreachable(Exception):
    """The switch did not answer. The worm must stop rather than guess."""


def answers(address: str, domain: str, port: int = 80, timeout: float = 2.0) -> bool:
    """True if `address` answers an HTTP request for `domain`, as loading it would."""
    request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode("ascii")
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            return bool(sock.recv(256))
    except OSError:
        return False


class DnsKillSwitch:
    """Stop the worm as soon as the kill-switch domain answers."""

    SLOT = SLOT

    def __init__(self, domain, server=None, port=53, http_port=80, timeout=2.0, tries=3,
                 every_round=True):
        self.domain = domain
        self.server = server          # the switch's address; the Worm installer fills it in
        self.port = port              # where the switch answers DNS questions
        self.http_port = http_port    # where the registered domain would answer HTTP
        self.timeout = timeout
        self.tries = tries
        # The real worm checked once, when it started, so registering the domain
        # did not stop copies that were already running. Checking before every
        # attempt lets a teacher stop a live outbreak; False gives the exact
        # behaviour.
        self.every_round = every_round
        self._checked = False

    def allowed(self) -> bool:
        """True while the worm may keep spreading."""
        if self._checked and not self.every_round:
            return True
        state, address = query(self.server, self.domain, self.timeout, self.tries, self.port)
        if state is None:
            raise SwitchUnreachable(
                "the stop-signal server at {} did not answer ({} tries)".format(
                    self.server, self.tries
                )
            )
        if state == "refused":
            raise SwitchUnreachable(
                "the switch at {} refused to answer for {}; is that name inside its zone?".format(
                    self.server, self.domain
                )
            )
        self._checked = True
        if address is None:
            return True               # the domain is not registered: nothing can answer
        if answers(address, self.domain, self.http_port, self.timeout):
            return False              # registered, and it answers: stop
        return True                   # has an address but nothing answers: the real worm went on
