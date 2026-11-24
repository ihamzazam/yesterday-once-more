"""A smallest-possible DNS client: one A question, sent straight to one server.

The worm and the switch tool must not depend on how a machine is told to
resolve names, so neither uses the system resolver. They ask the switch's
server by its address and read the answer code themselves.
"""

import os
import socket


def ask(server: str, name: str, timeout: float = 2.0, tries: int = 3, port: int = 53):
    """Ask `server` for an A record of `name`.

    Returns "exists", "missing" or "refused" (the server answered, but not for
    this name), or None when no answer arrived at all.
    """
    labels = name.rstrip(".").split(".")
    packet = b"".join(bytes([len(part)]) + part.encode("ascii") for part in labels)
    packet += b"\x00"                                     # end of the name
    packet += b"\x00\x01\x00\x01"                         # type A, class IN
    for _ in range(tries):
        ident = os.urandom(2)
        header = ident + b"\x00\x00" + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(header + packet, (server, port))
                while True:
                    reply, _ = sock.recvfrom(4096)
                    if reply[:2] != ident:
                        continue                            # an answer to someone else
                    code = reply[3] & 0x0F                 # response code
                    answers = int.from_bytes(reply[6:8], "big")
                    if code == 3:
                        return "missing"                   # NXDOMAIN: no such name
                    if code == 0:
                        return "exists" if answers else "missing"
                    return "refused"
        except OSError:
            pass                                          # no answer: try again
    return None
