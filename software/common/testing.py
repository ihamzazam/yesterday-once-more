"""A tiny fake of the worm around a part, so that a part can be tested without Docker."""

import socket


class FakeWorm:
    """Just enough of the worm's engine for a part that calls into it.

    `sent` records every (ip, port, data) the part hands over.
    """

    def __init__(self):
        self.sent = []
        self._bind_udp()

    def _bind_udp(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind(("127.0.0.1", 0))            # any free port
        self.udp.settimeout(0.05)

    @property
    def announce_port(self):
        return self.udp.getsockname()[1]

    def my_ip_toward(self, target):
        return "10.0.0.1"

    def exchange(self, ip, port, data, wait):
        self.sent.append((ip, port, data))

    def deliver(self, ip, port, data):
        self.sent.append((ip, port, data))
        return True

    def wait_answer(self, target):
        try:
            data, _ = self.udp.recvfrom(64)
            return data.decode().strip().lower()
        except socket.timeout:
            return None
