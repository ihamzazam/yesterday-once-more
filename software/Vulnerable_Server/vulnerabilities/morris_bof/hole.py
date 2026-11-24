"""The hole: the buffer-overflow server from Dr. Du's Morris worm example.

The vulnerable server and its helper `stack` are his, unchanged. `stack` is a
32-bit program with an executable stack, and the server feeds it whatever a
client sends. Sources are in assets/src; assets/NOTICE says where they come from.
"""

from pathlib import Path

from ..base import Vulnerability
from .yom_morris_bof.entry import MorrisBofEntry, aslr_setting

ASSETS = Path(__file__).resolve().parent / "assets"


class MorrisBufferOverflow(Vulnerability):
    name = "morris-bof"
    port = 9090
    needs_host = ("ASLR switched off on the Docker host", "a 64-bit host (the program is 32-bit)")

    def install(self, node):
        for binary in ("server", "stack"):
            node.importFile(str(ASSETS / binary), "/bof/{}".format(binary))
        node.appendStartCommand("chmod +x /bof/server /bof/stack")
        # Started the way his example starts it. Whatever this server and the
        # worm print on this machine shows up in `docker logs`.
        node.appendStartCommand("cd /bof && ./server", fork=True)

    def exploit(self):
        return MorrisBofEntry(port=self.port)

    def check_host(self):
        setting = aslr_setting()
        if setting == "0":
            return []
        return [
            "morris-bof needs ASLR switched off on the Docker host (it is {}). Until then the\n"
            "   worm refuses to launch. Fix:   sudo sysctl -w kernel.randomize_va_space=0\n"
            "   Restore afterwards:           sudo sysctl -w kernel.randomize_va_space=2".format(
                setting or "unknown")
        ]
