"""The sinkhole's web responder and its run-time switch (contract 4).

While the sinkhole is ON, an HTTP GET to the kill-switch domain is answered
(200). While it is OFF, nothing listens on the port, so the request fails.
A worm that treats "it answered" as "stop" therefore halts when the sinkhole
is on and spreads when it is off, exactly like the 2017 domain registration.

    yom-sinkhole run          serve (started at boot)
    yom-sinkhole on|off       flip the switch, takes effect within a second
    yom-sinkhole status       print on/off
    yom-sinkhole hits         print the requests it has answered
"""

import argparse
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from software.core import events, settings

PIECE = "sinkhole"
POLL_SECONDS = 0.5


def state_file(base=None):
    return settings.state_dir(PIECE, base) / "state"


def get_state(base=None) -> str:
    path = state_file(base)
    if path.exists():
        value = path.read_text().strip()
        if value in ("on", "off"):
            return value
    return settings.load(PIECE, base).get("initial", "on")


def set_state(value: str, base=None):
    if value not in ("on", "off"):
        raise ValueError("state is 'on' or 'off'")
    state_file(base).write_text(value + "\n")
    events.emit(f"switched_{value}", piece=PIECE, base=base)


def make_handler(cfg: dict, base=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (f"{cfg['domain']} is sinkholed by the lab.\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            events.emit("hit", piece=PIECE, base=base, client=self.client_address[0],
                        host=self.headers.get("Host", ""), path=self.path)

        do_HEAD = do_GET

        def log_message(self, fmt, *args):
            pass

    return Handler


class Switchable:
    """Opens the port when the state is on and closes it when it is off."""

    def __init__(self, cfg: dict, base=None):
        self.cfg, self.base = cfg, base
        self.server = None

    def _open(self):
        self.server = ThreadingHTTPServer(("0.0.0.0", self.cfg["port"]),
                                          make_handler(self.cfg, self.base))
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _close(self):
        self.server.shutdown()
        self.server.server_close()
        self.server = None

    def step(self):
        want = get_state(self.base)
        if want == "on" and self.server is None:
            self._open()
        elif want == "off" and self.server is not None:
            self._close()

    def serving(self) -> bool:
        return self.server is not None


def run(base=None):
    cfg = settings.load(PIECE, base)
    sw = Switchable(cfg, base)
    events.emit("started", piece=PIECE, base=base, domain=cfg["domain"], state=get_state(base))
    while True:
        sw.step()
        time.sleep(POLL_SECONDS)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="yom-sinkhole", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["run", "on", "off", "status", "hits"])
    args = parser.parse_args(argv)
    if args.command == "run":
        run()
    elif args.command in ("on", "off"):
        set_state(args.command)
        print(f"sinkhole {args.command}")
    elif args.command == "status":
        print(get_state())
    else:
        for e in events.read(piece=PIECE, event="hit"):
            print(f"{e['ts']}  {e['client']}  {e['host']}{e['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
