"""The web answer for the kill-switch domain.

Runs on the switch's machine. It answers every request with a plain page, the
way the server did that the researcher pointed the domain to. It is always
running, and it receives a request only once the domain is registered.

    PYTHONPATH=/opt/yom python3 -m yom_switch.responder [port]
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = b"<!doctype html><title>Registered</title><p>This domain is registered.\n"


class Handler(BaseHTTPRequestHandler):
    def _answer(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(PAGE)

    do_GET = _answer
    do_HEAD = _answer

    def log_message(self, fmt, *args):
        print("responder: {} asked for {}".format(self.address_string(), self.path), flush=True)


def main(port: int = 80):
    print("responder: answering HTTP on port {}".format(port), flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 80)
