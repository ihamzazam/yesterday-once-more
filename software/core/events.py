"""The shared event log: one JSON object per line.

Every runtime calls ``emit("encrypted", piece="ransomware", files=5)``.
check_state, tests and dashboards call ``read()``.

Line format: {"ts": <unix float>, "host": "<host id>", "piece": "...",
              "event": "...", ...fields}
"""

import fcntl
import json
import time
from pathlib import Path

from software.core import settings


def log_path(base: Path = None) -> Path:
    return (base or settings.root()) / "var" / "events.jsonl"


def emit(event: str, piece: str = "", base: Path = None, **fields) -> dict:
    record = {
        "ts": round(time.time(), 3),
        "host": settings.host(base).get("host", ""),
        "piece": piece,
        "event": event,
    }
    record.update(fields)
    path = log_path(base)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, sort_keys=True) + "\n"
    with path.open("a", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(line)
        stream.flush()
    return record


def read(base: Path = None, piece: str = None, event: str = None) -> list:
    path = log_path(base)
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if piece and record.get("piece") != piece:
            continue
        if event and record.get("event") != event:
            continue
        out.append(record)
    return out


def last(event: str, piece: str = None, base: Path = None):
    found = read(base, piece=piece, event=event)
    return found[-1] if found else None


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Print the shared event log.")
    parser.add_argument("--piece")
    parser.add_argument("--event")
    args = parser.parse_args()
    for record in read(piece=args.piece, event=args.event):
        print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
