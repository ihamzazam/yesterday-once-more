"""Per-piece settings: written at build time, read inside the container.

Build side:  ``settings_path("ransomware")`` names the file a service writes
             (as JSON) onto a node; ``dumps()`` renders it.
Run side:    ``load("ransomware")`` reads it back. A runtime reads nothing else.

Everything lives under one root (``$YOM_ROOT``, default ``/opt/yom``) so the
same code runs in a container and in a unit test's temporary folder.
No seedemu imports here: this module ships into containers.
"""

import json
import os
from pathlib import Path

DEFAULT_ROOT = "/opt/yom"


def root() -> Path:
    return Path(os.environ.get("YOM_ROOT", DEFAULT_ROOT))


def settings_path(piece: str, base: Path = None) -> Path:
    return (base or root()) / "etc" / f"{piece}.json"


def state_dir(piece: str, base: Path = None, create: bool = True) -> Path:
    path = (base or root()) / "var" / piece
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def exists(piece: str, base: Path = None) -> bool:
    return settings_path(piece, base).is_file()


def load(piece: str, base: Path = None) -> dict:
    path = settings_path(piece, base)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise RuntimeError(
            f"no settings for '{piece}' at {path}; was this piece installed on this host?"
        ) from None


def host(base: Path = None) -> dict:
    """This host's identity (written by core.install): host id, asn, name, ip."""
    if exists("host", base):
        return load("host", base)
    return {"host": os.uname().nodename}


def dumps(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def write(piece: str, value: dict, base: Path = None) -> Path:
    """Write settings directly (tests and run-time unpacking use this)."""
    path = settings_path(piece, base)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(value), encoding="utf-8")
    return path
