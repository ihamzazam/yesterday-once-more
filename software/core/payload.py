"""The Payload Package format (contract 2).

A package is everything a payload needs on a host, as plain data:

    name      short name ("ransomware", "marker")
    files     {relative path under the root: text content}
    settings  {piece name: settings dict}   -> root/etc/<piece>.json
    start     shell command run after unpacking, or None (manual trigger)
    needs     ["python3", "py:cryptography", "cmd:setarch", "file:/x"]

Build side, a payload piece's ``asPayload()`` returns a package whose settings
values may still be callables ``f(emulator) -> dict``; ``resolve(emulator)``
turns them into data once the network is known. Run side, a carrier calls
``from_bytes(blob).unpack(root)`` and ``check_needs()`` before ``start``.

Stdlib only: this module ships into containers.
"""

import base64
import gzip
import importlib.util
import json
import os
import shutil
from pathlib import Path

FORMAT = "yom-payload/1"


class PayloadPackage:
    def __init__(self, name: str, files: dict = None, settings: dict = None,
                 start: str = None, needs=None):
        if not name or "/" in name:
            raise ValueError("a package needs a simple name")
        self.name = name
        self.files = dict(files or {})
        self.settings = dict(settings or {})
        self.start = start
        self.needs = list(needs or [])

    # ---- composition (build side) ----------------------------------------
    def merge(self, other: "PayloadPackage") -> "PayloadPackage":
        """Add another package's files/settings/needs (its start is ignored)."""
        for path, text in other.files.items():
            if path in self.files and self.files[path] != text:
                raise ValueError(f"conflicting file {path} while merging {other.name}")
            self.files[path] = text
        for piece, value in other.settings.items():
            if piece in self.settings and self.settings[piece] is not value:
                raise ValueError(f"settings for {piece} given twice")
            self.settings[piece] = value
        for need in other.needs:
            if need not in self.needs:
                self.needs.append(need)
        return self

    def resolve(self, emulator=None) -> "PayloadPackage":
        """Return a copy whose lazy settings have been computed."""
        settings = {}
        for piece, value in self.settings.items():
            settings[piece] = value(emulator) if callable(value) else value
        return PayloadPackage(self.name, self.files, settings, self.start, self.needs)

    # ---- wire format ------------------------------------------------------
    def to_dict(self) -> dict:
        for piece, value in self.settings.items():
            if callable(value):
                raise ValueError(f"settings for {piece} not resolved; call resolve(emulator)")
        return {"format": FORMAT, "name": self.name, "files": self.files,
                "settings": self.settings, "start": self.start, "needs": self.needs}

    def to_bytes(self) -> bytes:
        return gzip.compress(json.dumps(self.to_dict(), sort_keys=True).encode("utf-8"), mtime=0)

    @classmethod
    def from_dict(cls, data: dict) -> "PayloadPackage":
        if data.get("format") != FORMAT:
            raise ValueError(f"not a {FORMAT} package")
        return cls(data["name"], data["files"], data["settings"], data["start"], data["needs"])

    @classmethod
    def from_bytes(cls, blob: bytes) -> "PayloadPackage":
        return cls.from_dict(json.loads(gzip.decompress(blob).decode("utf-8")))

    def to_b64(self) -> str:
        return base64.b64encode(self.to_bytes()).decode("ascii")

    # ---- arrival (run side) -----------------------------------------------
    def unpack(self, root) -> list:
        """Write files + settings under root; return written paths."""
        root = Path(root)
        written = []
        for rel, text in self.files.items():
            target = _safe_join(root, rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            if rel.startswith("bin/"):
                target.chmod(0o755)
            written.append(target)
        for piece, value in self.settings.items():
            target = _safe_join(root, f"etc/{piece}.json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            written.append(target)
        return written


def _safe_join(root: Path, rel: str) -> Path:
    if rel.startswith("/") or ".." in Path(rel).parts:
        raise ValueError(f"package path escapes the root: {rel}")
    return root / rel


def check_needs(needs) -> list:
    """Return the needs this host does NOT meet (empty list = ready)."""
    missing = []
    for need in needs:
        kind, _, value = need.partition(":")
        if not value:
            kind, value = "cmd", kind
        if kind == "py":
            ok = importlib.util.find_spec(value) is not None
        elif kind == "cmd":
            ok = shutil.which(value) is not None
        elif kind == "file":
            ok = os.path.exists(value)
        else:
            ok = False
        if not ok:
            missing.append(need)
    return missing
