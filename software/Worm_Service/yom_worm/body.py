"""The worm body: one tarball holding the code of every part and the settings file."""

import io
import json
import tarfile
from pathlib import Path


def pack(home, packages, manifest: dict) -> bytes:
    """Bundle the worm's package, the extra packages it uses, and worm.json."""
    home = Path(home)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name in ["yom_worm"] + list(packages):
            for path in sorted((home / name).rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts:
                    archive.add(path, arcname=path.relative_to(home).as_posix())
        data = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        info = tarfile.TarInfo("worm.json")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()
