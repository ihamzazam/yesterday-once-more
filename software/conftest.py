"""Shared pytest fixtures: a fake /opt/yom root in a temp folder."""

import json
from pathlib import Path

import pytest

from software.core.guard import MARKER

SAMPLES = {
    "notes.txt": b"Team handover notes\n",
    "budget.csv": b"department,allocated,spent\nit,8000,6200\n",
    "report.md": b"# Monthly report\n",
    "photo.jpg": b"\xff\xd8\xff\xe0 binary bytes \x00\x01",
}


@pytest.fixture
def yom_root(tmp_path, monkeypatch):
    root = tmp_path / "opt-yom"
    (root / "etc").mkdir(parents=True)
    monkeypatch.setenv("YOM_ROOT", str(root))
    (root / "etc" / "host.json").write_text(json.dumps({"host": "as151-victim1"}))
    (root / "etc" / "guard.json").write_text(json.dumps({"prefixes": ["10.151.0.0/24"],
                                                         "marker": MARKER}))
    return root


@pytest.fixture
def documents(tmp_path):
    folder = tmp_path / "home" / "seed" / "Documents"
    folder.mkdir(parents=True)
    (folder / MARKER).write_text("lab\n")
    for name, data in SAMPLES.items():
        (folder / name).write_bytes(data)
    return folder


def write_settings(root: Path, piece: str, value: dict):
    (root / "etc" / f"{piece}.json").write_text(json.dumps(value))
