"""Build time: copy a folder of files to many nodes in one call.

    place_files(emu, victims, CASE / "victim_files", "/home/seed/Documents")

``victims`` may be node objects or vnode names (resolved through the
emulator's bindings at render time). Each destination folder is marked as a
lab folder (``.yom-lab``), which is what ``core.guard`` checks before any
runtime touches files there.
"""

import itertools
from pathlib import Path

from seedemu.core import Layer

from software.core.guard import MARKER
from software.core.install import resolve_node

MARKER_TEXT = "This folder belongs to a SEED lab. Toolkit runtimes may change files here.\n"
_COUNTER = itertools.count(1)


def _apply(node, files, source: Path, dest: str, mark: bool, owner: str):
    for path in files:
        node.importFile(str(path), f"{dest}/{path.relative_to(source).as_posix()}")
    if mark:
        node.setFile(f"{dest}/{MARKER}", MARKER_TEXT)
    if owner:
        node.appendStartCommand(f"chown -R {owner}:{owner} {dest} 2>/dev/null || true")


class _PlaceFilesLayer(Layer):
    def __init__(self, vnodes, args):
        super().__init__()
        self.vnodes = vnodes
        self.args = args
        self.name = f"PlaceFiles{next(_COUNTER)}"
        self.addDependency("Base", False, False)

    def getName(self) -> str:
        return self.name

    def render(self, emulator):
        for vnode in self.vnodes:
            _apply(resolve_node(emulator, vnode), *self.args)


def place_files(emulator, nodes, source, dest: str, mark: bool = True, owner: str = "seed"):
    source = Path(source).resolve()
    if not source.is_dir():
        raise ValueError(f"no such folder: {source}")
    files = [p for p in sorted(source.rglob("*")) if p.is_file()]
    if not files:
        raise ValueError(f"{source} is empty")
    dest = dest.rstrip("/")
    args = (files, source, dest, mark, owner)
    vnodes = [n for n in nodes if isinstance(n, str)]
    for node in nodes:
        if not isinstance(node, str):
            _apply(node, *args)
    if vnodes:
        emulator.addLayer(_PlaceFilesLayer(vnodes, args))
    return [p.relative_to(source).as_posix() for p in files]
