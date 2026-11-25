"""Helpers shared by the installers, the build-time half of every piece.

An installer puts three things on a node: the runtime package (plain Python
that runs inside the container), a settings file, and start commands. These
helpers keep that the same everywhere.
"""

import inspect
from pathlib import Path
import shutil
import subprocess

#: Where every piece lives inside a node.
HOME = "/opt/yom"

_TEXT_SUFFIXES = {".py", ".json", ".sh", ".txt", ".md", ".sol", ".abi"}


def stage_tree(node, source: Path, dest: str) -> int:
    """Copy a folder of runtime files onto a node.

    Text goes through setFile(); anything else (real binaries) is imported as
    a file. Returns the number of files staged.
    """
    count = 0
    for path in sorted(Path(source).rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        target = "{}/{}".format(dest, path.relative_to(source).as_posix())
        if path.suffix in _TEXT_SUFFIXES:
            node.setFile(target, path.read_text(encoding="utf-8"))
        else:
            node.importFile(str(path.resolve()), target)
        count += 1
    return count


def runtime_dir(plug_cls) -> Path:
    """The folder holding a worm part: what has to travel inside the worm body."""
    return Path(inspect.getfile(plug_cls)).resolve().parent


#: What a node needs to run any of our runtime packages.
RUNTIME_NEEDS = ("python3",)


def add_command(node, name: str, package: str) -> None:
    """Give a node a one-word command that starts a runtime package.

    Example: add_command(node, "worm", "yom_worm") gives the node `worm launch`.
    The Python the command needs is installed on the node as well, so nobody
    has to remember it.
    """
    node.setFile(
        "/usr/local/bin/{}".format(name),
        "#!/bin/bash\nPYTHONPATH={} exec python3 -m {} \"$@\"\n".format(HOME, package),
    )
    node.addSoftware(*RUNTIME_NEEDS)
    node.appendStartCommand("chmod +x /usr/local/bin/{}".format(name))


def address_of(node) -> str:
    """The node's first IP address. Only meaningful after the emulator renders."""
    return str(node.getInterfaces()[0].getAddress())


def reset_output(output: Path, image: str = "handsonsecurity/seedemu-base:2.0") -> None:
    """Remove a previous build folder, so that the lab can be built again.

    The Internet Map's traffic observer runs as root and writes files into
    that folder, so a plain removal fails with "Permission denied". Those
    files are removed through a throwaway container. A lab that is still
    running is left alone: its files must stay until it is stopped.
    """
    output = Path(output)
    if not output.exists():
        return
    running = subprocess.run(["docker", "compose", "ps", "-q"], cwd=output,
                             capture_output=True, text=True)
    if running.returncode == 0 and running.stdout.strip():
        raise SystemExit(
            f"{output.name} is still running. Stop it first with `docker compose down` in that folder."
        )
    try:
        shutil.rmtree(output)
    except PermissionError:
        subprocess.run(
            ["docker", "run", "--rm", "-v", "{}:/w".format(output.resolve()), image,
             "sh", "-c", "rm -rf /w/* /w/.[!.]*"],
            check=True, stdout=subprocess.DEVNULL,
        )
        shutil.rmtree(output)
