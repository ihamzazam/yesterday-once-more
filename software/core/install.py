"""Build time: copy a piece's runtime code, settings and launchers onto nodes.

Every node that gets a toolkit package also gets:

    /opt/yom/etc/host.json    who am I  (host id, asn, name, ip)
    /opt/yom/etc/guard.json   containment: the emulator's own network prefixes
    /opt/yom/bin/*            launchers, also linked into /usr/local/bin

and is marked so ``use_base_image()`` can move it onto the prebuilt image
(python3 + cryptography + eth-account), which keeps builds free of pip.
"""

from pathlib import Path

from software.core import settings as yom_settings
from software.core.guard import MARKER
from software.core.payload import PayloadPackage

ROOT = yom_settings.DEFAULT_ROOT
SOFTWARE_DIR = Path(__file__).resolve().parents[1]
CORE_RUNTIME = ("settings.py", "events.py", "guard.py", "ready.py", "tui.py", "payload.py")

BASE_IMAGE = "yom-base:1"
BASE_IMAGE_SOFTWARE = ["python3", "python3-pip", "python3-cryptography"]
BASE_NEEDS = ["python3", "py:cryptography", "py:eth_account"]

NODE_ATTRIBUTE = "yom_packages"


# --------------------------------------------------------------------------
# Building packages
# --------------------------------------------------------------------------

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def runtime_files(*pieces: str) -> dict:
    """Runtime source of core + the named pieces, keyed by path under the root."""
    files = {
        "software/__init__.py": _read(SOFTWARE_DIR / "__init__.py"),
        "software/core/__init__.py": _read(SOFTWARE_DIR / "core" / "__init__.py"),
    }
    for name in CORE_RUNTIME:
        files[f"software/core/{name}"] = _read(SOFTWARE_DIR / "core" / name)
    for piece in pieces:
        piece_dir = SOFTWARE_DIR / piece
        files[f"software/{piece}/__init__.py"] = _read(piece_dir / "__init__.py")
        runtime = piece_dir / "runtime"
        for path in sorted(runtime.rglob("*")):
            if path.is_dir() or "__pycache__" in path.parts or path.suffix in (".pyc",):
                continue
            rel = path.relative_to(SOFTWARE_DIR)
            files[f"software/{rel.as_posix()}"] = _read(path)
    for rel, text in files.items():
        if rel.endswith(".py") and ("import seedemu" in text or "from seedemu" in text):
            raise AssertionError(f"runtime file imports seedemu: {rel}")
    return files


def launcher(name: str, module: str) -> dict:
    """A /opt/yom/bin/<name> shell launcher for ``python3 -m <module>``."""
    text = (
        "#!/bin/sh\n"
        f"export YOM_ROOT=\"${{YOM_ROOT:-{ROOT}}}\"\n"
        "export PYTHONPATH=\"$YOM_ROOT${PYTHONPATH:+:$PYTHONPATH}\"\n"
        f"exec python3 -m {module} \"$@\"\n"
    )
    return {f"bin/{name}": text}


def package(name: str, pieces, settings: dict = None, launchers: dict = None,
            start: str = None, needs=None, extra_files: dict = None) -> PayloadPackage:
    files = runtime_files(*pieces)
    for cmd, module in (launchers or {}).items():
        files.update(launcher(cmd, module))
    files.update(extra_files or {})
    return PayloadPackage(name, files, settings or {}, start, list(needs or BASE_NEEDS))


# --------------------------------------------------------------------------
# Network facts
# --------------------------------------------------------------------------

def host_identity(node) -> dict:
    ifaces = node.getInterfaces()
    ip = str(ifaces[0].getAddress()) if ifaces else ""
    return {"host": f"as{node.getAsn()}-{node.getName()}", "asn": node.getAsn(),
            "name": node.getName(), "ip": ip}


def node_ip(node) -> str:
    ifaces = node.getInterfaces()
    if not ifaces:
        raise ValueError(f"as{node.getAsn()}/{node.getName()} has no interface yet")
    return str(ifaces[0].getAddress())


def lab_prefixes(emulator) -> list:
    """Every network prefix of the emulation: the containment boundary."""
    prefixes = []
    for (_, kind, _), obj in emulator.getRegistry().getAll().items():
        if kind == "net":
            prefix = str(obj.getPrefix())
            if prefix not in prefixes:
                prefixes.append(prefix)
    return sorted(prefixes)


def resolve_node(emulator, vnode_or_node):
    """A physical node from a vnode name (binding) or a node object.

    seedemu's getBindingFor/resolvVnode only work for vnodes that some seedemu
    Service installed a server on. Toolkit pieces also install onto plain
    hosts (the attacker), so fall back to matching the Binding's filter
    (asn / nodeName / ip) against the registry ourselves.
    """
    if not isinstance(vnode_or_node, str):
        return vnode_or_node
    vnode = vnode_or_node
    try:
        return emulator.getBindingFor(vnode)
    except AssertionError:
        pass
    import re

    for binding in emulator.getBindings():
        if not binding.shoudBind(vnode):
            continue
        f = binding.filter
        matches = []
        for (scope, kind, name), node in emulator.getRegistry().getAll().items():
            if kind != "hnode":
                continue
            if f.asn is not None and node.getAsn() != f.asn:
                continue
            if f.nodeName is not None and not re.compile(f.nodeName).fullmatch(name):
                continue
            if f.ip is not None and f.ip not in [str(i.getAddress()) for i in node.getInterfaces()]:
                continue
            matches.append(node)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError(f"binding for {vnode} matches {len(matches)} hosts; make its filter exact")
    raise ValueError(f"no binding matches vnode {vnode}")


# --------------------------------------------------------------------------
# Installing
# --------------------------------------------------------------------------

def prepare_node(emulator, node, root: str = ROOT):
    """Identity, guard, launcher linking: once per node."""
    if node.getAttribute(NODE_ATTRIBUTE, None) is not None:
        return
    node.setAttribute(NODE_ATTRIBUTE, [])
    node.setFile(f"{root}/etc/host.json", yom_settings.dumps(host_identity(node)))
    node.setFile(f"{root}/etc/guard.json",
                 yom_settings.dumps({"prefixes": lab_prefixes(emulator), "marker": MARKER}))
    node.appendStartCommand(
        f"mkdir -p {root}/var/log && chmod +x {root}/bin/* 2>/dev/null; "
        f"for f in {root}/bin/*; do [ -e \"$f\" ] && ln -sf \"$f\" /usr/local/bin/; done"
    )


def install_package(emulator, node, pkg: PayloadPackage, root: str = ROOT, start: bool = True):
    """Stage a package onto a node (direct install, no carrier)."""
    node = resolve_node(emulator, node)
    prepare_node(emulator, node, root)
    pkg = pkg.resolve(emulator)
    for rel, text in pkg.files.items():
        node.setFile(f"{root}/{rel}", text)
    for piece, value in pkg.settings.items():
        node.setFile(f"{root}/etc/{piece}.json", yom_settings.dumps(value))
    if start and pkg.start:
        node.appendStartCommand(
            f"({pkg.start}) >> {root}/var/log/{pkg.name}.log 2>&1", fork=True
        )
    node.getAttribute(NODE_ATTRIBUTE).append(pkg.name)
    return pkg


def use_base_image(compiler, emulator, image: str = BASE_IMAGE):
    """Run every toolkit node on the prebuilt base image (see images/)."""
    from seedemu.compiler import DockerImage
    from seedemu.compiler.DockerImageConstant import BASE_IMAGE as SEEDEMU_BASE

    if image not in [img.getName() for img, _ in compiler.getImages()]:
        # subset: everything the stock seedemu-base image has, so the compiler
        # does not apt-get install it again on top of ours.
        compiler.addImage(DockerImage(image, BASE_IMAGE_SOFTWARE, local=False,
                                      subset=SEEDEMU_BASE))
    count = 0
    for (_, kind, _), obj in emulator.getRegistry().getAll().items():
        if kind == "hnode" and obj.getAttribute(NODE_ATTRIBUTE, None) is not None:
            compiler.setImageOverride(obj, image)
            count += 1
    return count
