"""core runtime: guard, payload package, events, settings, install."""

import ast
import json

import pytest

from software.core import events, guard, install, payload, settings


# ---- guard ----------------------------------------------------------------

def test_guard_ip_prefixes():
    g = guard.Guard(["10.151.0.0/24", "10.152.0.0/24"])
    assert g.ip_allowed("10.151.0.71")
    assert g.ip_allowed("10.152.0.9")
    assert not g.ip_allowed("10.153.0.1")
    assert not g.ip_allowed("8.8.8.8")
    assert not g.ip_allowed("not-an-ip")
    with pytest.raises(guard.ContainmentError):
        g.require_ip("192.168.1.1")


def test_guard_without_settings_allows_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("YOM_ROOT", str(tmp_path))
    g = guard.load()
    assert not g.ip_allowed("10.151.0.71")
    assert not g.folder_allowed(tmp_path)


def test_guard_marked_folders(tmp_path):
    lab = tmp_path / "lab"
    (lab / "sub").mkdir(parents=True)
    (lab / guard.MARKER).write_text("x")
    other = tmp_path / "other"
    other.mkdir()
    g = guard.Guard([])
    assert g.folder_allowed(lab)
    assert g.folder_allowed(lab / "sub")          # parents count
    assert not g.folder_allowed(other)
    with pytest.raises(guard.ContainmentError):
        g.require_folder(other)


def test_guard_symlink_into_lab_is_judged_by_target(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    lab = tmp_path / "lab"
    lab.mkdir()
    (lab / guard.MARKER).write_text("x")
    (lab / "escape").symlink_to(other)
    assert not guard.Guard([]).folder_allowed(lab / "escape")


def test_guard_loads_build_settings(yom_root):
    g = guard.load()
    assert g.prefixes() == ["10.151.0.0/24"]


# ---- payload package ------------------------------------------------------

def test_payload_roundtrip_and_unpack(tmp_path):
    pkg = payload.PayloadPackage(
        "demo",
        files={"software/demo/x.py": "print('hi')\n", "bin/demo": "#!/bin/sh\necho hi\n"},
        settings={"demo": {"a": 1}},
        start="demo run",
        needs=["python3", "py:json"],
    )
    again = payload.PayloadPackage.from_bytes(pkg.to_bytes())
    assert again.to_dict() == pkg.to_dict()
    written = again.unpack(tmp_path)
    assert (tmp_path / "software/demo/x.py").read_text() == "print('hi')\n"
    assert json.loads((tmp_path / "etc/demo.json").read_text()) == {"a": 1}
    assert (tmp_path / "bin/demo").stat().st_mode & 0o111
    assert len(written) == 3


def test_payload_lazy_settings_resolve():
    pkg = payload.PayloadPackage("demo", settings={"demo": lambda emu: {"ip": emu}})
    with pytest.raises(ValueError):
        pkg.to_bytes()
    assert pkg.resolve("10.0.0.1").settings == {"demo": {"ip": "10.0.0.1"}}


def test_payload_rejects_escaping_paths(tmp_path):
    for bad in ("../evil.py", "/etc/passwd"):
        with pytest.raises(ValueError):
            payload.PayloadPackage("x", files={bad: "x"}).unpack(tmp_path)


def test_payload_merge_conflicts():
    a = payload.PayloadPackage("a", files={"f": "1"}, needs=["python3"])
    a.merge(payload.PayloadPackage("b", files={"f": "1", "g": "2"}, needs=["py:json"]))
    assert set(a.files) == {"f", "g"} and a.needs == ["python3", "py:json"]
    with pytest.raises(ValueError):
        a.merge(payload.PayloadPackage("c", files={"f": "different"}))


def test_check_needs():
    assert payload.check_needs(["python3", "py:json", "file:/"]) == []
    assert payload.check_needs(["py:no_such_module_xyz", "cmd:no-such-cmd-xyz"]) == [
        "py:no_such_module_xyz", "cmd:no-such-cmd-xyz"]


# ---- events / settings ----------------------------------------------------

def test_events_emit_and_read(yom_root):
    events.emit("armed", piece="ransomware", trigger="manual")
    events.emit("encrypted", piece="ransomware", files=4)
    events.emit("paid", piece="ransom_payment", request_id=0)
    assert [e["event"] for e in events.read()] == ["armed", "encrypted", "paid"]
    assert events.read(piece="ransom_payment")[0]["request_id"] == 0
    assert events.last("encrypted")["files"] == 4
    assert events.read()[0]["host"] == "as151-victim1"


def test_settings_missing_is_a_clear_error(yom_root):
    with pytest.raises(RuntimeError, match="no settings for 'nope'"):
        settings.load("nope")


# ---- install (build side, no emulator needed) -----------------------------

def test_runtime_files_ship_no_seedemu():
    files = install.runtime_files("ransomware", "ransom_payment")
    assert "software/core/payload.py" in files
    assert "software/core/install.py" not in files      # build-only
    assert "software/ransomware/service.py" not in files
    assert not any("/tests/" in path for path in files)
    for path, text in files.items():
        if path.endswith(".py"):
            tree = ast.parse(text)
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                assert not any(n.split(".")[0] in ("seedemu", "chainseed") for n in names), path


def test_launcher_and_package():
    pkg = install.package("demo", ["ransomware"], settings={"demo": {}},
                          launchers={"yom-demo": "software.ransomware.runtime.main"},
                          start="yom-demo arm")
    assert "exec python3 -m software.ransomware.runtime.main" in pkg.files["bin/yom-demo"]
    assert pkg.start == "yom-demo arm"
    assert "py:cryptography" in pkg.needs
