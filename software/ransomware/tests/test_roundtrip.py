"""Encrypt -> exchange -> recover round trips on a temp lab folder."""

import json

import pytest
from cryptography.exceptions import InvalidTag

from software.conftest import SAMPLES, write_settings
from software.core.guard import MARKER, ContainmentError
from software.ransomware.runtime import crypto, engine
from software.ransomware.tests.helpers import SUFFIX, lab_settings

QUIET = {"echo": lambda *a, **k: None}


def setup(yom_root, folder, **kw):
    cfg, keys = lab_settings(folder, **kw)
    write_settings(yom_root, "ransomware", cfg)
    return engine.Ransomware(), keys


def test_seal_roundtrip():
    private = crypto.new_rsa_keypair()
    sealed = crypto.seal_with_rsa_pub(private.public_key(), b"lab bytes")
    assert crypto.unseal_with_rsa_priv(private, sealed) == b"lab bytes"
    with pytest.raises(ValueError):
        crypto.unseal_with_rsa_priv(crypto.new_rsa_keypair(), sealed)


@pytest.mark.parametrize("scheme", ["wannacry", "simple"])
def test_round_trip(yom_root, documents, scheme):
    rw, keys = setup(yom_root, documents, scheme=scheme, extensions=None)
    assert rw.state() == engine.PREPARED

    record = rw.detonate()
    assert len(record["files"]) == len(SAMPLES)
    for name in SAMPLES:
        assert not (documents / name).exists()
        assert (documents / (name + SUFFIX)).read_bytes().startswith(b"WANACRY!")
    assert rw.state() == engine.ENCRYPTED
    assert all(s.startswith("ENCRYPTED") for s in rw.inspect().values())

    blob = rw.request_blob(rw.save_request())
    assert b"PRIVATE KEY" not in blob
    file_key = rw.accept(json.loads(engine.release(keys, blob)))
    assert rw.state() == engine.GRANTED

    assert rw.recover(file_key, **QUIET) == len(SAMPLES)
    for name, data in SAMPLES.items():
        assert (documents / name).read_bytes() == data
        assert not (documents / (name + SUFFIX)).exists()
    assert rw.state() == engine.RECOVERED


def test_file_modes_survive(yom_root, documents):
    (documents / "notes.txt").chmod(0o640)
    rw, keys = setup(yom_root, documents, extensions=None)
    rw.detonate()
    assert (documents / ("notes.txt" + SUFFIX)).stat().st_mode & 0o777 == 0o640
    file_key = rw.accept(json.loads(engine.release(keys, rw.request_blob(rw.request()))))
    rw.recover(file_key, **QUIET)
    assert (documents / "notes.txt").stat().st_mode & 0o777 == 0o640


def test_detonate_is_idempotent(yom_root, documents):
    rw, _ = setup(yom_root, documents, extensions=None)
    first = rw.detonate()
    assert rw.detonate()["files"] == first["files"]
    assert len(list(documents.glob("*" + SUFFIX))) == len(SAMPLES)


def test_tampered_envelope_restores_nothing(yom_root, documents):
    rw, keys = setup(yom_root, documents, extensions=None)
    rw.detonate()
    file_key = rw.accept(json.loads(engine.release(keys, rw.request_blob(rw.request()))))
    victim = documents / ("notes.txt" + SUFFIX)
    data = bytearray(victim.read_bytes())
    data[-1] ^= 0x01
    victim.write_bytes(bytes(data))
    with pytest.raises(InvalidTag):
        rw.recover(file_key, **QUIET)
    assert not any((documents / name).exists() for name in SAMPLES)


def test_wrong_key_restores_nothing(yom_root, documents):
    rw, _ = setup(yom_root, documents, extensions=None)
    rw.detonate()
    with pytest.raises(InvalidTag):
        rw.recover(crypto.new_file_key(), **QUIET)
    assert not any((documents / name).exists() for name in SAMPLES)


def test_release_refuses_other_attacker(yom_root, documents):
    rw, _ = setup(yom_root, documents, extensions=None)
    rw.detonate()
    with pytest.raises(ValueError, match="different attacker key"):
        engine.release(crypto.new_attacker_keys(), rw.request_blob(rw.request()))


def test_unmarked_folder_is_refused(yom_root, documents):
    (documents / MARKER).unlink()
    rw, _ = setup(yom_root, documents, extensions=None)
    with pytest.raises(ContainmentError):
        rw.detonate()
    assert all((documents / name).exists() for name in SAMPLES)


def test_note_written_and_excluded(yom_root, documents):
    rw, _ = setup(yom_root, documents, extensions=None)
    assert rw.write_notes() == [documents / "READ_ME.txt"]
    assert "yom-ransomware menu" in (documents / "READ_ME.txt").read_text()
    rw.detonate()
    assert (documents / "READ_ME.txt").exists()
