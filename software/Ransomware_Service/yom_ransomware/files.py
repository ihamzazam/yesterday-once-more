"""Locking and unlocking the files of one folder.

This is a lab. It only ever touches the files that sit directly in one folder
that a case filled with documents: no subfolders, no links, nothing outside.
The original v2 encrypted five texts built into the program; here the real
files on the disk are encrypted, so any case can bring its own documents.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import paths
from .keys import b64, sha256, unb64, write_atomic

MAGIC = b"Y04LAB1\n"
NONCE_SIZE = 12
TAG_SIZE = 16

#: Folders that must never be locked, however a case is written.
NEVER_LOCK = {
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/home/seed", "/lib", "/opt",
    "/proc", "/root", "/sbin", "/sys", "/tmp", "/usr", "/var",
}


def check_folder(folder) -> Path:
    """Refuse anything that does not look like a folder of documents.

    The system-folder rule comes first, so it holds even for a path that does
    not exist.
    """
    folder = Path(folder)
    if str(folder.resolve()) in NEVER_LOCK:
        raise ValueError(f"refusing to lock {folder}: it is a system folder, not documents")
    if folder.is_symlink():
        raise ValueError(f"{folder} is a link; refusing to lock through it")
    if not folder.is_dir():
        raise ValueError(f"{folder} is not a folder")
    return folder


def documents_in(folder: Path):
    """The files directly in the folder: no subfolders, no links, not our note."""
    return sorted(
        path for path in folder.iterdir()
        if path.is_file() and not path.is_symlink()
        and path.name != paths.NOTE_NAME
        and not path.name.endswith(paths.LOCKED_SUFFIX)
    )


def _context(participant_id: str, name: str) -> bytes:
    return f"{participant_id}/{name}".encode("utf-8")


def encrypt_all(folder: Path, participant_id: str, file_key: bytes) -> dict:
    """Encrypt every document in memory. Returns {name: {nonce, ciphertext, sha256}}."""
    record = {}
    for path in documents_in(folder):
        plain = path.read_bytes()
        nonce = os.urandom(NONCE_SIZE)
        record[path.name] = {
            "nonce": b64(nonce),
            "ciphertext": b64(AESGCM(file_key).encrypt(nonce, plain, _context(participant_id, path.name))),
            "sha256": sha256(plain),
        }
    return record


def apply_lock(folder: Path, record: dict):
    """Replace each document with its .WNCRY envelope and remove the original."""
    for name, entry in record.items():
        write_atomic(
            folder / (name + paths.LOCKED_SUFFIX),
            MAGIC + unb64(entry["nonce"]) + unb64(entry["ciphertext"]),
        )
        (folder / name).unlink()


def unlock(folder: Path, participant_id: str, file_key: bytes, record: dict):
    """Restore every document, check it against its recorded hash, drop the envelope."""
    restored = []
    for name in sorted(record):
        entry = record[name]
        plain = AESGCM(file_key).decrypt(
            unb64(entry["nonce"]), unb64(entry["ciphertext"]), _context(participant_id, name)
        )
        if sha256(plain) != entry["sha256"]:
            raise ValueError(f"recovered document does not match its original: {name}")
        write_atomic(folder / name, plain)
        (folder / (name + paths.LOCKED_SUFFIX)).unlink(missing_ok=True)
        restored.append(name)
    return restored


def inspect(folder: Path, record: dict = None) -> dict:
    """The state of every document, without changing anything."""
    folder = Path(folder)
    record = record or {}
    names = sorted({path.name for path in documents_in(folder)}
                   | {path.name[:-len(paths.LOCKED_SUFFIX)]
                      for path in folder.iterdir() if path.name.endswith(paths.LOCKED_SUFFIX)}
                   | set(record))
    state = {}
    for name in names:
        plain, envelope = folder / name, folder / (name + paths.LOCKED_SUFFIX)
        plain_here = plain.is_file() and not plain.is_symlink()
        envelope_here = envelope.is_file() and not envelope.is_symlink()
        if plain_here and envelope_here:
            state[name] = "INCONSISTENT: both the document and its .WNCRY envelope exist"
        elif envelope_here:
            state[name] = f"LOCKED ({paths.LOCKED_SUFFIX})"
        elif plain_here:
            if name in record and sha256(plain.read_bytes()) != record[name]["sha256"]:
                state[name] = "CHANGED: not the document that was locked"
            else:
                state[name] = "ORIGINAL"
        else:
            state[name] = "MISSING"
    return state
