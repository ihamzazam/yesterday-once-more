"""Crypto primitives of the WannaCry v2 lab, unchanged in behaviour.

RSA-2048 keypairs, a hybrid seal (ephemeral AES-256-GCM key wrapped with
RSA-OAEP-SHA256) and atomic file writes.
"""

import base64
import json
import os
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16
RSA_BITS = 2048


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def write_atomic(path: Path, data: bytes, mode: int = None):
    """Replace one file after flushing its complete new contents to disk.

    mkstemp creates 0600 files; pass ``mode`` for files people should read.
    """
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".lab-")
    try:
        if mode is not None:
            os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path: Path, value: dict, private: bool = False):
    """Save JSON with the same atomic replacement, optionally owner-only."""
    data = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    if private:
        old_umask = os.umask(0o077)
        try:
            write_atomic(path, data)
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)
    else:
        write_atomic(path, data)


def new_rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def priv_pem_from(private) -> bytes:
    return private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def pub_pem(public) -> bytes:
    return public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_priv_pem(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def load_pub_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


def fingerprint(pub_pem_text: str) -> str:
    from hashlib import sha256
    return sha256(pub_pem_text.encode("ascii")).hexdigest()[:16]


_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


def seal_with_rsa_pub(public, plaintext: bytes) -> dict:
    """Seal bytes to one RSA public key (AES-256-GCM + RSA-OAEP wrap)."""
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped = public.encrypt(aes_key, _OAEP)
    return {"wrap": b64(wrapped), "nonce": b64(nonce), "ct": b64(ciphertext)}


def unseal_with_rsa_priv(private, sealed: dict) -> bytes:
    """Open a seal produced by seal_with_rsa_pub with the matching private key."""
    aes_key = private.decrypt(unb64(sealed["wrap"]), _OAEP)
    return AESGCM(aes_key).decrypt(unb64(sealed["nonce"]), unb64(sealed["ct"]), None)


def new_file_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def encrypt_blob(key: bytes, data: bytes, context: bytes) -> tuple:
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, data, context)


def decrypt_blob(key: bytes, nonce: bytes, ciphertext: bytes, context: bytes) -> bytes:
    """AES-GCM: raises cryptography.exceptions.InvalidTag on any tampering."""
    return AESGCM(key).decrypt(nonce, ciphertext, context)


def new_attacker_keys() -> dict:
    """The attacker keypair. Generated at build time by the service."""
    private = new_rsa_keypair()
    return {
        "attacker_priv_pem_b64": b64(priv_pem_from(private)),
        "attacker_pub_pem": pub_pem(private.public_key()).decode("ascii"),
    }
