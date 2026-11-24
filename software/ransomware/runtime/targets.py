"""Target rules: which files the ransomware takes.

    rules = TargetRules(folders=["/home/seed/Documents"],
                        extensions=WANNACRY_EXTENSIONS, exclude=["READ_ME.txt"],
                        suffix=".WNCRY")
    rules.collect(guard)   -> sorted list of Paths

Never follows symlinks, never takes its own envelopes, dotfiles or the lab
marker, and (with a guard) refuses folders that are not marked lab folders.
"""

import fnmatch
import os
from pathlib import Path

from software.core.guard import MARKER

# File types WannaCry 2.0 encrypted (from public analyses of the sample).
WANNACRY_EXTENSIONS = [
    ".der", ".pfx", ".key", ".crt", ".csr", ".p12", ".pem", ".odt", ".ott", ".sxw", ".stw",
    ".uot", ".3ds", ".max", ".3dm", ".ods", ".ots", ".sxc", ".stc", ".dif", ".slk", ".wb2",
    ".odp", ".otp", ".sxd", ".std", ".uop", ".odg", ".otg", ".sxm", ".mml", ".lay", ".lay6",
    ".asc", ".sqlite3", ".sqlitedb", ".sql", ".accdb", ".mdb", ".db", ".dbf", ".odb", ".frm",
    ".myd", ".myi", ".ibd", ".mdf", ".ldf", ".sln", ".suo", ".cs", ".c", ".cpp", ".pas", ".h",
    ".asm", ".js", ".cmd", ".bat", ".ps1", ".vbs", ".vb", ".pl", ".dip", ".dch", ".sch",
    ".brd", ".jsp", ".php", ".asp", ".rb", ".java", ".jar", ".class", ".sh", ".mp3", ".wav",
    ".swf", ".fla", ".wmv", ".mpg", ".vob", ".mpeg", ".asf", ".avi", ".mov", ".mp4", ".3gp",
    ".mkv", ".3g2", ".flv", ".wma", ".mid", ".m3u", ".m4u", ".djvu", ".svg", ".ai", ".psd",
    ".nef", ".tiff", ".tif", ".cgm", ".raw", ".gif", ".png", ".bmp", ".jpg", ".jpeg", ".vcd",
    ".iso", ".backup", ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".bak", ".tbk", ".bz2",
    ".paq", ".arc", ".aes", ".gpg", ".vmx", ".vmdk", ".vdi", ".sldm", ".sldx", ".sti", ".sxi",
    ".602", ".hwp", ".snt", ".onetoc2", ".dwg", ".pdf", ".wk1", ".wks", ".123", ".rtf", ".csv",
    ".txt", ".vsdx", ".vsd", ".edb", ".eml", ".msg", ".ost", ".pst", ".potm", ".potx", ".ppam",
    ".ppsx", ".ppsm", ".pps", ".pot", ".pptm", ".pptx", ".ppt", ".xltm", ".xltx", ".xlc",
    ".xlm", ".xlt", ".xlw", ".xlsb", ".xlsm", ".xlsx", ".xls", ".dotx", ".dotm", ".dot",
    ".docm", ".docb", ".docx", ".doc",
]

EXTENSION_PRESETS = {"wannacry": WANNACRY_EXTENSIONS}


class TargetRules:
    def __init__(self, folders, extensions=None, exclude=(), suffix: str = ".locked",
                 recursive: bool = True):
        if not folders:
            raise ValueError("target rules need at least one folder")
        if not suffix.startswith("."):
            raise ValueError("the suffix must start with a dot")
        self.folders = [Path(f) for f in folders]
        self.extensions = None if extensions is None else {e.lower() for e in extensions}
        self.exclude = list(exclude)
        self.suffix = suffix
        self.recursive = recursive

    @classmethod
    def from_settings(cls, cfg: dict) -> "TargetRules":
        t = cfg["targets"]
        return cls(t["folders"], t.get("extensions"), t.get("exclude", ()), cfg["suffix"],
                   t.get("recursive", True))

    def matches(self, path: Path) -> bool:
        name = path.name
        if name.startswith(".") or name == MARKER:
            return False
        if name.endswith(self.suffix):
            return False
        if any(fnmatch.fnmatch(name, pattern) for pattern in self.exclude):
            return False
        if self.extensions is not None and path.suffix.lower() not in self.extensions:
            return False
        return True

    def _walk(self, folder: Path):
        if self.recursive:
            for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
                for name in sorted(filenames):
                    yield Path(dirpath) / name
        else:
            for path in sorted(folder.iterdir()):
                yield path

    def _files(self, guard=None):
        for folder in self.folders:
            if guard is not None:
                guard.require_folder(folder)
            if folder.is_symlink() or not folder.is_dir():
                continue
            for path in self._walk(folder):
                if path.is_symlink() or not path.is_file():
                    continue
                yield path

    def collect(self, guard=None) -> list:
        """Plaintext files these rules would encrypt."""
        return [p for p in self._files(guard) if self.matches(p)]

    def envelopes(self, guard=None) -> list:
        """Envelopes (``*<suffix>``) present in the target folders."""
        return [p for p in self._files(guard) if p.name.endswith(self.suffix)]

    def display_name(self, path: Path) -> str:
        for folder in self.folders:
            try:
                rel = path.relative_to(folder)
            except ValueError:
                continue
            return rel.as_posix() if len(self.folders) == 1 else f"{folder.name}/{rel.as_posix()}"
        return str(path)
