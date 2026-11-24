"""Test helpers: settings for a lab Documents folder in a temp root."""

from software.ransomware.runtime import crypto
from software.ransomware.runtime.targets import WANNACRY_EXTENSIONS

SUFFIX = ".WNCRY"


def lab_settings(folder, scheme="wannacry", extensions=WANNACRY_EXTENSIONS, payment=False):
    keys = crypto.new_attacker_keys()
    cfg = {
        "family": "WannaCry", "scheme": scheme, "suffix": SUFFIX, "magic": "WANACRY!",
        "attacker_pub_pem": keys["attacker_pub_pem"], "delete_originals": True,
        "targets": {"folders": [str(folder)], "extensions": extensions,
                    "exclude": ["READ_ME.txt"], "recursive": True},
        "note": {"filename": "READ_ME.txt", "text": "Lab note. Open ${menu_cmd}."},
        "ui": {"title": "SEED INCIDENT LAB", "subtitle": "test"},
        "countdown_hours": None, "trigger": {"mode": "manual"}, "payment": payment,
        "commands": {"menu": "yom-ransomware menu", "decrypt": "yom-ransomware decrypt",
                     "detonate": "yom-ransomware detonate"},
        "needs": ["python3"],
    }
    return cfg, keys
