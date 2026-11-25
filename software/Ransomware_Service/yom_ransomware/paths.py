"""Where the ransomware keeps its files on a machine."""

from pathlib import Path

#: On a victim: what the infection leaves behind.
STATE = Path("/opt/wannacry")
KEYLOG = STATE / "ransomware.json"          # keys, and the record of the locked files
RECORD = STATE / "participant.json"         # the victim's id
WALLET = STATE / "wallet.json"
REQUEST = STATE / "exchange_request.json"
REPLY = STATE / "exchange_reply.json"
ACCEPTED = STATE / "accepted.json"
CHAIN = STATE / "chain.json"

#: On the attacker: the operator's keys and the chain's details.
OPERATOR = Path("/opt/yom/ransom")
ATTACKER_KEYS = OPERATOR / "attacker_keys.json"
CHAIN_KEY = OPERATOR / "chain_key.json"
OPERATOR_CHAIN = OPERATOR / "chain.json"

#: The command the victim is left with. It starts the menu from the code the
#: worm brought.
MENU = Path("/usr/local/bin/ransom")

#: The folder a victim's files live in, unless a case says otherwise.
DOCUMENTS = "/home/seed/Documents"
NOTE_NAME = "@Please_Read_Me@.txt"
LOCKED_SUFFIX = ".WNCRY"
