#!/usr/bin/env python3
"""Y51 WannaCry: one-shot, read-only status of a victim host.

Run on a victim:   y51-check-state          (or --json for tests)

The story-level checks live here, not in the ransomware: the five victim
documents are compared against the SHA-256 baseline taken from
cases/Y51_wannacry/victim_files at build time. It also summarises the shared
event log and, when a payment is attached, the chain. Sends no transactions.
"""

import argparse
import hashlib
import json
from pathlib import Path

from software.core import events, settings

CASE = "y51_check"


def file_states(cfg: dict) -> dict:
    folder = Path(cfg["folder"])
    suffix = cfg["suffix"]
    out = {}
    for name, digest in sorted(cfg["baseline"].items()):
        plain = folder / name
        envelope = folder / (name + suffix)
        if plain.is_file() and envelope.is_file():
            out[name] = "INCONSISTENT"
        elif envelope.is_file():
            out[name] = "ENCRYPTED"
        elif plain.is_file():
            ok = hashlib.sha256(plain.read_bytes()).hexdigest() == digest
            out[name] = "ORIGINAL" if ok else "CHANGED"
        else:
            out[name] = "MISSING"
    return out


def chain_state() -> dict:
    if not settings.exists("ransom_payment"):
        return {"attached": False}
    from software.ransom_payment.runtime.victim_client import Client

    client = Client()
    info = {"attached": True, "chain_id": client.chain_id, "price": client.price_text,
            "wallet": client.wallet_address(), "request_id": client.request_id()}
    try:
        info.update(client.contract_status())
        if info["wallet"]:
            info["balance"] = client.format_ether(client.balance())
    except (OSError, RuntimeError, ValueError) as error:
        info["error"] = str(error)
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    cfg = settings.load(CASE)
    files = file_states(cfg)
    log = [(e["piece"], e["event"]) for e in events.read()]
    report = {
        "host": settings.host().get("host"),
        "files": files,
        "all_original": all(v == "ORIGINAL" for v in files.values()),
        "all_encrypted": all(v == "ENCRYPTED" for v in files.values()),
        "events": [f"{p}.{e}" for p, e in log],
        "chain": chain_state(),
    }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    print(f"host:     {report['host']}")
    chain = report["chain"]
    if chain["attached"]:
        alive = chain.get("code_bytes", 0) > 0
        print(f"chain:    id {chain['chain_id']}, ransom {chain['price']}")
        if "address" in chain:
            print(f"contract: {chain['address']} "
                  f"({chain['code_bytes']} bytes, {'ALIVE' if alive else 'DEAD - deployment failed!'})")
        if "error" in chain:
            print(f"          unreachable: {chain['error']}")
        print(f"wallet:   {chain['wallet'] or 'none yet (participant menu, option 6)'}"
              + (f"  balance {chain['balance']} lab ETH" if chain.get("balance") else ""))
        print(f"request:  {'id ' + str(chain['request_id']) if chain['request_id'] is not None else 'not paid yet'}")
    print(f"files vs baseline ({cfg['folder']}):")
    for name, state in files.items():
        print(f"  {name:<16} {state}")
    print("events:   " + (", ".join(report["events"]) or "none"))


if __name__ == "__main__":
    main()
