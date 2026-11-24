"""Wait for the world to be ready before acting.

All waits poll with a deadline and raise ``TimeoutError`` naming what they
waited for. Stdlib only.
"""

import json
import socket
import time
from urllib.request import Request, urlopen


def wait(check, what: str, timeout: float = 300, interval: float = 3, quiet: bool = True):
    """Call ``check()`` until it returns a truthy value; return that value."""
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        try:
            value = check()
            if value:
                return value
        except Exception as error:  # noqa: BLE001 - any failure means "not yet"
            last_error = error
        if time.monotonic() >= deadline:
            detail = f" (last error: {last_error})" if last_error else ""
            raise TimeoutError(f"gave up waiting for {what} after {timeout:.0f}s{detail}")
        if not quiet:
            print(f"  waiting for {what}...", flush=True)
        time.sleep(interval)


def port_open(host: str, port: int, timeout: float = 2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_port(host: str, port: int, timeout: float = 300):
    return wait(lambda: port_open(host, port), f"{host}:{port}", timeout)


def http_json(url: str, payload: dict = None, timeout: float = 5):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data, {"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def wait_http(url: str, timeout: float = 300):
    def check():
        with urlopen(url, timeout=5) as response:
            return 200 <= response.status < 500
    return wait(check, url, timeout)


def wait_rpc(rpc_url: str, chain_id: int = None, timeout: float = 600):
    """Wait until an Ethereum JSON-RPC endpoint answers (with the right chain)."""
    def check():
        result = http_json(rpc_url, {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []})
        value = int(result["result"], 16)
        return chain_id is None or value == chain_id
    return wait(check, f"chain RPC {rpc_url}", timeout)


def wait_code(rpc_url: str, address: str, timeout: float = 600):
    """Wait until contract code exists at an address."""
    def check():
        result = http_json(rpc_url, {"jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
                                     "params": [address, "latest"]})
        return len(result.get("result") or "0x") > 2
    return wait(check, f"contract code at {address}", timeout)


def wait_dns(name: str, timeout: float = 120):
    return wait(lambda: socket.gethostbyname(name), f"DNS name {name}", timeout)
