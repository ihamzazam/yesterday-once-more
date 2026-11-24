"""Headless pay-and-recover flow against an in-memory payment client.

The fake implements the victim-client interface (contract 3). Its
``await_key`` answers with the attacker release tool, which is what the real
watcher does on the attacker host. The real chain is covered by the in-
container run (see cases/Y51_wannacry/README.md).
"""

from software.conftest import SAMPLES, write_settings
from software.ransomware.runtime import engine, headless
from software.ransomware.tests.helpers import lab_settings


class FakeClient:
    price_wei = 10**18
    fund_max = 5
    cfg = {"rpc_url": "http://chain.invalid:8545", "chain_id": 18000}

    def __init__(self, attacker_keys):
        self.keys = attacker_keys
        self.wallet = None
        self.wei = 0
        self.blob = None
        self.paid_id = None

    def contract_status(self):
        return {"address": "0x" + "1" * 40, "code_bytes": 3038}

    def wallet_exists(self):
        return self.wallet is not None

    def create_wallet(self, password):
        self.wallet = "0x" + "2" * 40

    def wallet_address(self):
        return self.wallet

    def balance(self, address=None):
        return self.wei

    def buy(self, amount, address=None):
        self.wei += amount * 10**18

    @staticmethod
    def format_ether(wei):
        return str(wei // 10**18)

    def register(self, blob):
        self.blob = self.blob or blob

    def is_paid(self):
        return self.paid_id is not None

    def request_id(self):
        return self.paid_id

    def pay(self, password):
        assert self.wei >= self.price_wei and self.paid_id is None
        self.wei -= self.price_wei
        self.paid_id = 0
        return {"request_id": 0, "transaction_hash": "0xabc"}

    def await_key(self, timeout=600):
        return engine.release(self.keys, self.blob)


def test_headless_pay_and_recover(yom_root, documents, monkeypatch):
    monkeypatch.setattr(headless.ready, "wait_rpc", lambda *a, **k: True)
    cfg, keys = lab_settings(documents, extensions=None, payment=True)
    write_settings(yom_root, "ransomware", cfg)
    client = FakeClient(keys)

    summary = headless.run("pw", timeout=5, client=client)

    assert summary["ok"] and summary["restored"] == len(SAMPLES)
    assert client.paid_id == 0 and client.wei == 10**18   # paid exactly once
    for name, data in SAMPLES.items():
        assert (documents / name).read_bytes() == data


def test_headless_rerun_does_not_pay_twice(yom_root, documents, monkeypatch):
    monkeypatch.setattr(headless.ready, "wait_rpc", lambda *a, **k: True)
    cfg, keys = lab_settings(documents, extensions=None, payment=True)
    write_settings(yom_root, "ransomware", cfg)
    client = FakeClient(keys)
    headless.run("pw", timeout=5, client=client)
    # A second run on a recovered host must not register or pay again.
    rw = engine.Ransomware()
    rw.reply_path.unlink()
    headless.run("pw", timeout=5, client=client)
    assert client.paid_id == 0
