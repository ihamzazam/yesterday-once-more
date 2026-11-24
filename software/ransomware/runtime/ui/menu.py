"""The participant workspace: the WannaCry v2 lab terminal UI.

Same screens, keys and wording as v2 (terminal_ui.py + participant.py). What
varies per scenario comes from settings: title, family name, note text, price
and countdown. The wallet, exchange and payment screens exist only when a
payment client is attached.
"""

from datetime import datetime
import fcntl
from getpass import getpass
import json
import random
import time

from cryptography.exceptions import InvalidTag

from software.core import settings
from software.core.tui import busy, field, heading, pause
from software.ransomware.runtime import crypto
from software.ransomware.runtime.engine import Ransomware

ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError)


def payment_client(rw: Ransomware):
    """The payment client, or None when no payment is attached (contract 3)."""
    if not rw.cfg.get("payment") or not settings.exists("ransom_payment", rw.base):
        return None
    from software.ransom_payment.runtime.victim_client import Client
    return Client(base=rw.base)


# ---------------------------------------------------------------------------
# Recovery step (option 5), ported from ransomware.run_recovery_step in v2
# ---------------------------------------------------------------------------

def grant_file_key(rw: Ransomware):
    """Accept the reply, save the key, print the grant; recover nothing."""
    reply = json.loads(rw.reply_path.read_text(encoding="utf-8"))
    file_key = rw.accept(reply)
    if rw.cfg["scheme"] == "wannacry":
        print("Attacker reply accepted; file key unsealed with recovered victim key.")
    else:
        print("Attacker reply accepted; file key received.")
    print()
    print("=" * 60)
    print("  KEY GRANTED - YOUR DECRYPTION KEY (copy it):")
    print()
    print(f"  {crypto.b64(file_key)}")
    print("=" * 60)
    print()
    print("Run the decryptor on this host and paste this key when asked:")
    print(f"  {rw.cfg['commands']['decrypt']}")
    print("It decrypts your documents and checks each one's AES-GCM")
    print("integrity tag. Nothing is recovered until you do.")
    return file_key


def run_recovery_step(rw: Ransomware, client, password: str = None, wait_timeout: int = 600):
    """One UI-driven step of the exchange, ending at the KEY GRANT.

      1. Before any payload: say so.
      2. No exchange yet: build the on-chain request (the inert sealed blob).
         With a wallet and a payment client, register it on-chain with real
         payment; the manual file-copy path remains the fallback otherwise.
      3. A reply is present: accept it, print KEY GRANTED, and STOP. The
         victim runs the decryptor with that key; recovery is manual.
    """
    rw.keylog()  # raises the "no keylog yet" message before any payload

    if rw.reply_path.exists():
        return grant_file_key(rw)

    if not rw.request_path.exists():
        on_chain = rw.save_request()
        print("EXCHANGE REQUEST (this is the payload that goes on the chain):")
        print(json.dumps(on_chain, indent=2))

    if client is not None:
        client.register(rw.request_blob(json.loads(rw.request_path.read_text(encoding="utf-8"))))
        # A paid request must NEVER be registered again: a second registration
        # would pay a second ransom.
        already_registered = client.is_paid()
        if client.wallet_exists() and (password or already_registered):
            try:
                if already_registered:
                    print(f"payment already made; waiting for the on-chain reply "
                          f"to request {client.request_id()} (no new payment)...")
                else:
                    result = client.pay(password)
                    print(f"registered on-chain: request id {result['request_id']}")
                    print(f"payment transaction: {result['transaction_hash']}")
                reply = client.await_key(wait_timeout)
                rw.reply_path.write_text(reply.decode("utf-8") + "\n", encoding="utf-8")
                print(f"attacker reply received on-chain; saved to {rw.reply_path}")
            except (OSError, RuntimeError, TimeoutError) as error:
                print(f"\nOn-chain exchange unavailable: {error}")
                print("Falling back to the manual copy path. Current instructions:")
            else:
                return grant_file_key(rw)

    print("\nNext: on the attacker machine run the reply step with the attacker")
    print("keys, then copy the reply output to:")
    print(f"  {rw.reply_path}")
    print("Then choose document recovery again to accept it and get your key.")
    return None


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------

def wallet_screen(client):
    balance = "Not checked"
    checked = "Use r to refresh"
    while True:
        heading("PARTICIPANT WALLET",
                f"Private chain {client.chain_id} / local password-protected keystore")
        exists = client.wallet_exists()
        address = client.wallet_address() if exists else None
        field("Address", address or "No wallet yet")
        field("Balance", balance)
        field("Last checked", checked)
        if address:
            print("\nSelect the full address above to copy using your terminal's copy shortcut.")
        print("\n[c] Create wallet   [r] Refresh balance   [l] Look up an address")
        print("[b] Back")
        choice = input("\nWallet > ").strip().lower()
        if choice == "b":
            return
        try:
            if choice == "c":
                if exists:
                    raise ValueError("your wallet already exists; its address is shown above")
                password = getpass("Choose a lab wallet password: ")
                if password != getpass("Repeat password: "):
                    raise ValueError("passwords do not match")
                with busy("Creating your encrypted wallet locally..."):
                    client.create_wallet(password)
                del password
                balance, checked = "Not checked", "Wallet created; use r to refresh"
            elif choice == "r":
                if not address:
                    raise ValueError("create a wallet first")
                with busy(f"Reading balance from chain {client.chain_id}..."):
                    value = client.balance(address)
                balance = f"{client.format_ether(value)} lab ETH"
                checked = datetime.now().astimezone().isoformat(timespec="seconds")
            elif choice == "l":
                lookup = client.validate_address(input("Paste an address to look up: "))
                with busy("Querying the pasted address..."):
                    lookup, value = client.lookup(lookup)
                field("Address", lookup)
                field("Balance", f"{client.format_ether(value)} lab ETH")
                pause()
            else:
                print("Choose one of the displayed actions.")
                pause()
        except ERRORS as error:
            if choice == "r":
                balance, checked = "Unavailable", "Refresh failed; check chain connectivity"
            print(f"\nWallet: {error}")
            pause()


def exchange_screen(client):
    """Buy lab ETH on the SEED Crypto Exchange; the faucet settles beneath."""
    limit = client.fund_max
    presets = [a for a in (1, 2, 3, 5) if a <= limit]
    while True:
        heading("SEED CRYPTO EXCHANGE",
                f"Play-money market / settlement on private chain {client.chain_id}")
        exists = client.wallet_exists()
        address = client.wallet_address() if exists else None
        field("Deposit address", address or "No wallet yet — create one first (option 6)")
        if not address:
            print("\n[b] Back")
            if input("\nExchange > ").strip().lower() == "b":
                return
            continue
        try:
            balance = f"{client.format_ether(client.balance(address))} lab ETH"
        except ERRORS:
            balance = "Unavailable"
        field("Your balance", balance)
        field("LAB/USD", f"{random.uniform(1985.0, 2115.0):,.2f} (play rate)")
        first = [f"[{a}] Buy {a} lab ETH" for a in presets[:3]]
        print("\n" + "   ".join(first))
        print("   ".join([f"[{a}] Buy {a} lab ETH" for a in presets[3:]]
                         + [f"[a] Custom amount (1-{limit})"]))
        print("[b] Back")
        choice = input("\nExchange > ").strip().lower()
        try:
            if choice == "b":
                return
            elif choice in [str(a) for a in presets]:
                amount = int(choice)
            elif choice == "a":
                amount = int(input(f"Amount of lab ETH to buy (1-{limit}): "))
            else:
                print("Choose one of the displayed actions.")
                pause()
                continue
            if not 1 <= amount <= limit:
                raise ValueError(f"the exchange trades whole amounts from 1 to {limit} lab ETH")
            with busy("Placing your order on the SEED Exchange..."):
                time.sleep(1.0)  # order matching theater
                client.buy(amount, address)
                time.sleep(0.4)  # settlement theater
            print(f"\nOrder filled: +{amount} lab ETH delivered to your wallet.")
            pause()
        except ERRORS as error:
            print(f"\nExchange: {error}")
            pause()


def _countdown(rw: Ransomware) -> str:
    hours = rw.cfg.get("countdown_hours")
    if not hours or not rw.keylog_path.exists():
        return ""
    left = rw.keylog_path.stat().st_mtime + hours * 3600 - time.time()
    if left <= 0:
        return "expired"
    h, rem = divmod(int(left), 3600)
    return f"{h:02d}:{rem // 60:02d}:{rem % 60:02d} left to pay"


def run_interface(rw: Ransomware = None):
    """Allow one active UI per participant to avoid overlapping actions."""
    rw = rw or Ransomware()
    client = payment_client(rw)
    ui = rw.cfg.get("ui", {})
    title = ui.get("title", "SEED INCIDENT LAB")
    subtitle = ui.get("subtitle", "Participant workspace / wallet and document exercises")
    try:
        with (rw.state_dir / ".participant-ui.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            while True:
                heading(title, subtitle)
                try:
                    field("Participant", rw.participant_id)
                    field("Recorded state", rw.state())
                except ERRORS as error:
                    print(f"Participant record unavailable: {error}")
                countdown = _countdown(rw)
                if countdown:
                    field("Countdown", countdown)
                if client is not None:
                    field("Wallet", "Available" if client.wallet_exists() else "Not created")
                    print("\n  DOCUMENTS                      WALLET & FUNDING")
                    print("  [1] Instructions               [3] SEED Exchange (buy lab ETH)")
                    print("  [2] Inspect documents          [6] My wallet")
                    print("  [5] Document recovery (exchange)")
                else:
                    print("\n  DOCUMENTS")
                    print("  [1] Instructions")
                    print("  [2] Inspect documents")
                    print("  [5] Document recovery (exchange)")
                print("\n  [0] Exit")
                if client is not None:
                    print(f"\nRansom payment is enforced by the RansomExchange contract "
                          f"on chain {client.chain_id}.")
                choice = input("\nHome > ").strip()
                try:
                    if choice == "0":
                        return
                    if choice == "1":
                        heading("INCIDENT INSTRUCTIONS", "Participant guide")
                        print(rw.note_text(client.price_text if client else "",
                                           client.chain_id if client else ""))
                        pause()
                    elif choice == "2":
                        heading("DOCUMENT INSPECTION", "Current observations / no files changed")
                        for name, status in rw.inspect().items():
                            field(name, status)
                        pause()
                    elif choice == "5":
                        heading("DOCUMENT RECOVERY",
                                "Blockchain key exchange / grant + manual decryptor"
                                if client is not None else "Key exchange / grant + manual decryptor")
                        password = None
                        if (
                            client is not None
                            and client.wallet_exists()
                            and not client.is_paid()
                            and not rw.reply_path.exists()
                        ):
                            password = getpass("Wallet password (to sign the paid registration): ")
                        run_recovery_step(rw, client, password=password)
                        pause()
                    elif choice == "3" and client is not None:
                        exchange_screen(client)
                    elif choice in ("6", "7") and client is not None:
                        wallet_screen(client)
                    else:
                        print("Choose one of the displayed actions.")
                        pause()
                except InvalidTag:
                    print("Sample authentication failed; this attempt restored no files.")
                    pause()
                except ERRORS as error:
                    print(f"Action unavailable: {error}")
                    pause()
    except BlockingIOError:
        print("Another participant menu is already open. Close it before opening a new one.")
    except (EOFError, KeyboardInterrupt):
        print("\nLeaving participant workspace.")
