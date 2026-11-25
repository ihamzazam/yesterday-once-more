"""Lightweight terminal screens for the victim; no web server, no background polling.

Ported from the original v2 implementation. What changed: the menu finds its
files through `paths`, it can be opened with the `ransom` command the worm
leaves behind, and the chain's id is read from the chain's config.
"""

from contextlib import contextmanager
from datetime import datetime
import fcntl
from getpass import getpass
import json
import os
from pathlib import Path
import random
import shutil
import sys
import time
from threading import Event, Thread

from cryptography.exceptions import InvalidTag

from . import chain, files, keys, paths, victim, wallet

ERRORS = victim.ERRORS
INSTRUCTIONS = Path(__file__).with_name("PARTICIPANT_README.txt")


def interactive_terminal():
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


def heading(title: str, subtitle: str):
    """Redraw real terminals; keep redirected output plain and readable."""
    width = min(78, max(42, shutil.get_terminal_size().columns))
    if interactive_terminal():
        print("\033[2J\033[H", end="")
    color = interactive_terminal() and "NO_COLOR" not in os.environ
    print("=" * width)
    print(f"\033[1;36m{title}\033[0m" if color else title)
    print(subtitle)
    print("=" * width)


def field(label: str, value):
    print(f"  {label:<16} {value}")


def pause():
    input("\nPress Enter to continue...")


@contextmanager
def busy(message: str):
    """Animate during an operation; stop the animation on exceptions."""
    print(f"\n{message}", flush=True)
    done = Event()

    def animate():
        frames = "|/-\\"
        index = 0
        while not done.wait(0.15):
            print(f"\r  {frames[index % 4]} Working...", end="", flush=True)
            index += 1

    thread = Thread(target=animate, daemon=True) if interactive_terminal() else None
    if thread:
        thread.start()
    try:
        yield
    finally:
        done.set()
        if thread:
            thread.join()
            print("\r\033[K", end="", flush=True)


def chain_id() -> str:
    try:
        return str(keys.read_json(paths.CHAIN)["chain_id"])
    except ERRORS:
        return "?"


def wallet_screen():
    balance = "Not checked"
    checked = "Use r to refresh"
    while True:
        heading("PARTICIPANT WALLET", f"Private chain {chain_id()} / local password-protected keystore")
        exists = paths.WALLET.exists() or paths.WALLET.is_symlink()
        address = wallet.wallet_address(paths.WALLET) if exists else None
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
                    wallet.create_wallet(paths.WALLET, password)
                del password
                balance, checked = "Not checked", "Wallet created; use r to refresh"
            elif choice == "r":
                if not address:
                    raise ValueError("create a wallet first")
                with busy(f"Reading balance from chain {chain_id()}..."):
                    config = wallet.connect()
                    value = wallet.balance_wei(config, address)
                balance = f"{wallet.format_ether(value)} lab ETH"
                checked = datetime.now().astimezone().isoformat(timespec="seconds")
            elif choice == "l":
                lookup = wallet.validate_address(input("Paste an address to look up: "))
                with busy("Querying the pasted address..."):
                    value = wallet.balance_wei(wallet.connect(), lookup)
                field("Address", lookup)
                field("Balance", f"{wallet.format_ether(value)} lab ETH")
                pause()
            else:
                print("Choose one of the displayed actions.")
                pause()
        except ERRORS as error:
            if choice == "r":
                balance, checked = "Unavailable", "Refresh failed; check chain connectivity"
            print(f"\nWallet: {error}")
            pause()


def exchange_screen():
    """Buy lab ETH on the SEED Crypto Exchange; the faucet settles beneath.

    Pure theater on top of the lab faucet: the participant sees a market
    screen and an order flow, while request_funds does the real transfer.
    """
    while True:
        heading("SEED CRYPTO EXCHANGE", f"Play-money market / settlement on private chain {chain_id()}")
        exists = paths.WALLET.exists() or paths.WALLET.is_symlink()
        address = wallet.wallet_address(paths.WALLET) if exists else None
        field("Deposit address", address or "No wallet yet: create one first (option 6)")
        if not address:
            print("\n[b] Back")
            if input("\nExchange > ").strip().lower() == "b":
                return
            continue
        try:
            value = wallet.balance_wei(wallet.connect(), address)
            balance = f"{wallet.format_ether(value)} lab ETH"
        except ERRORS:
            balance = "Unavailable"
        field("Your balance", balance)
        field("LAB/USD", f"{random.uniform(1985.0, 2115.0):,.2f} (play rate)")
        print("\n[1] Buy 1 lab ETH   [2] Buy 2 lab ETH   [3] Buy 3 lab ETH")
        print("[5] Buy 5 lab ETH   [a] Custom amount (1-5)")
        print("[b] Back")
        choice = input("\nExchange > ").strip().lower()
        try:
            if choice == "b":
                return
            elif choice in ("1", "2", "3", "5"):
                amount = int(choice)
            elif choice == "a":
                amount = int(input("Amount of lab ETH to buy (1-5): "))
            else:
                print("Choose one of the displayed actions.")
                pause()
                continue
            if not 1 <= amount <= wallet.FUND_AMOUNT:
                raise ValueError(f"the exchange trades whole amounts from 1 to {wallet.FUND_AMOUNT} lab ETH")
            with busy("Placing your order on the SEED Exchange..."):
                time.sleep(1.0)  # order matching theater
                wallet.request_funds(wallet.connect(), address, amount)
                time.sleep(0.4)  # settlement theater
            print(f"\nOrder filled: +{amount} lab ETH delivered to your wallet.")
            pause()
        except ERRORS as error:
            print(f"\nExchange: {error}")
            pause()


def run_interface():
    """Allow one active UI per participant to avoid overlapping actions."""
    try:
        paths.STATE.mkdir(parents=True, exist_ok=True)
        with (paths.STATE / ".participant-ui.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            while True:
                heading("SEED INCIDENT LAB", "Participant workspace / wallet and document exercises")
                try:
                    record = keys.read_json(paths.RECORD)
                    field("Participant", record["participant_id"])
                    field("Recorded state", record["state"])
                except ERRORS as error:
                    print(f"Participant record unavailable: {error}")
                field("Wallet", "Available" if paths.WALLET.exists() else "Not created")
                print("\n  DOCUMENTS                      WALLET & FUNDING")
                print("  [1] Instructions               [3] SEED Exchange (buy lab ETH)")
                print("  [2] Inspect documents          [6] My wallet")
                print("  [5] Document recovery (pay and get the key)")
                print("\n  [0] Exit")
                print(f"\nRansom payment is enforced by the RansomExchange contract on chain {chain_id()}.")
                choice = input("\nHome > ").strip()
                try:
                    if choice == "0":
                        return
                    if choice == "1":
                        heading("INCIDENT INSTRUCTIONS", "Participant guide")
                        print(INSTRUCTIONS.read_text(encoding="utf-8"))
                        pause()
                    elif choice == "2":
                        heading("DOCUMENT INSPECTION", "Current observations / no files changed")
                        keylog = keys.read_json(paths.KEYLOG) if paths.KEYLOG.exists() else {}
                        for name, status in files.inspect(
                                keylog.get("documents", paths.DOCUMENTS), keylog.get("files")).items():
                            field(name, status)
                        pause()
                    elif choice == "5":
                        heading("DOCUMENT RECOVERY",
                                "Blockchain key exchange / grant + manual decryptor")
                        request_file = paths.REQUEST
                        already_registered = (
                            request_file.exists()
                            and keys.read_json(request_file).get("request_id") is not None
                        )
                        password = None
                        if (paths.WALLET.exists() and paths.CHAIN.exists()
                                and not already_registered
                                and not paths.REPLY.exists()):
                            # The wallet signs the paid registration.
                            password = getpass("Wallet password (to sign the paid registration): ")
                        victim.recovery_step(password=password)
                        pause()
                    elif choice == "3":
                        exchange_screen()
                    elif choice in ("6", "7"):
                        wallet_screen()
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
