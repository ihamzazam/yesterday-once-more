"""Shared terminal look: headings, fields, spinners, pauses.

These are the WannaCry v2 lab screens' primitives, unchanged, so every piece's
UI looks the same. No web server and no idle background polling.
"""

from contextlib import contextmanager
import os
import shutil
import sys
from threading import Event, Thread


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


def field(label, value):
    print(f"  {label:<16} {value}")


def pause():
    input("\nPress Enter to continue...")


def banner(lines, width: int = 60):
    """A ruled block, as used by the key-grant and decryptor screens."""
    print("=" * width)
    for line in lines:
        print(line)
    print("=" * width)


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
