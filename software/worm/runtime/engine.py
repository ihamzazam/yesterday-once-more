#!/usr/bin/env python3
"""The worm chassis. Knows NOTHING about worms.

Five plugs are handed in; this loop just calls them in order:

    governor.allowed()      -> continue at all?
    scanner.next_target()   -> who is next
    entry.break_in()        -> gain execution on the target
    payload.run()           -> what to do after arriving
    transport.deliver()     -> how the body reaches the target
"""

import time


class Worm:
    def __init__(self, scanner, governor, entry, payload, transport):
        self.scanner = scanner
        self.governor = governor
        self.entry = entry
        self.payload = payload
        self.transport = transport
        self.infected = set()

    def spread(self, rounds=10):
        for i in range(rounds):
            print(f"round {i+1}:")
            if not self.governor.allowed():
                print("  [governor] kill switch says STOP. Worm halts.")
                return
            target = self.scanner.next_target(self.infected)
            if target is None:
                print("  [scanner]  no targets left. Worm rests.")
                return
            if self.entry.break_in(target):
                self.payload.run(target)
                self.transport.deliver(target)
                self.infected.add(target)
            time.sleep(1)
