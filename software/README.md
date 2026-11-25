# Software

The reusable pieces that cases are built from. A case picks what it needs,
connects the pieces, and adds its own story:

```text
                             ┌────────────────────────────┐
                             │            CASE            │
                             │   machines, story, files   │
                             └─────────────┬──────────────┘
                                           │  connects the pieces
        ┌──────────────────────────────────┬────────────────────────────────┐
        │                                  │                                │
        ▼                                  ▼                                ▼
┌────────────────┐    break-in    ┌────────────────┐    carries     ┌────────────────┐
│   VULNERABLE   │─────────────▶  │      WORM      │◀─────────────  │   RANSOMWARE   │
│     SERVER     │    (a pair)    │   (spreads)    │                │  (locks + UI)  │
│   (the hole)   │                │                │                │                │
└────────────────┘                └───────▲────────┘                └────────────────┘
                                           │ checks
                                   ┌───────┴────────┐
                                   │    SWITCH     │  ◀── the teacher flips it
                                   │  (DNS signal)  │
                                   └────────────────┘
```

| Piece | Folder | Status |
| --- | --- | --- |
| Vulnerable server | [Vulnerable_Server](Vulnerable_Server/README.md) | built |
| Worm | [Worm_Service](Worm_Service/README.md) | built |
| Switch | [Switch_Service](Switch_Service/README.md) | built |
| Ransomware | [Ransomware_Service](Ransomware_Service/README.md) | built |

WannaCry is the four of them together, in one lab:
[`Ransomware_Service/examples/wannacry.py`](Ransomware_Service/examples/wannacry.py).
The worm breaks in through the hole carrying the ransomware, the victims are
locked, a victim pays on the payment chain and gets its documents back, and
the teacher can stop the worm with the switch.

| Case | Hole | What the worm carries | Stop signal |
| --- | --- | --- | --- |
| Morris | buffer overflow | nothing | DNS |
| WannaCry | the same | ransomware | DNS |

A case keeps only three things: the machines, the story (its text and the
victim's files), and the few lines that connect the pieces.

## Every piece is built the same way

Each piece has two halves, joined by a small settings file that the first
half writes and the second reads. Nobody types that file by hand.

| | Installer (build time) | Runtime (inside containers) |
| --- | --- | --- |
| Runs | on your machine, while the emulation is built | on the emulated machine |
| Is | a seedemu `Service` | a plain Python package, standard library only |
| Does | takes the case's choices, puts code and files on the node, writes the settings file | reads the settings file and does its job |
| Lives | `seedemu_service.py` | a folder named `yom_<piece>` |

The runtime never imports seedemu and never contains an address or the name
of a case. It can be tested on your machine without Docker, and the same
folder can travel inside the worm body to the next machine.

## Three rules that keep the pieces apart

- **Pieces find each other through the emulator, never through each other's
  files.** The worm asks which machines have the hole, and where the switch
  is, the same way seedemu's own `BotnetService` does.
- **Nothing is written down twice.** The addresses the buffer overflow needs
  are measured, not hardcoded; a target list is derived, not typed.
- **A missing answer is never a "go".** The worm refuses to launch when its
  break-in cannot work, and stops when the switch cannot be reached.

## Shared helpers

[`Core/`](Core/) holds what every installer needs: putting a runtime folder
on a node, giving a node a one-word command, reading a node's address, and a
fake worm for testing a part without Docker. It is the one folder here that
is not a piece of the attack.

## Tests

From the repository root:

    .venv/bin/python -m pytest

They need no Docker. Each piece's README says how to run the real thing.
