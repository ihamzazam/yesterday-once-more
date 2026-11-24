# Vulnerable Server

The hole on the victim's side, offered as a menu of vulnerabilities.

```python
from software.Vulnerable_Server import MorrisBufferOverflow, VulnerableServer

bof = MorrisBufferOverflow()             # pick one from the menu
victims = VulnerableServer(bof)          # put it on machines
emu.addLayer(victims)
victims.install("vuln-victim1")          # one virtual node per machine
emu.addBinding(Binding("vuln-victim1", filter=Filter(asn=150, nodeName="victim1")))
```

## A vulnerability is a pair

Each entry in the menu is **the hole and the break-in that matches it**, kept
in one class so they cannot drift apart:

- **The hole** is what this service installs on a victim: files, software and
  start commands.
- **The break-in** is what the worm uses. A case never writes it; the worm
  takes it from the same object:

```python
worm = Worm(entry=bof.exploit(), ...)
```

If the break-in names a hole that no machine has, the worm's installer stops
with a clear message instead of attacking machines that are not there.

## The menu

| Vulnerability | Port | What the Docker host needs |
| --- | --- | --- |
| `MorrisBufferOverflow` | 9090/tcp | ASLR switched off (`sudo sysctl -w kernel.randomize_va_space=0`) |

## MorrisBufferOverflow

This is the buffer-overflow server from Dr. Du's Morris worm example
(`Y02_morris_worm`), unchanged. `server` listens on port 9090 and hands each
connection to `stack`, a 32-bit program with an executable stack that copies
whatever it receives into a 100-byte buffer.

The break-in is his too, with one change: the command inside his shellcode.
His fetched a single file; this one fetches the worm's folder, refuses to
overwrite an already infected machine, and tells the sender what happened.
It uses two more ports on each victim: **9999/tcp** (receives the worm body)
and **9998/udp** (answers the sender).

**Why ASLR has to be off.** The badfile has to name the exact place in memory
where `stack` keeps its frame. With ASLR on, that place changes on every run.
Two safety nets come with it:

- building the emulation prints a warning when ASLR is on;
- the worm refuses to launch and prints the fix, instead of crashing victims.

Switch ASLR off before or after the lab starts, it makes no difference: the
vulnerable server waits until it is off before it starts. That matters because
a program that was started while ASLR was on keeps randomising its children.

The addresses are not written down anywhere. The launcher runs its own copy
of `stack` the same way the server does, reads what it prints, and passes the
two numbers down inside the worm body.

## Two traps in the base image, handled by the installer

- **zsh swallows the shell an exploit gets.** This image's `/root/.bashrc`
  is just `exec zsh`. Bash also reads that file when it is started with `-c`
  and its input is a network connection, which is exactly the situation an
  exploit creates. So the shell turned into zsh and the exploit's command
  never ran. Dr. Du's example works around it by deleting the file. Here it
  is changed to run zsh only for interactive shells, so people keep zsh.
- **Imported files are not executable.** A file put on a node arrives with
  no executable bit, so the installer sets it when the machine boots.

## Adding a vulnerability

Create a folder under `vulnerabilities/` with two halves, following
`morris_bof/`:

1. a class deriving from `Vulnerability` that implements `install(node)` and
   `exploit()`;
2. a small runtime package (the break-in class) that follows the rules for a
   worm part, see [Worm_Service](../Worm_Service/README.md).

Then export the class from `vulnerabilities/__init__.py` and
`Vulnerable_Server/__init__.py`.
