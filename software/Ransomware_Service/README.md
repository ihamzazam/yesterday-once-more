# Ransomware Service

What the worm carries for WannaCry: the program that locks a victim's
documents, and the whole experience around it.

```python
from software.Ransomware_Service import Ransomware

ransom = Ransomware(in_as=lab, on_network="net0")   # brings its payment chain
emu.addLayer(ransom)
for binding in ransom.bindings:                     # the chain's five machines
    emu.addBinding(binding)

worm = Worm(entry=bof.exploit(), payload=ransom.payload, ...)
```

Compile with chain-seed's compiler, because the payment chain is a chain-seed
chain: `emu.compile(ChainSeedDocker(platform=Platform.AMD64), ...)`.

## What it is

- **The payload.** `ransom.payload` is what the worm carries. On each victim
  it locks the documents, leaves the ransom note, and leaves a `ransom`
  command behind.
- **The payment chain.** Five machines: three chain nodes, a faucet and a
  utility server that deploys the `RansomExchange` contract. The case says
  which network they live on; the addresses are assigned by the emulator.
- **The attacker's tools.** They go on the machine the worm is launched from:
  `ransom init` creates the attacker's keys at boot, `ransom watch` answers
  paid requests, `ransom withdraw` takes the money.

Nothing of the ransomware is installed on a victim when the lab is built.
The whole package arrives with the worm, and the menu appears only after the
machine is locked, as with real ransomware.

## The experience on a victim

1. The documents become `.WNCRY` envelopes; a note in the folder says so.
2. `ransom` opens the menu: inspect the documents, create a wallet, buy lab
   money on the exchange, pay.
3. Paying registers the request on the chain with exactly 1 lab ETH.
4. The attacker's `ransom watch` posts the key on the chain.
5. The menu accepts it and prints **KEY GRANTED**.
6. `ransom decrypt` restores every document and checks each against its
   original.

## The keys, as in v2

| Key | Lives on | Travels |
| --- | --- | --- |
| attacker RSA keypair | attacker's machine | only the public half, inside the worm |
| victim RSA keypair | each victim | its private half, sealed, on the chain |
| file key | each victim | sealed under the victim's key |
| contract's account | utility server and attacker | never |

The chain is public, so nothing private is ever put on it unsealed. The
contract's account key, which lets its holder answer requests, is handed to
the attacker when the lab is built and is never part of the worm's settings.

## One manual step removed from v2

The contract lets only its deployer answer requests, and the deployer is the
utility server's account. In v2 the attacker had to copy that account's key
over by hand. Now the installer creates the account, gives it to the utility
server, and gives the same one to the attacker.

## What it will not do

- Lock a system folder, or anything outside the one documents folder. No
  subfolders, no links.
- Lock a machine twice.
- Start the worm from a machine that has no attacker keys or no chain.
- Register a request twice, so a victim never pays twice.

## Options

| | Default | |
| --- | --- | --- |
| `Ransomware(in_as=...)` | | the autonomous system for the chain's machines |
| `Ransomware(on_network=...)` | `net0` | the network they join |
| `Ransomware(chain_id=...)` | `18000` | the lab chain's id |
| `Ransomware(documents=...)` | `/home/seed/Documents` | the folder that gets locked |
| `Ransomware(ransom_wei=...)` | 1 ETH | the ransom; the contract enforces it |

The case creates the documents themselves: they are part of the story. The
WannaCry case does it with five files in `documents/`: see
[`cases/Y51_wannacry`](../../cases/Y51_wannacry/README.md).

## Ports

The chain uses **8545/tcp** (RPC), **80/tcp** (faucet) and **8080/tcp**
(utility) on its own machines. On a victim, the ransomware needs no port.

## Differences from the historical WannaCry

The original took Bitcoin and talked to its victims through Tor. This lab
uses a private chain, because the chain enforces the payment and keeps the
whole exchange visible to students. The original had no way to see who paid;
here every request is a transaction. A case README should say so.

## Tests

From the repository root: `.venv/bin/python -m pytest`. They need no Docker,
and cover locking real files, the whole exchange on the manual path, the
installer on a real emulator, and that the WannaCry case builds.
