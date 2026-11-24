# Y51 — WannaCry (2017)

Ransomware with the WannaCry 3-tier key hierarchy and an enforced, on-chain
ransom exchange, recreated on SEED Emulator. This case is a short recipe
(`emulator.py`) over toolkit pieces in `software/`:

| Piece | Role here |
|---|---|
| `core/files` | puts the five documents (`victim_files/`) into `/home/seed/Documents` on each victim and marks it as a lab folder |
| `ransomware` | `Ransomware.preset("wannacry")` (+ `.md`), installed on every victim, **manual trigger** |
| `ransom_payment` | private chain 18000 (3 Geth nodes, faucet, utility server deploying `RansomExchange`), victim client, watcher on `attacker` |
| `check_state.py` | case-owned: compares documents with the SHA-256 baseline of `victim_files/` |

Phase 1 status: no worm yet. Triggering the ransomware by hand stands in for
the worm's arrival (Phase 4 replaces it with the worm carrying the same
Payload Package).

## Network

AS151, `10.151.0.0/24`: `victim1..3`, `attacker`, `chain0..2`, `faucet`,
`utility`, `router0`. Addresses are assigned by seedemu; the toolkit resolves
them at build time.

## Run it

```bash
cd ~/workspace/yom-toolkit
source .venv/bin/activate
images/build.sh                      # once: builds yom-base:1
cd cases/Y51_wannacry
python3 emulator.py                  # writes ./out-y51
cd out-y51 && docker compose build && docker compose up -d
```

The chain needs a few minutes to start mining and deploy the contract.
Check from any victim:

```bash
docker exec as151h-victim1-10.151.0.71 y51-check-state
```

`contract: ... ALIVE` means the exchange is ready.

## The participant flow

```bash
docker exec as151h-victim1-10.151.0.71 yom-ransomware detonate    # the "infection"
docker exec -it as151h-victim1-10.151.0.71 yom-ransomware menu    # the v2 participant UI
```

In the menu: `6` create a wallet → `3` buy lab ETH → `5` document recovery
(pays 1 lab ETH on-chain; the attacker's watcher answers automatically) →
copy the granted key → leave the menu and run
`yom-ransomware decrypt` → paste the key.

Scripted version of the same flow (used as the end-to-end test):

```bash
docker exec as151h-victim2-10.151.0.72 yom-ransomware headless --password lab
docker exec as151h-victim2-10.151.0.72 y51-check-state          # all ORIGINAL again
```

Attacker side (read-only status, or sweep the collected ransoms):

```bash
docker exec as151h-attacker-10.151.0.74 yom-ransom-watcher status
docker exec as151h-attacker-10.151.0.74 yom-ransom-watcher withdraw
```

Every runtime logs to `/opt/yom/var/events.jsonl` on its host
(`python3 -m software.core.events` with `PYTHONPATH=/opt/yom` prints it).

## Stop

```bash
cd out-y51 && docker compose down
```
