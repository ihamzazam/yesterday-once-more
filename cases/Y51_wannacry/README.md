# Y51 — WannaCry (2017)

A worm that carried ransomware, recreated on SEED Emulator with the reusable
pieces in [`software/`](../../software/README.md).

## What happens

1. Three victims have documents. The attacker starts the worm.
2. The worm breaks in through a buffer overflow, carrying the ransomware, and
   locks the documents of every machine it reaches. Each machine then spreads
   it further.
3. A victim opens the `ransom` menu the worm left behind, creates a wallet,
   buys lab money and pays on a private chain.
4. The attacker answers, the victim receives the key and restores every
   document.
5. The teacher can stop every worm at any moment with the kill switch of the
   real incident: registering one nonsense domain.

## Run it

Needs Docker, and ASLR switched off on the host, as Dr. Du's Morris lab does
too (restore it afterwards with `=2`):

```sh
sudo sysctl -w kernel.randomize_va_space=0
cd cases/Y51_wannacry
../../.venv/bin/python emulator.py                  # builds ./output
cd output
docker compose up -d --build                       # the first build takes a while
docker compose logs hnode_159_ransom-utility       # wait for "Contract deployed"
curl -X POST -H "Content-Type: application/json" -d '{"name": "submit_event"}' \
     http://localhost:8082/api/v1/install           # once: infected machines show
                                                    # themselves on the map
```

The map is at `http://localhost:8082`. Then:

```sh
docker compose exec -d hnode_159_attacker sh -c 'worm launch > /tmp/worm.out 2>&1'
docker compose logs hnode_159_victim1              # it arrives and locks
docker compose exec -it hnode_159_victim1 ransom   # the victim's menu
docker compose exec hnode_159_attacker ransom watch  # the attacker answers
docker compose exec hnode_159_switch switch stop   # every worm stops
docker compose down
```

## The pieces

| Piece | Role in this case |
| --- | --- |
| `Vulnerable_Server` | the hole the worm breaks in through |
| `Worm_Service` | spreads, carrying the ransomware |
| `Ransomware_Service` | locks the documents; the menu; the payment chain |
| `Switch_Service` | the kill-switch domain |

## Differences from the real incident

- **Bitcoin and Tor became a private chain.** The chain enforces the payment
  and keeps the whole exchange visible to students.
- **The hole is Dr. Du's Morris buffer overflow**, standing in for the SMB bug.
- **The kill switch is checked before every attempt,** so a live outbreak can
  be stopped. The real worm checked once, at start.
