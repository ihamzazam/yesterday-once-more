# YOM toolkit architecture

**Idea.** Reusable attack pieces live in `software/`. Each historic case in
`cases/` is a short recipe that composes them.

**Rule.** If it is about the *story* (which files, which network, which victims,
the README), it goes in `cases/`. If it is about the *attack technique*, it goes
in `software/`.

```
software/
  core/               shared plumbing, no attack logic
    payload.py        Payload Package format (files + settings + start command + needs)
    settings.py       each piece's settings: written at build time, read in the container
    events.py         shared JSON-lines event log: emit("encrypted", ...)
    install.py        copy a piece's runtime code + needs into containers
    ready.py          wait for chain / contract / DNS / ports before acting
    guard.py          containment: only lab IP prefixes (injected at build), only marked lab folders
    files.py          copy a folder of files to many nodes in one call
    tui.py            shared terminal look (headings, fields, spinners, menus)
  worm/               service.py + runtime/ + examples/ + tests/ + README
  ransomware/         service.py + runtime/ (crypto, target rules, ui/, decryptor, headless)
  vulnerable_server/  service.py + C sources + published profile
  ransom_payment/     chainseed chain + RansomExchange contract + victim client + attacker watcher
  sinkhole/           DNS zone for a domain + web responder + on/off switch
cases/
  Y51_wannacry/       emulator.py, victim_files/, check_state.py, README
  Y11_morris_worm/    emulator.py, README
images/               prebuilt base image (python3, cryptography, eth-account)
docs/architecture.md
```

## Two halves per piece

| Half | Where it runs | May import | Job |
|---|---|---|---|
| `service.py` | build time, on the laptop | seedemu, chainseed (payment only) | sees the whole network, resolves vnode → IP (`emulator.getBindingFor`), validates matches, writes settings |
| `runtime/` | inside the container | stdlib, `cryptography`, `eth_account`/`eth_abi`, `software.core` runtime modules | reads **only** its settings file; unit-testable on its own |

No hard-coded IPs or paths in `software/`; only cases choose them.

In a container everything lives under `/opt/yom` (the *root*):

```
/opt/yom/software/...           runtime code (same package layout as the repo)
/opt/yom/etc/<piece>.json       settings written at build time
/opt/yom/var/<piece>/           runtime state
/opt/yom/var/events.jsonl       the shared event log
/opt/yom/bin/<command>          small launchers (PYTHONPATH=/opt/yom)
```

`software/__init__.py`, `software/core/__init__.py` and every piece's
`__init__.py` stay empty, so runtime imports never pull in seedemu.
Runtime-safe core modules: `payload`, `settings`, `events`, `ready`, `guard`, `tui`.
Build-only core modules: `install`, `files`.

## Five contracts

Pieces never call each other's code. They connect only through these:

1. **Profile ↔ exploit.** `vulnerable_server` publishes a profile (bug kind,
   port, measured offsets, protections, patched flag). An exploit declares what
   it targets. A mismatch fails at BUILD time.
2. **Payload Package.** Any payload piece exposes `asPayload()`; any carrier
   (the worm) carries packages. On arrival the carrier unpacks and runs the start
   command, after checking `needs`.
3. **Payment client.** Ransomware calls `register(sealed_blob)` / `pay()` /
   `await_key()` from `ransom_payment`'s victim client and never touches chain
   code. The watcher runs on the attacker host. All chainseed code lives inside
   `ransom_payment/` only.
4. **Kill-switch domain.** The worm's `DomainKillSwitch` plug does an HTTP GET to
   a domain before spreading; if it answers, the worm stops. `sinkhole` decides
   whether the domain answers and can be toggled at run time.
5. **Events.** Every runtime writes to the shared event log. `check_state`, tests
   and later dashboards read it.

### Payload Package format (`core/payload.py`)

```json
{ "name": "ransomware",
  "files":    { "software/ransomware/runtime/main.py": "<text>", ... },
  "settings": { "ransomware": { ... }, "ransom_payment": { ... } },
  "start":    "yom-ransomware detonate",      // null = manual trigger
  "needs":    ["python3", "py:cryptography", "py:eth_account"] }
```

`install.install_package(node, pkg)` stages a package onto a node at build time
(direct install). A carrier ships `pkg.to_bytes()` and calls
`payload.unpack(blob, root)` + `payload.check_needs()` on arrival.

### Event format (`core/events.py`)

One JSON object per line: `{"ts": 1732..., "host": "as151-victim1",
"piece": "ransomware", "event": "encrypted", ...fields}`.

## Piece notes

- **worm** — installs only on patient zero. A copy lives on each infected host:
  arrive → governor/kill switch → run local payloads → spread. Plugs: scanner
  (list / subnet / random with rate limit), exploit (from the profile), transport
  (shellcode listener; pull-from-parent optional), governor (kill switch, max
  generations, reinfect probability). Built-in `MarkerPayload`. The scanner obeys
  `guard`. Sockets, not `shell=True`/`nc` pipelines.
- **ransomware** — target rules (folders, extensions with a `wannacry` preset,
  exclusions), key scheme (`wannacry` 3-tier hybrid, or `simple`), suffix,
  delete/keep originals, trigger (`on_arrival` / `delay` / `manual`).
  `Ransomware.preset("wannacry")` fills defaults; everything can be overridden.
  The terminal UI is the v2 UI on `core/tui.py`; only title, family name, note
  text, price and countdown come from settings. Payment screens hide when no
  payment is attached. Headless mode runs the full pay-and-recover flow for
  tests. It knows no fixture files: AES-GCM integrity replaces the baseline
  check, which moves to the case's `check_state.py`.
- **vulnerable_server** — deterministic, executable stack per process: build
  `gcc -m32 -z execstack -fno-stack-protector`, run under `setarch i386 -R`. No
  host sysctl. ebp/buf are measured inside the container and published in the
  profile; the exploit reads them.
- **ransom_payment** — a component that adds chain nodes + faucet + utility
  server deploying RansomExchange, a victim client and an attacker watcher. The
  deploy-gas fix lives inside this folder.
- **sinkhole** — uses seedemu DNS. If the network has no DNS, it adds a minimal
  one (root, TLD, zone, local resolver).

## WannaCry recipe target shape

```python
emu, victims = build_network()
place_files(emu, victims, "victim_files/", "/home/seed/Documents")
vuln = VulnerableServerService(kind="stack_overflow", port=9090); [vuln.install(v) for v in victims]
payment = RansomPayment(price_eth=1).attachTo(emu, asn=151)
sinkhole = Sinkhole(domain=KILL_DOMAIN)
ransom = Ransomware.preset("wannacry").setTargets(["/home/seed/Documents"]).setPayment(payment)
worm = WormService(); worm.install("attacker").asPatientZero()
worm.setExploit(vuln.exploit()).setScanner(Subnet(...)).setKillSwitch(sinkhole).addPayload(ransom.asPayload())
```

Morris uses the same worm and vulnerable server with
`.setReinfect(probability=1/7).addPayload(MarkerPayload())`, and no ransomware,
payment or sinkhole.

## Deviations

Places where reality forced a change from the spec. Each one is deliberate.

_(filled in per phase, see below)_

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | recon | done |
| 1 | core + ransomware + ransom_payment, Y51 without worm | in progress |
| 2 | vulnerable_server | — |
| 3 | worm + sinkhole | — |
| 4 | thin Y51 + Y11 Morris | — |
