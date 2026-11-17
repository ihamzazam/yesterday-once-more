# PROJECT MEMORY — handoff document
> Last updated: 2026-11-17 (late evening). Purpose: full context for a fresh chat window
> or a fresh device. Read top to bottom. Pushed to the FORK only (origin = ihamzazam),
> never to upstream (seed-labs).

## 0. Who / what / why
- User: master's student at ZJU under **Dr. Wenliang Du**; first task = bring **WannaCry**
  into the new **yesterday-once-more** repo and make it modular.
- Repo vision (Dr. Du's): not just recreate historic incidents — provide **reusable modular
  attack software** (services) that cases compose. Example: one worm service reused across
  WannaCry + Morris worm.
- User is learning Python/git/seedemu. Teaching style that works: **one small step per
  message, super-simple language, user types everything** (exception: under time pressure,
  agent may do mechanical work while user reviews + commits). No information dumps.

## 1. Repos & remotes (THIS machine: ~/yesterday-once-more, branch `hamza`)
```
origin   = https://github.com/ihamzazam/yesterday-once-more   ← FORK: daily pushes go HERE
upstream = https://github.com/seed-labs/yesterday-once-more   ← official: only presentable work
```
- **Workflow**: daily work → origin (fork). Dr. Du sees seed-labs/hamza only when presentable
  (confirm his preferred review flow at syncs).
- Cross-device: clone the FORK on other machines.
- Commits on hamza (newest first):
  - d63f845 Add Worm_Service runtime skeleton: engine + plugs
  - 543e3aa Rename lab_* files to accurate names
  - 70a5218 Port Y51 wannacry v2 implementation from seed-emulator demo (builds on seedemu 2.0.0)
  - d2b70de Add .gitignore

## 2. Toolchain — battle-tested recipe (THIS device: ~/scratch-day1/.venv, python 3.10 via uv)
Gotchas discovered by hand (all three bit us once):
1. `uv venv` ships **without pip** → use `uv pip install ...` (or pip inside is system pip → PEP 668 error).
2. `setuptools<81` must be installed explicitly — old `eth_keyfile` imports `pkg_resources`, uv venvs lack setuptools.
3. chain-seed installs with **`--no-deps`** from pinned source (see §4).
```
uv venv --python 3.10 .venv && source .venv/bin/activate
uv pip install seedemu==2.0.0
uv pip install --no-deps ~/research/chain-seed-0.1.0a0     # pinned source copy
uv pip install "web3==5.31.1" "eth-account==0.5.9" "eth-keys>=0.3.4,<0.4" PyYAML requests
uv pip install "setuptools<81"
```
Verified pair: **seedemu 2.0.0 (PyPI) + chainseed 0.1.0a0 (pinned)** — import gate passes.

## 3. Upstream state (as of 2026-11-17) — tracked, mid-flight
- **seedemu 2.0.0 is on PyPI** (`pip install seedemu`). Blockchain services were REMOVED
  from seedemu (they live in chain-seed). Docker compiler lost `internetMapEnabled=` flag —
  maps are now container bundles: `compiler.addContainerBundle(InternetMap(emu, ".map.seed"))`.
- **chain-seed is preparing 1.0.0** (commits Nov 16–17): renamed version, fixed pins to
  `seedemu>=2.0.0`, **deleted `ChainSeedDocker`** (services now declare images via new
  `Service.getDockerImages()` API). PROBLEM: that new API is in seedemu's `release` branch,
  NOT yet in PyPI 2.0.0 → chainseed 1.0.0 fails its compatibility gate today.
  **=> we pinned chainseed 0.1.0a0. Migration when both publish: case drops ChainSeedDocker,
  uses plain Docker (2-line change).** Fresh 1.0.0 clone at ~/research/chain-seed.
- **AI toolkit**: `tools/seed-agent/` — read `PRINCIPLES.md` (10 design principles; our
  worm design validated against it; P4 = no hardcoded IPs in services; P3 = fluent
  chainable APIs; P10 = ship runnable examples). Also `skills/seedemu-add-service`.
- House style for new cases: `example.yaml` + `test_runtime.py` + TrafficVisualizer
  (tools/TrafficVisualizer) + README with mermaid diagram. `tools/BotnetLab` exists with
  allowlist-handler security pattern (reuse for our payload slot design).
- GitHub/Docker Hub from Mainland China = slow/blocked (DNS pollution, throttling).
  git clone of seed-emulator times out; use raw.githubusercontent / codeload tarballs / gh api.

## 4. Machine-local artifacts (THIS device only — not in any repo)
- `~/scratch-day1/.venv` — the working toolchain venv.
- `~/scratch-day1/lab/` — v2 copy with the two 2.0.0 patches (source of the ported case).
- `~/scratch-day1/wormsketch/` — first worm loop draft (superseded by repo skeleton).
- `~/scratch-day1/wormdrill/` — live drill: `run_worm.py` (composition script; aims at two
  throwaway victims), `body.py` (marker-dropping worm body), `bof_test.py` (../bof_test.py).
- `~/research/chain-seed-0.1.0a0/` — pinned chainseed source. `~/research/chain-seed/` —
  fresh 1.0.0 clone (for the future migration).
- Docker: `morris-worm-base` image (contains `/bof/server` 64-bit doorman :9090 and
  `/bof/stack` 32-bit vulnerable binary); throwaway containers door-test / victim-2 / v3.
- `/tmp/stack-binary` — GNU_STACK-patched stack binary; `/tmp/real-badfile`, `/tmp/bad4141`.
- **REMEMBER: restore host ASLR after drills: `sudo sysctl -w kernel.randomize_va_space=2`**
  (was set to 0 for the overflow drills; confirm it is back to 2).
- Morris lab original: was at ~/research/seed-emulator/examples/yesterday_once_more/
  Y02_morris_worm — **deleted by user (in Trash)**; recoverable from GitHub or Trash.
  The morris emulation build needs the OLD seedemu (dead APIs) — do not rebuild on 2.0.0.

## 5. Architecture (agreed, validated against seed-agent PRINCIPLES.md)
Two worlds: **build-time** (seedemu Service/Server, vnodes + bindings, runs on your laptop
once) vs **runtime** (plain Python inside containers). Our services have both halves:

```
software/Worm_Service/            ← NOTE: Dr. Du's skeleton dirs are Title_Case — USE HIS
├── runtime/engine.py             ← chassis: one loop, FIVE plugs, knows nothing
│                                   (governor → scanner → entry → payload → transport)
├── runtime/plugins.py            ← plugs; P4: NO lab-specific defaults, case configures
└── seedemu/worm_service.py       ← NOT WRITTEN YET: WormService(Service) stager
software/Ransomware_Service/      ← planned: from ransomware.py (crypto/protocol),
                                    corpus.py + prepare, wallet.py, ransom_chain.py,
                                    chain_setup helper, contracts/, recover CLI
software/Vulnerable_Server/       ← planned: stack.c+server.c door, must solve NX/determinism
cases/Y51_wannacry/               ← the case: emulator.py (thin), UI theater, docs
```
- The worm is modular BECAUSE the exploit is a **plug**: vulnerability lives on victims
  (Vulnerable_Server service), exploit lives in the worm (Entry plug); matching is done by
  the case composer. Real WannaCry precedent: worm carried EternalBlue, not the SMB server.
- Rename map (DONE): lab_chain→chain_setup, lab_keylogic→ransomware, lab_ransom_chain→
  ransom_chain, lab_wallet→wallet. **wormdoor.py: slated for deletion** (replaced by the
  buffer-overflow door) — still in tree.
- BufferOverflowEntry needs: port 9090, ebp=0xffffd5e8, buf=0xffffd578 (VALIDATED in the
  server's spawn context via the tty-probe trick — `stack` prints its own addresses; capture
  via tty or probe-then-read-late), shellcode = original morris worm.py bytes (320 B, exact),
  and a deterministic, EXECUTABLE stack on victims (see §6 wall).

## 6. THE OPEN WALL (tracked ticket — the only real blocker left)
Live overflow drill results (morris-worm-base throwaway containers):
- ✅ Door healthy; addresses exact (kernel-confirmed EIP control: `ip=41414141` at offset 116
  = ebp+4); delivered bytes byte-identical; ASLR 0; shellcode byte-exact vs original.
- ✅ GNU_STACK patched 0x0→0x7 (R|W|X); runtime maps show `[stack] rwxp`.
- ❌ Shellcode still never executes — silent death at the sled jump. Suspects: kernel
  READ_IMPLIES_EXEC semantics for 32-bit-on-64-bit; something in the exec-spawn context.
- Next steps: gdb/strace the stack child; compile our own stack.c with `-z execstack`
  ( gcc -m32 -z execstack ); try the `execstack` apt tool; kernel archaeology.
- Service implication: Vulnerable_Server must bake determinism + executability in
  (documented, deliberate — it is a lab door, not real malware).
- Tools that worked: privileged container `dmesg` for RIP truth; `docker exec -t` for
  line-buffered live output; process census via /proc/*/comm; instrument-stack trick
  (replace stack with a python recorder to dump received bytes + spawn env).

## 7. Decisions made (do not re-litigate)
- No version numbers in the new repo — it is just "the WannaCry example" (cases/Y51_wannacry).
- Kill switch: IN (historically faithful; DNS governor; needs DNS infra in the emulation).
- Entry: reuse Morris's buffer overflow (Dr. Du explicitly blessed it); more doors later.
- Scale: AS180 first; mini-internet base later (dump/load/merge). Multi-victim from day one.
- Payment: keep current contract (global 1 ETH); per-request pricing = maybe later.
- bootstrap.sh + case README + design doc: DEFERRED until after the sync (user prefers
  working demo first, docs against reality).
- Progress-log files do NOT go in the repo (user keeps a personal notebook).
- Design note content was drafted in chat (6 sections) — regenerate from §5/§6 when needed.

## 8. Sync with Dr. Du — the five bullets (next sync: tomorrow morning)
1. Ported + pinned: WannaCry in the new repo on PyPI seedemu 2.0.0 + pinned chainseed;
   upstream 1.0.0 migration planned (2-line change).
2. Architecture agreed: three layers; Worm_Service (5 plugs), Ransomware_Service,
   Vulneratable door service; cases = thin composition.
3. Overflow proof-of-concept: kernel-confirmed EIP control; shellcode-execution anomaly
   under investigation (open wall, tracked).
4. wormdoor dropped; Morris bof reused as the door (modularity in action).
5. Open questions: kill-switch DNS home · examples-folder-vs-this-repo reconciliation ·
   Botnet_Service wrapping tools/BotnetLab · scale target · Title_Case dirs vs snake_case.

## 9. Immediate next steps (queue)
1. Sync prep: rehearse the five bullets (agent quizzes the user, 10 min).
2. After sync: file Dr. Du's answers → write docs/design note from reality (§5 + §6).
3. Step 1: package Vulnerable_Server (solve the NX/determinism wall — §6).
4. Step 2: finish BufferOverflowEntry + Payload (exec ransom detonate) plugs.
5. Step 3: case rewiring — delete wormdoor.py, compose services, multi-victim.
6. Step 4: build + `docker compose up` + watch the worm spread in AS180.
7. Later: Morris case on the same chassis (modularity proof); scale to mini-internet;
   adopt house case template (example.yaml/test_runtime.py/TrafficVisualizer).
