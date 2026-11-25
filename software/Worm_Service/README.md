# Worm Service

The spread loop, with four slots that a case fills in.

```python
from software.Worm_Service import Worm

worm = Worm(entry=bof.exploit(),                            # how to break in: from the hole
            payload=ransomware,                             # what to do after breaking in
            governor=DnsKillSwitch(switch.name("stop")))    # when to stop
emu.addLayer(worm)
worm.launch_from("patient-zero")
emu.addBinding(Binding("patient-zero", filter=Filter(asn=150, nodeName="attacker")))
```

## The four slots

| Slot | The question it answers | If a case leaves it out |
| --- | --- | --- |
| `entry` | How does the worm break in? | Must be given. Take it from the hole: `bof.exploit()` |
| `payload` | What does it do after breaking in? | Nothing: the worm only spreads, like Morris |
| `governor` | When does it stop? | Only the time limit can stop it |
| `scanner` | Who does it attack? | Every machine that has the matching hole |

The same worm serves several cases by swapping slots. Morris is the same hole
with nothing carried. Mirai is a weak-passwords hole carrying a bot.

## How it spreads

1. A person runs `worm launch` on the first machine (or it starts at boot).
2. The worm checks that its break-in can work here. If not, it says why and
   stops before touching anyone.
3. It waits until the stop-signal server has answered once.
4. It packs its body: its own code, the code of the four parts, and the
   settings file.
5. Round after round: ask the stop signal, pick a target, break in, hand over
   the body, wait for the target to answer.
6. On the target, the body unpacks itself to `/tmp/yomw`, answers "arrived",
   tells the Internet Map, does what it carried, and starts spreading too.

Nothing of the worm is put on a victim when the emulation is built. It gets
there by breaking in, which is what makes it a worm.

## What the installer does for a case

- **Who to attack.** The worm looks for every machine that has the hole its
  break-in fits, and attacks exactly those. No case types an address.
- **Where the switch is.** If the worm has a `DnsKillSwitch`, its server
  address is found and filled in.
- **What a victim needs.** The body is Python, so `python3` is added to every
  target. A carried part can ask for more: the ransomware asks for its crypto
  libraries, and they are added to every target and to the launcher.

## The Internet Map

The map is seedemu's own dashboard. With its `submit_event` add-on installed
(one command, see the examples), a machine **flashes on the map the moment
the worm arrives on it** and stays highlighted. When the worm stops there,
the highlight goes away. It is the same add-on Dr. Du's Morris worm uses. On
a lab without the map, or without the add-on, the worm simply says nothing to
any map.

## Running it

    docker compose exec <launcher container> worm launch
    docker compose logs <launcher container> <victim containers>

Every machine prints one JSON line per thing it does. The same lines are kept
in `events.jsonl` in the worm's folder: `/opt/yom/` on the launcher and
`/tmp/yomw/` on a victim.

`Worm(..., autostart=True)` starts the worm when the launcher boots, for demos
where nobody runs the command by hand.

## What the worm will not do

- Attack a machine that is not on its list.
- Start when its break-in cannot work on this host.
- Start before the stop-signal server has answered.
- Read a missing answer from the switch as "go". It stops instead.
- Run longer than `max_seconds` (30 minutes by default).
- Run twice on one machine, or overwrite a machine that is already infected.

## Writing a part

Any class can fill a slot if it follows three rules:

1. a class attribute `SLOT` naming its slot;
2. a constructor whose arguments are plain data, each kept in an attribute of
   the same name;
3. the method of its slot.

```python
class DnsKillSwitch:                       # from Switch_Service
    SLOT = "governor"

    def __init__(self, domain, server=None):
        self.domain = domain
        self.server = server

    def allowed(self):                     # True while the worm may spread
        ...
```

| Slot | Method | Called |
| --- | --- | --- |
| `scanner` | `next_target(exclude)` → address or `None` | each round |
| `entry` | `break_in(target, body)` → `"arrived"`, `"already"` or `None` | each round |
| `governor` | `allowed()` → `True` or `False` | each round, before anything else |
| `payload` | `run(worm)` | once, on the machine the body landed on |

A part may also have a few more things, all optional:

| | What it is for |
| --- | --- |
| `prepare(worm)` | called once on every machine; the `worm` does the networking for the part |
| `check_host()` | on any part, on the launcher: problems that stop the launch. It may also measure something there that then travels inside the body |
| `stage(node)` | on the launcher at build time: the tools the part needs there |
| `TARGET_NEEDS`, `TARGET_BUILD` (class) | software and build commands every target and the launcher need |
| `NEEDS_LAYER` (class) | a layer that must be installed before the worm; the ransomware names its payment chain |

A part lives in its own small package next to the component that provides it
(for example `yom_morris_bof/`, `yom_switch/`). The installer ships that
folder inside the worm body. Keep it to the standard library, and do not
import the worm package from it: the part has to run on any machine.

## Options

`Worm(..., pace=Pace(...))` sets the loop itself:

| | Default | |
| --- | --- | --- |
| `attempt_delay` | 2.0 | seconds between two attempts |
| `announce_wait` | 8.0 | how long to wait for a victim to answer |
| `body_wait` | 8.0 | how long to wait for a victim to take the body |
| `max_seconds` | 1800 | the worm always stops after this |
| `startup_wait` | 60 | how long to wait for the stop-signal server at start |
| `announce_port` | 9998 | UDP port that victims answer on |

## Example

[`examples/morris_picture.py`](examples/morris_picture.py) is the smallest
worm lab: three victims, one attacker, one switch, nothing carried. Its
docstring has the commands.

## Tests

From the repository root: `.venv/bin/python -m pytest`. They need no Docker.
