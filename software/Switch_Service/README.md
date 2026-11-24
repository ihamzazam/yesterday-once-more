# Switch Service

A stop signal that the teacher can flip while the lab runs.

```python
from software.Switch_Service import DnsKillSwitch, DnsSwitch

switch = DnsSwitch()                              # one machine hosts it
emu.addLayer(switch)
emu.addBinding(Binding(switch.vnode, filter=Filter(asn=150, nodeName="switch")))

worm = Worm(..., governor=DnsKillSwitch(switch.name("stop")))   # a worm that obeys it
```

## What it is

The real WannaCry looked up a long nonsense domain before it went to work.
As long as the name did not exist it spread; the moment somebody registered
it, every copy stopped. This service plays that registry:

- **The server.** One machine runs a real BIND server (seedemu's own DNS
  service) with one small zone, `yom.test.` by default.
- **The flip tool.** The same machine gets a one-word command to change the
  zone while the lab runs. It uses `nsupdate`, the tool Dr. Du's Morris worm
  (`control_worm.sh`) and his first WannaCry example (`add_record.sh`) use.
- **The reader.** `DnsKillSwitch` is the worm's "when to stop" slot. The worm
  asks the server directly, by its address, so nothing in the emulation has
  to be told about DNS.

## Using it

Run these inside the switch's machine, for example
`docker compose exec <switch container> switch stop`:

| Command | What happens |
| --- | --- |
| `switch stop` | the name `stop.yom.test` starts to exist: every worm stops |
| `switch go` | the name is removed: the worm may spread again |
| `switch status` | says whether the signal is there right now |
| `switch set pause` / `switch unset pause` | the same for any other name |

The worm checks the switch before every attempt, so a flip takes effect
within seconds. New copies check it first too, so the outbreak stays stopped.

## How the worm finds the server

A case gives the reader a name (`stop.yom.test`) and no address. The worm's
installer looks for the switch in the emulation, checks that the name is
inside its zone, and fills in the server's address by itself.

## Two things the reader refuses to do

- **Guess.** If the server does not answer, the worm stops with the reason.
  A missing answer is never read as "go".
- **Start too early.** When the worm launches it waits until the server has
  answered once, so BIND still starting up cannot be mistaken for "no stop
  signal".

## Options

| | Default | |
| --- | --- | --- |
| `DnsSwitch(zone=...)` | `yom.test` | the zone the server is responsible for |
| `DnsSwitch(vnode=...)` | `yom-switch` | the virtual node name to install on |
| `DnsSwitch(value=...)` | `127.0.0.1` | the address a signal points to |
| `DnsKillSwitch(domain, server=None)` | | `server` is filled in by the Worm installer |
| `DnsKillSwitch(..., timeout=2.0, tries=3)` | | how long to wait for the server |

The server needs port **53/udp** on its machine.
