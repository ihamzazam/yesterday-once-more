# Switch Service

The kill switch of the real WannaCry, as a lab piece.

```python
from software.Switch_Service import DnsKillSwitch, DnsSwitch

switch = DnsSwitch()                              # one machine plays the internet for the domain
emu.addLayer(switch)
emu.addBinding(Binding(switch.vnode, filter=Filter(asn=150, nodeName="switch")))

worm = Worm(..., governor=DnsKillSwitch(switch.kill_switch))   # a worm that obeys it
```

## What happened in 2017

When WannaCry started on a machine, it first tried to load one long nonsense
address over HTTP:

    www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com

Nobody had registered that domain, so nothing answered, and the worm went to
work. During the outbreak a security researcher registered it. From then on,
new copies got an answer and stopped. That one registration stopped the
spread.

## What it is

- **The domain.** The real one. One machine runs a real BIND server
  (seedemu's own DNS service) that is responsible for it, and every machine
  in the lab asks that server for names.
- **The web answer.** The same machine runs a small web server. It is always
  up, but it is reached only once the domain is registered.
- **The flip tool.** A one-word command on that machine. `switch stop` does
  what the researcher did: it registers `www.` and the domain, the exact
  name the worm asks for. It changes the DNS record
  with `nsupdate`, the tool Dr. Du's Morris worm (`control_worm.sh`) and his
  first WannaCry example (`add_record.sh`) use.
- **The reader.** `DnsKillSwitch` is the worm's "when to stop" slot. It does
  the same two steps as the real worm: it asks for the domain, and if the
  domain has an address it tries to load it over HTTP. It stops only if
  something really answers.

## Using it

Run these inside the switch's machine, for example
`docker compose exec <switch container> switch stop`:

| Command | What happens |
| --- | --- |
| `switch stop` | the domain is registered: it answers, every worm stops |
| `switch go` | the domain is unregistered: nothing answers, the worm may spread again |
| `switch status` | says whether the domain is registered, and whether it answers |
| `switch set pause` / `switch unset pause` | register or unregister another name |

On any machine in the lab a student can see the same thing by hand:

    nslookup www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com

## How the worm finds the server

A case gives the reader a domain and no address. The worm's installer looks
for the switch in the emulation, checks that the domain is inside its zone,
and fills in the server's address by itself.

## Two things the reader refuses to do

- **Guess.** If the DNS server does not answer, the worm stops with the
  reason. A missing answer is never read as "go".
- **Start too early.** When the worm launches it waits until the server has
  answered once, so BIND still starting up cannot be mistaken for "no such
  domain".

## One deliberate difference

The real worm checked the domain **once, when it started**. So registering the
domain later did not stop copies that were already running; it only stopped
new ones.

This reader checks **before every attempt**, so a teacher can stop a live
outbreak. For the exact behaviour: `DnsKillSwitch(..., every_round=False)`.

## Options

| | Default | |
| --- | --- | --- |
| `DnsSwitch(domain=...)` | the real domain | what the worm tries to load |
| `DnsSwitch(vnode=...)` | `yom-switch` | the virtual node name to install on |
| `DnsSwitch(http_port=...)` | `80` | where the registered domain answers |
| `DnsKillSwitch(domain, server=None)` | | `server` is filled in by the Worm installer |
| `DnsKillSwitch(..., every_round=True)` | | `False`: check once, as the real worm did |

The machine uses port **53/udp** (DNS) and **80/tcp** (HTTP).
