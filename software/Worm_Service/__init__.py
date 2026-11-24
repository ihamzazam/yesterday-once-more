"""Worm_Service: the spread loop with four slots the case fills in.

    from software.Worm_Service import Worm
    worm = Worm(entry=bof.exploit(), payload=ransomware, governor=DnsKillSwitch(...))

Slots: `scanner` (who to attack), `entry` (how to break in), `payload` (what
to do after breaking in) and `governor` (when to stop). A case may leave
`scanner` and `payload` out: the worm then attacks every machine that has the
matching hole and carries nothing.
"""

from .seedemu_service import Worm
from .yom_worm.builtin import NoPayload, ShuffleScanner
from .yom_worm.spec import Pace

__all__ = ["NoPayload", "Pace", "ShuffleScanner", "Worm"]
