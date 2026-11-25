"""Switch_Service: the kill-switch domain of the real WannaCry, as a lab piece.

    from software.Switch_Service import DnsKillSwitch, DnsSwitch

    switch = DnsSwitch()                                # the machine that serves the domain
    worm = Worm(..., governor=DnsKillSwitch(switch.kill_switch))
"""

from .seedemu_service import KILL_SWITCH, DnsSwitch
from .yom_switch import DnsKillSwitch, SwitchUnreachable

__all__ = ["DnsKillSwitch", "DnsSwitch", "KILL_SWITCH", "SwitchUnreachable"]
