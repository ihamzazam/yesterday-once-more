"""Switch_Service: a stop signal the teacher can flip while the lab runs.

    from software.Switch_Service import DnsSwitch, DnsKillSwitch
"""

from .seedemu_service import DnsSwitch
from .yom_switch import DnsKillSwitch, SwitchUnreachable

__all__ = ["DnsKillSwitch", "DnsSwitch", "SwitchUnreachable"]
