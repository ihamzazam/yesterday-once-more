"""Ransomware_Service: what the worm carries for WannaCry.

    from software.Ransomware_Service import Ransomware

    ransom = Ransomware(in_as=lab, on_network="net0")    payment chain + the payload
    worm = Worm(entry=bof.exploit(), payload=ransom.payload, ...)
"""

from .seedemu_service import Ransomware
from .yom_ransomware import RansomwarePayload

__all__ = ["Ransomware", "RansomwarePayload"]
