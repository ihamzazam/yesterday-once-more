"""The buffer-overflow hole from Dr. Du's Morris worm example, with its break-in.

The two halves of the pair: `MorrisBufferOverflow` is the hole an installer
puts on victims, and `MorrisBofEntry` is the break-in that matches it.
"""

from .hole import MorrisBufferOverflow
from .yom_morris_bof import MorrisBofEntry

__all__ = ["MorrisBofEntry", "MorrisBufferOverflow"]
