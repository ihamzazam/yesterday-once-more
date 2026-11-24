"""The vulnerability catalogue. Each entry is a pair: a hole and its break-in."""

from .morris_bof import MorrisBufferOverflow

__all__ = ["MorrisBufferOverflow"]
