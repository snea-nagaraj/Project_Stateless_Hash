# slhdsa/ch8/params.py
"""
FORS parameters (Section 8).

Parameters:
- n : security parameter (bytes) – same n as WOTS/XMSS
- k : number of FORS trees
- a : height of each FORS tree (t = 2^a leaves per tree)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ForsParams:
    n: int
    k: int
    a: int  # tree height; t = 2^a leaves per tree

    @property
    def t(self) -> int:
        """Number of leaves per tree: t = 2^a."""
        return 1 << self.a

    @property
    def m_bits(self) -> int:
        """Number of bits in the message digest signed by this FORS key: k * a."""
        return self.k * self.a

    @property
    def md_bytes(self) -> int:
        """Number of bytes required to hold the k*a bits: ceil(k*a / 8)."""
        return (self.m_bits + 7) // 8
