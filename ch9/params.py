# slhdsa/ch9/params.py
"""
SLH-DSA parameter glue (Section 9 + Table 2).

This ties together:
- Hypertree parameters (d, h′)
- FORS parameters (k, a)
- WOTS/XMSS parameters (from earlier chapters)
"""

from __future__ import annotations

from dataclasses import dataclass

from slhdsa.ch5.params import WotsParams
from slhdsa.ch6.params import XmssParams
from slhdsa.ch7.params import HypertreeParams
from slhdsa.ch8.params import ForsParams


@dataclass(frozen=True)
class SlhDsaParams:
    """
    n      : security parameter (bytes)
    d      : number of XMSS layers in the hypertree
    h_prime: per-layer XMSS tree height h′
    k      : number of FORS trees
    a      : height of each FORS tree (t = 2^a leaves)
    """
    n: int
    d: int
    h_prime: int
    k: int
    a: int

    # --- derived ---

    @property
    def h_total(self) -> int:
        """Total hypertree height h = d * h′."""
        return self.d * self.h_prime

    # underlying building-block parameter objects

    @property
    def wots(self) -> WotsParams:
        return WotsParams(self.n)

    @property
    def xmss(self) -> XmssParams:
        return XmssParams(self.n, self.h_prime)

    @property
    def ht(self) -> HypertreeParams:
        return HypertreeParams(self.n, self.d, self.h_prime)

    @property
    def fors(self) -> ForsParams:
        return ForsParams(self.n, self.k, self.a)

    # --- message digest length m (bytes) ---

    @property
    def md_bytes(self) -> int:
        """
        m = ceil((h - h′)/8) + ceil(k*a / 8) + ceil(h′/8)

        We use:
        - first ceil(k*a/8) bytes for md (FORS)
        - next  ceil((h - h′)/8) bytes for idxtree
        - next  ceil(h′/8)      bytes for idxleaf
        """
        h = self.h_total
        h_prime = self.h_prime
        k = self.k
        a = self.a

        part_md = (k * a + 7) // 8
        part_tree = (h - h_prime + 7) // 8
        part_leaf = (h_prime + 7) // 8

        return part_md + part_tree + part_leaf
