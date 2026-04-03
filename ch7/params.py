# slhdsa/ch7/params.py
"""
Hypertree parameters (Section 7).

- n       : security parameter (bytes)
- d       : number of XMSS layers in the hypertree
- h_prime : height of each XMSS tree (h′), so total height h = d * h_prime
"""

from __future__ import annotations

from dataclasses import dataclass

from slhdsa.ch6.params import XmssParams
from slhdsa.ch5.params import WotsParams


@dataclass(frozen=True)
class HypertreeParams:
    n: int
    d: int
    h_prime: int  # per-layer XMSS tree height (h′)

    @property
    def xmss(self) -> XmssParams:
        """XMSS parameters shared by all layers."""
        return XmssParams(self.n, self.h_prime)

    @property
    def wots(self) -> WotsParams:
        """Underlying WOTS+ parameters."""
        return WotsParams(self.n)

    @property
    def h_total(self) -> int:
        """Total hypertree height h = d * h′."""
        return self.d * self.h_prime
