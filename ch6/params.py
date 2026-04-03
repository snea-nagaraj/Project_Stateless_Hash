# slhdsa/ch6/params.py
"""
XMSS parameters (Section 6).

- n       : security parameter (bytes) – same n as WOTS+
- h_prime : height of the XMSS tree (h′), so there are 2^h′ leaves.

We reuse the WOTS+ parameters from Chapter 5.
"""

from __future__ import annotations

from dataclasses import dataclass

from slhdsa.ch5.params import WotsParams


@dataclass(frozen=True)
class XmssParams:
    n: int
    h_prime: int  # h′ – tree height

    @property
    def wots(self) -> WotsParams:
        """Associated WOTS+ parameters for this XMSS key."""
        return WotsParams(self.n)
