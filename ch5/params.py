# slhdsa/params.py
"""
Parameter helpers for SLH-DSA WOTS+ (Section 5).

For all FIPS 205 parameter sets, lgw = 4, so:
- w    = 2^lgw = 16
- len1 = ceil(8n / lgw) = 2n
- len2 = floor(log2(len1 * (w - 1)) / lgw) + 1 = 3
- len  = len1 + len2 = 2n + 3
"""

from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class WotsParams:
    n: int         # security parameter (bytes)
    lgw: int = 4   # log2(w); fixed to 4 in FIPS 205

    @property
    def w(self) -> int:
        return 1 << self.lgw

    @property
    def len1(self) -> int:
        # len1 = ceil(8n / lgw)
        return math.ceil((8 * self.n) / self.lgw)

    @property
    def len2(self) -> int:
        # len2 = floor(log2(len1 * (w - 1)) / lgw) + 1
        return math.floor(math.log2(self.len1 * (self.w - 1)) / self.lgw) + 1

    @property
    def length(self) -> int:
        # len = len1 + len2
        return self.len1 + self.len2
