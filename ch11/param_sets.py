# slhdsa/ch11/param_sets.py
"""
Section 11 – FIPS 205 parameter sets (Table 2).

We define a small ParamSetInfo that stores:
- The raw FIPS parameters (n, h, d, h', a, k, lgw, m)
- Meta info: hash_family ("shake" or "sha2"), variant ("s" or "f"),
  security_category, pk_bytes, sig_bytes
- A helper to construct a SlhDsaParams object used by the rest of the code.
"""

from __future__ import annotations

from dataclasses import dataclass

from slhdsa.ch9.params import SlhDsaParams


@dataclass(frozen=True)
class ParamSetInfo:
    name: str
    n: int
    h: int
    d: int
    h_prime: int
    a: int
    k: int
    lgw: int
    m: int
    hash_family: str          # "shake" or "sha2"
    variant: str              # "s" or "f"
    security_category: int    # 1, 3, or 5
    pk_bytes: int
    sig_bytes: int

    def to_params(self) -> SlhDsaParams:
        """
        Create a SlhDsaParams object used by your implementation.
        SlhDsaParams is assumed to take (n, d, h_prime, k, a).
        Total height h = d * h_prime is implied.
        """
        return SlhDsaParams(
            n=self.n,
            d=self.d,
            h_prime=self.h_prime,
            k=self.k,
            a=self.a,
        )


#
# Helper to avoid typing: all lgw = 4 in FIPS 205.
#
LGW = 4


# ------------------------- SHAKE parameter sets ------------------------- #

SLH_DSA_SHAKE_128s = ParamSetInfo(
    name="SLH-DSA-SHAKE-128s",
    n=16,
    h=63,
    d=7,
    h_prime=9,
    a=12,
    k=14,
    lgw=LGW,
    m=30,
    hash_family="shake",
    variant="s",
    security_category=1,
    pk_bytes=32,
    sig_bytes=7856,
)

SLH_DSA_SHAKE_128f = ParamSetInfo(
    name="SLH-DSA-SHAKE-128f",
    n=16,
    h=66,
    d=22,
    h_prime=3,
    a=6,
    k=33,
    lgw=LGW,
    m=34,
    hash_family="shake",
    variant="f",
    security_category=1,
    pk_bytes=32,
    sig_bytes=17088,
)

SLH_DSA_SHAKE_192s = ParamSetInfo(
    name="SLH-DSA-SHAKE-192s",
    n=24,
    h=63,
    d=7,
    h_prime=9,
    a=14,
    k=17,
    lgw=LGW,
    m=39,
    hash_family="shake",
    variant="s",
    security_category=3,
    pk_bytes=48,
    sig_bytes=16224,
)

SLH_DSA_SHAKE_192f = ParamSetInfo(
    name="SLH-DSA-SHAKE-192f",
    n=24,
    h=66,
    d=22,
    h_prime=3,
    a=8,
    k=33,
    lgw=LGW,
    m=42,
    hash_family="shake",
    variant="f",
    security_category=3,
    pk_bytes=48,
    sig_bytes=35664,
)

SLH_DSA_SHAKE_256s = ParamSetInfo(
    name="SLH-DSA-SHAKE-256s",
    n=32,
    h=64,
    d=8,
    h_prime=8,
    a=14,
    k=22,
    lgw=LGW,
    m=47,
    hash_family="shake",
    variant="s",
    security_category=5,
    pk_bytes=64,
    sig_bytes=29792,
)

SLH_DSA_SHAKE_256f = ParamSetInfo(
    name="SLH-DSA-SHAKE-256f",
    n=32,
    h=68,
    d=17,
    h_prime=4,
    a=9,
    k=35,
    lgw=LGW,
    m=49,
    hash_family="shake",
    variant="f",
    security_category=5,
    pk_bytes=64,
    sig_bytes=49856,
)

# ------------------------- SHA2 parameter sets -------------------------- #

SLH_DSA_SHA2_128s = ParamSetInfo(
    name="SLH-DSA-SHA2-128s",
    n=16,
    h=63,
    d=7,
    h_prime=9,
    a=12,
    k=14,
    lgw=LGW,
    m=30,
    hash_family="sha2",
    variant="s",
    security_category=1,
    pk_bytes=32,
    sig_bytes=7856,
)

SLH_DSA_SHA2_128f = ParamSetInfo(
    name="SLH-DSA-SHA2-128f",
    n=16,
    h=66,
    d=22,
    h_prime=3,
    a=6,
    k=33,
    lgw=LGW,
    m=34,
    hash_family="sha2",
    variant="f",
    security_category=1,
    pk_bytes=32,
    sig_bytes=17088,
)

SLH_DSA_SHA2_192s = ParamSetInfo(
    name="SLH-DSA-SHA2-192s",
    n=24,
    h=63,
    d=7,
    h_prime=9,
    a=14,
    k=17,
    lgw=LGW,
    m=39,
    hash_family="sha2",
    variant="s",
    security_category=3,
    pk_bytes=48,
    sig_bytes=16224,
)

SLH_DSA_SHA2_192f = ParamSetInfo(
    name="SLH-DSA-SHA2-192f",
    n=24,
    h=66,
    d=22,
    h_prime=3,
    a=8,
    k=33,
    lgw=LGW,
    m=42,
    hash_family="sha2",
    variant="f",
    security_category=3,
    pk_bytes=48,
    sig_bytes=35664,
)

SLH_DSA_SHA2_256s = ParamSetInfo(
    name="SLH-DSA-SHA2-256s",
    n=32,
    h=64,
    d=8,
    h_prime=8,
    a=14,
    k=22,
    lgw=LGW,
    m=47,
    hash_family="sha2",
    variant="s",
    security_category=5,
    pk_bytes=64,
    sig_bytes=29792,
)

SLH_DSA_SHA2_256f = ParamSetInfo(
    name="SLH-DSA-SHA2-256f",
    n=32,
    h=68,
    d=17,
    h_prime=4,
    a=9,
    k=35,
    lgw=LGW,
    m=49,
    hash_family="sha2",
    variant="f",
    security_category=5,
    pk_bytes=64,
    sig_bytes=49856,
)

ALL_PARAM_SETS = [
    SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_192s,
    SLH_DSA_SHAKE_192f,
    SLH_DSA_SHAKE_256s,
    SLH_DSA_SHAKE_256f,
    SLH_DSA_SHA2_128s,
    SLH_DSA_SHA2_128f,
    SLH_DSA_SHA2_192s,
    SLH_DSA_SHA2_192f,
    SLH_DSA_SHA2_256s,
    SLH_DSA_SHA2_256f,
]
