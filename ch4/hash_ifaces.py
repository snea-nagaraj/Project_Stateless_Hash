# slhdsa/ch4/hash_ifaces.py
"""
Section 4.1 – Hash Functions and Pseudorandom Functions.

This module is the *frontend* used by all higher-level code (WOTS, XMSS, FORS,
hypertree, SLH-DSA). It dispatches to the Chapter 11 implementations:

- SHAKE-based (Section 11.1)      → slhdsa.ch11.hash_shake
- SHA2-based  (Section 11.2.1/2)  → slhdsa.ch11.hash_sha2

You can switch between them at runtime with:

    from slhdsa.ch4 import hash_ifaces
    hash_ifaces.set_hash_family("shake")  # or "sha2"

The function *signatures* stay the same as before, so callers don’t change.
"""

from __future__ import annotations

from .adrs import ADRS
from slhdsa.ch11 import (
    # SHAKE backend
    hmsg_shake,
    prf_shake,
    prf_msg_shake,
    F_shake,
    H_shake,
    T_l_shake,
    # SHA2 backend
    hmsg_sha2,
    prf_sha2,
    prf_msg_sha2,
    F_sha2,
    H_sha2,
    T_l_sha2,
)

# ---------------------------------------------------------------------
# Global selection of hash family
# ---------------------------------------------------------------------

_HASH_FAMILY: str = "shake"  # default: SHAKE parameter sets


def set_hash_family(name: str) -> None:
    """
    Select hash family used by all higher-level code.

    name: "shake"  → use Chapter 11.1 SHAKE256 instantiation
          "sha2"   → use Chapter 11.2 SHA2 instantiation
    """
    global _HASH_FAMILY
    if name not in ("shake", "sha2"):
        raise ValueError("hash family must be 'shake' or 'sha2'")
    _HASH_FAMILY = name


def get_hash_family() -> str:
    """Return the currently active hash family ("shake" or "sha2")."""
    return _HASH_FAMILY


# ---------------------------------------------------------------------
# Public interfaces used everywhere else
# ---------------------------------------------------------------------


def prf_msg(SK_prf: bytes, opt_rand: bytes, M: bytes, n: int) -> bytes:
    if _HASH_FAMILY == "shake":
        return prf_msg_shake(SK_prf, opt_rand, M, n)
    else:
        return prf_msg_sha2(SK_prf, opt_rand, M, n)


def h_msg(R: bytes, PK_seed: bytes, PK_root: bytes, M: bytes, m: int) -> bytes:
    if _HASH_FAMILY == "shake":
        return hmsg_shake(R, PK_seed, PK_root, M, m)
    else:
        # SHA2 Hmsg needs both m *and* n; n = |PK_seed| = |PK_root|
        n = len(PK_seed)
        return hmsg_sha2(R, PK_seed, PK_root, M, m, n)


def prf(PK_seed: bytes, SK_seed: bytes, adrs: ADRS, n: int) -> bytes:
    if _HASH_FAMILY == "shake":
        return prf_shake(PK_seed, SK_seed, adrs, n)
    else:
        return prf_sha2(PK_seed, SK_seed, adrs, n)


def T_l(PK_seed: bytes, adrs: ADRS, M_l: bytes, n: int) -> bytes:
    if _HASH_FAMILY == "shake":
        return T_l_shake(PK_seed, adrs, M_l, n)
    else:
        return T_l_sha2(PK_seed, adrs, M_l, n)


def H(PK_seed: bytes, adrs: ADRS, M_2: bytes, n: int) -> bytes:
    if _HASH_FAMILY == "shake":
        return H_shake(PK_seed, adrs, M_2, n)
    else:
        return H_sha2(PK_seed, adrs, M_2, n)


def F(PK_seed: bytes, adrs: ADRS, M_1: bytes, n: int) -> bytes:
    if _HASH_FAMILY == "shake":
        return F_shake(PK_seed, adrs, M_1, n)
    else:
        return F_sha2(PK_seed, adrs, M_1, n)
