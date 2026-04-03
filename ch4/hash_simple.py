# slhdsa/ch4/hash_simple.py
"""
Simple, non-standard but consistent instantiation of the Section 4.1 functions
using SHA-256, just to test WOTS+ end-to-end.

Later, we will replace this with the exact FIPS 205 Section 11 instantiation.
"""

from __future__ import annotations

import hashlib

from .adrs import ADRS


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def prf_msg(SK_prf: bytes, opt_rand: bytes, M: bytes, n: int) -> bytes:
    """
    PRFmsg(SK.prf, opt_rand, M) -> B^n
    Simple instantiation: H("PRFmsg" || SK_prf || opt_rand || M)
    """
    h = _sha256(b"PRFmsg" + SK_prf + opt_rand + M)
    return h[:n]


def h_msg(R: bytes, PK_seed: bytes, PK_root: bytes, M: bytes, m: int) -> bytes:
    """
    Hmsg(R, PK.seed, PK.root, M) -> B^m
    Simple instantiation: H("Hmsg" || R || PK_seed || PK_root || M)
    Supports m <= 32 only.
    """
    h = _sha256(b"Hmsg" + R + PK_seed + PK_root + M)
    if m <= 32:
        return h[:m]
    raise ValueError("h_msg simple impl supports m <= 32 only")


def prf(PK_seed: bytes, SK_seed: bytes, adrs: ADRS, n: int) -> bytes:
    """
    PRF(PK.seed, SK.seed, ADRS) -> B^n
    Simple instantiation: H("PRF" || PK_seed || SK_seed || ADRS)
    """
    h = _sha256(b"PRF" + PK_seed + SK_seed + adrs.to_bytes())
    return h[:n]


def T_l(PK_seed: bytes, adrs: ADRS, M_l: bytes, n: int) -> bytes:
    """
    Tl(PK.seed, ADRS, M_l) -> B^n
    Simple instantiation: H("Tl" || PK_seed || ADRS || M_l)
    """
    h = _sha256(b"Tl" + PK_seed + adrs.to_bytes() + M_l)
    return h[:n]


def H(PK_seed: bytes, adrs: ADRS, M_2: bytes, n: int) -> bytes:
    """
    H(PK.seed, ADRS, M_2) -> B^n
    M_2 is 2n bytes; domain-separated SHA-256.
    """
    h = _sha256(b"H" + PK_seed + adrs.to_bytes() + M_2)
    return h[:n]


def F(PK_seed: bytes, adrs: ADRS, M_1: bytes, n: int) -> bytes:
    """
    F(PK.seed, ADRS, M_1) -> B^n
    M_1 is n bytes; domain-separated SHA-256.
    """
    h = _sha256(b"F" + PK_seed + adrs.to_bytes() + M_1)
    return h[:n]
