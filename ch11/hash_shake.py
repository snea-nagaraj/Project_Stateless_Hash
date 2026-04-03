# slhdsa/ch11/hash_shake.py
"""
Section 11.1 – SLH-DSA Using SHAKE.

Implements Hmsg, PRF, PRFmsg, F, H, Tl for the six SHAKE parameter sets.
"""

from __future__ import annotations

import hashlib

from slhdsa.ch4.adrs import ADRS


def hmsg_shake(
    R: bytes,
    PK_seed: bytes,
    PK_root: bytes,
    M: bytes,
    m: int,
) -> bytes:
    """
    Hmsg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m)
    8m bits => m bytes.
    """
    xof = hashlib.shake_256(R + PK_seed + PK_root + M)
    return xof.digest(m)


def prf_shake(
    PK_seed: bytes,
    SK_seed: bytes,
    adrs: ADRS,
    n: int,
) -> bytes:
    """
    PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
    """
    xof = hashlib.shake_256(PK_seed + adrs.to_bytes() + SK_seed)
    return xof.digest(n)


def prf_msg_shake(
    SK_prf: bytes,
    opt_rand: bytes,
    M: bytes,
    n: int,
) -> bytes:
    """
    PRFmsg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n)
    """
    xof = hashlib.shake_256(SK_prf + opt_rand + M)
    return xof.digest(n)


def F_shake(
    PK_seed: bytes,
    adrs: ADRS,
    M1: bytes,
    n: int,
) -> bytes:
    """
    F(PK.seed, ADRS, M1) = SHAKE256(PK.seed || ADRS || M1, 8n)
    """
    xof = hashlib.shake_256(PK_seed + adrs.to_bytes() + M1)
    return xof.digest(n)


def H_shake(
    PK_seed: bytes,
    adrs: ADRS,
    M2: bytes,
    n: int,
) -> bytes:
    """
    H(PK.seed, ADRS, M2) = SHAKE256(PK.seed || ADRS || M2, 8n)
    """
    xof = hashlib.shake_256(PK_seed + adrs.to_bytes() + M2)
    return xof.digest(n)


def T_l_shake(
    PK_seed: bytes,
    adrs: ADRS,
    M_l: bytes,
    n: int,
) -> bytes:
    """
    Tl(PK.seed, ADRS, M_l) = SHAKE256(PK.seed || ADRS || M_l, 8n)
    (ℓ is implicit from len(M_l) / n)
    """
    xof = hashlib.shake_256(PK_seed + adrs.to_bytes() + M_l)
    return xof.digest(n)
