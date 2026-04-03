# slhdsa/ch11/hash_sha2.py
"""
Section 11.2 – SLH-DSA Using SHA2.

Implements Hmsg, PRF, PRFmsg, F, H, Tl for all SHA2 parameter sets.

We distinguish:
- Category 1 (n = 16): Section 11.2.1
- Categories 3 & 5 (n = 24 or 32): Section 11.2.2
"""

from __future__ import annotations

import hashlib
import hmac

from slhdsa.ch4.adrs import ADRS


def _compress_adrs(adrs: ADRS) -> bytes:
    """
    Compressed address ADRS^c:

      ADRS^c = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]

    (See Figure 18 in FIPS 205.)
    """
    b = adrs.to_bytes()
    return b[3:4] + b[8:16] + b[19:20] + b[20:32]  # 1 + 8 + 1 + 12 = 22 bytes


def _trunc_n(d: bytes, n: int) -> bytes:
    """Trunc_n(d) – first n bytes."""
    return d[:n]


def _mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    """
    MGF1 from RFC 8017 (Appendix B.2.1), generic over SHA-256 / SHA-512.

    hash_name: "sha256" or "sha512"
    """
    if hash_name == "sha256":
        hlen = 32
        hfn = hashlib.sha256
    elif hash_name == "sha512":
        hlen = 64
        hfn = hashlib.sha512
    else:
        raise ValueError(f"Unsupported hash_name for MGF1: {hash_name}")

    if length == 0:
        return b""

    T = bytearray()
    counter = 0
    while len(T) < length:
        C = counter.to_bytes(4, "big")
        T.extend(hfn(seed + C).digest())
        counter += 1

    return bytes(T[:length])


# ---------------------------------------------------------------------------
# Hmsg
# ---------------------------------------------------------------------------


def hmsg_sha2(
    R: bytes,
    PK_seed: bytes,
    PK_root: bytes,
    M: bytes,
    m: int,
    n: int,
) -> bytes:
    """
    Hmsg for SHA2 parameter sets.

    If n = 16:
      Hmsg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)

    If n = 24 or 32:
      Hmsg = MGF1-SHA-512(R || PK.seed || SHA-512(R || PK.seed || PK.root || M), m)
    """
    if n == 16:
        inner = hashlib.sha256(R + PK_seed + PK_root + M).digest()
        seed = R + PK_seed + inner
        return _mgf1(seed, m, "sha256")
    else:
        inner = hashlib.sha512(R + PK_seed + PK_root + M).digest()
        seed = R + PK_seed + inner
        return _mgf1(seed, m, "sha512")


# ---------------------------------------------------------------------------
# PRF
# ---------------------------------------------------------------------------


def prf_sha2(
    PK_seed: bytes,
    SK_seed: bytes,
    adrs: ADRS,
    n: int,
) -> bytes:
    """
    PRF(PK.seed, SK.seed, ADRS)

    - For all SHA2 parameter sets, uses SHA-256 and truncation:

      PRF = Trunc_n(SHA-256(PK.seed || zero(64 - n) || ADRS^c || SK.seed))
    """
    adrs_c = _compress_adrs(adrs)
    pad_len = 64 - n
    zeros = b"\x00" * pad_len
    d = hashlib.sha256(PK_seed + zeros + adrs_c + SK_seed).digest()
    return _trunc_n(d, n)


# ---------------------------------------------------------------------------
# PRFmsg
# ---------------------------------------------------------------------------


def prf_msg_sha2(
    SK_prf: bytes,
    opt_rand: bytes,
    M: bytes,
    n: int,
) -> bytes:
    """
    PRFmsg(SK.prf, opt_rand, M)

    - If n = 16: Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M))
    - If n = 24 or 32: Trunc_n(HMAC-SHA-512(SK.prf, opt_rand || M))
    """
    data = opt_rand + M
    if n == 16:
        d = hmac.new(SK_prf, data, hashlib.sha256).digest()
    else:
        d = hmac.new(SK_prf, data, hashlib.sha512).digest()
    return _trunc_n(d, n)


# ---------------------------------------------------------------------------
# F
# ---------------------------------------------------------------------------


def F_sha2(
    PK_seed: bytes,
    adrs: ADRS,
    M1: bytes,
    n: int,
) -> bytes:
    """
    F(PK.seed, ADRS, M1)

    - For all SHA2 parameter sets, uses SHA-256:

      F = Trunc_n(SHA-256(PK.seed || zero(64 - n) || ADRS^c || M1))
    """
    adrs_c = _compress_adrs(adrs)
    pad_len = 64 - n
    zeros = b"\x00" * pad_len
    d = hashlib.sha256(PK_seed + zeros + adrs_c + M1).digest()
    return _trunc_n(d, n)


# ---------------------------------------------------------------------------
# H
# ---------------------------------------------------------------------------


def H_sha2(
    PK_seed: bytes,
    adrs: ADRS,
    M2: bytes,
    n: int,
) -> bytes:
    """
    H(PK.seed, ADRS, M2)

    - For n = 16:
        H = Trunc_n(SHA-256(PK.seed || zero(64 - n) || ADRS^c || M2))

    - For n = 24 or 32:
        H = Trunc_n(SHA-512(PK.seed || zero(128 - n) || ADRS^c || M2))
    """
    adrs_c = _compress_adrs(adrs)
    if n == 16:
        pad_len = 64 - n
        zeros = b"\x00" * pad_len
        d = hashlib.sha256(PK_seed + zeros + adrs_c + M2).digest()
    else:
        pad_len = 128 - n
        zeros = b"\x00" * pad_len
        d = hashlib.sha512(PK_seed + zeros + adrs_c + M2).digest()
    return _trunc_n(d, n)


# ---------------------------------------------------------------------------
# Tl
# ---------------------------------------------------------------------------


def T_l_sha2(
    PK_seed: bytes,
    adrs: ADRS,
    M_l: bytes,
    n: int,
) -> bytes:
    """
    Tl(PK.seed, ADRS, M_l)

    - For n = 16:
        Tl = Trunc_n(SHA-256(PK.seed || zero(64 - n) || ADRS^c || M_l))

    - For n = 24 or 32:
        Tl = Trunc_n(SHA-512(PK.seed || zero(128 - n) || ADRS^c || M_l))
    """
    adrs_c = _compress_adrs(adrs)
    if n == 16:
        pad_len = 64 - n
        zeros = b"\x00" * pad_len
        d = hashlib.sha256(PK_seed + zeros + adrs_c + M_l).digest()
    else:
        pad_len = 128 - n
        zeros = b"\x00" * pad_len
        d = hashlib.sha512(PK_seed + zeros + adrs_c + M_l).digest()
    return _trunc_n(d, n)
