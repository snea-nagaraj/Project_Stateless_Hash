# slhdsa/ch10/api.py
"""
SLH-DSA external functions (Section 10):

- Algorithm 21: slh_keygen()
- Algorithm 22: slh_sign()         (pure)
- Algorithm 23: hash_slh_sign()    (pre-hash)
- Algorithm 24: slh_verify()       (pure)
- Algorithm 25: hash_slh_verify()  (pre-hash)

These are thin wrappers around the internal functions from Chapter 9.
"""

from __future__ import annotations

import os
import hashlib
from typing import Callable, Literal, Tuple

from slhdsa.ch4.utils import to_bytes_be
from slhdsa.ch9.params import SlhDsaParams
from slhdsa.ch9.slh_dsa import (
    SlhDsaPrivateKey,
    SlhDsaPublicKey,
    SlhDsaSignature,
    slh_keygen_internal,
    slh_sign_internal,
    slh_verify_internal,
)


# ---------------------------------------------------------------------------
# Randomness helper
# ---------------------------------------------------------------------------


def _default_rng(n: int) -> bytes:
    """Default RNG: os.urandom(n)."""
    return os.urandom(n)


# ---------------------------------------------------------------------------
# Algorithm 21: slh_keygen()
# ---------------------------------------------------------------------------


def slh_keygen(
    params: SlhDsaParams,
    rng: Callable[[int], bytes] = _default_rng,
) -> Tuple[SlhDsaPrivateKey, SlhDsaPublicKey]:
    """
    Algorithm 21 slh_keygen()

    Generates an SLH-DSA key pair.

    Input :
      - params: SlhDsaParams
      - rng   : callable(n) -> n random bytes (default: os.urandom)

    Output:
      - (SK, PK)
    """
    n = params.n

    SK_seed = rng(n)
    SK_prf = rng(n)
    PK_seed = rng(n)

    # Spec has a NULL check; in Python, rng should always return bytes.
    if SK_seed is None or SK_prf is None or PK_seed is None:
        raise RuntimeError("slh_keygen: RNG failed to produce bytes")

    return slh_keygen_internal(SK_seed, SK_prf, PK_seed, params)


# ---------------------------------------------------------------------------
# Pure SLH-DSA signing & verification (Algorithms 22 & 24)
# ---------------------------------------------------------------------------


def slh_sign(
    M: bytes,
    SK: SlhDsaPrivateKey,
    params: SlhDsaParams,
    ctx: bytes = b"",
    deterministic: bool = False,
    rng: Callable[[int], bytes] = _default_rng,
) -> SlhDsaSignature:
    """
    Algorithm 22 slh_sign(M, ctx, SK)

    Pure SLH-DSA signature generation.

    - M      : message bytes
    - ctx    : context string, length <= 255 (default: empty)
    - SK     : SLH-DSA private key
    - params : SlhDsaParams
    - deterministic: if True, uses deterministic variant (addrnd omitted)
    - rng    : RNG for hedged variant (addrnd), default os.urandom
    """
    if len(ctx) > 255:
        raise ValueError("slh_sign: context string too long (> 255 bytes)")

    n = params.n

    if deterministic:
        addrnd = None
    else:
        addrnd = rng(n)
        if addrnd is None:
            raise RuntimeError("slh_sign: RNG failed to produce addrnd")

    # M′ = toByte(0, 1) ∥ toByte(|ctx|, 1) ∥ ctx ∥ M
    M_prime = bytes([0]) + bytes([len(ctx)]) + ctx + M

    return slh_sign_internal(M_prime, SK, addrnd, params)


def slh_verify(
    M: bytes,
    SIG: SlhDsaSignature,
    PK: SlhDsaPublicKey,
    params: SlhDsaParams,
    ctx: bytes = b"",
) -> bool:
    """
    Algorithm 24 slh_verify(M, SIG, ctx, PK)

    Pure SLH-DSA signature verification.

    - M      : message bytes
    - SIG    : structured SLH-DSA signature
    - PK     : SLH-DSA public key
    - params : SlhDsaParams
    - ctx    : context string, length <= 255 (default: empty)
    """
    if len(ctx) > 255:
        return False

    # M′ = toByte(0, 1) ∥ toByte(|ctx|, 1) ∥ ctx ∥ M
    M_prime = bytes([0]) + bytes([len(ctx)]) + ctx + M
    return slh_verify_internal(M_prime, SIG, PK, params)


# ---------------------------------------------------------------------------
# Pre-hash SLH-DSA (Algorithms 23 & 25)
# ---------------------------------------------------------------------------

PreHashName = Literal["sha256", "sha512", "shake128", "shake256"]


def _compute_ph_and_oid(
    M: bytes,
    ph_name: PreHashName,
) -> tuple[bytes, bytes]:
    """
    Helper for Algorithms 23 & 25.

    Given:
      - M       : message bytes
      - ph_name : "sha256" | "sha512" | "shake128" | "shake256"

    Returns:
      - (OID, PHM)
        OID : DER encoding of hash/XOF OID (11 bytes, per spec)
        PHM : digest / XOF output bytes
    """
    if ph_name == "sha256":
        # 2.16.840.1.101.3.4.2.1
        oid_int = 0x0609608648016503040201
        OID = to_bytes_be(oid_int, 11)
        PHM = hashlib.sha256(M).digest()
    elif ph_name == "sha512":
        # 2.16.840.1.101.3.4.2.3
        oid_int = 0x0609608648016503040203
        OID = to_bytes_be(oid_int, 11)
        PHM = hashlib.sha512(M).digest()
    elif ph_name == "shake128":
        # 2.16.840.1.101.3.4.2.11
        oid_int = 0x060960864801650304020B
        OID = to_bytes_be(oid_int, 11)
        # SHAKE128(M, 256) → 256-bit (32-byte) output
        PHM = hashlib.shake_128(M).digest(32)
    elif ph_name == "shake256":
        # 2.16.840.1.101.3.4.2.12
        oid_int = 0x060960864801650304020C
        OID = to_bytes_be(oid_int, 11)
        # SHAKE256(M, 512) → 512-bit (64-byte) output
        PHM = hashlib.shake_256(M).digest(64)
    else:
        raise ValueError(f"Unsupported pre-hash function: {ph_name}")

    return OID, PHM


def hash_slh_sign(
    M: bytes,
    SK: SlhDsaPrivateKey,
    params: SlhDsaParams,
    ctx: bytes = b"",
    ph_name: PreHashName = "sha256",
    deterministic: bool = False,
    rng: Callable[[int], bytes] = _default_rng,
) -> SlhDsaSignature:
    """
    Algorithm 23 hash_slh_sign(M, ctx, PH, SK)

    Pre-hash SLH-DSA signing.

    - M        : message bytes
    - SK       : SLH-DSA private key
    - params   : SlhDsaParams
    - ctx      : context string (<= 255 bytes)
    - ph_name  : "sha256" | "sha512" | "shake128" | "shake256"
    - deterministic: use deterministic variant if True
    - rng      : RNG for hedged variant (addrnd)
    """
    if len(ctx) > 255:
        raise ValueError("hash_slh_sign: context string too long (> 255 bytes)")

    n = params.n

    if deterministic:
        addrnd = None
    else:
        addrnd = rng(n)
        if addrnd is None:
            raise RuntimeError("hash_slh_sign: RNG failed to produce addrnd")

    # Compute OID and pre-hash PHM according to PH
    OID, PHM = _compute_ph_and_oid(M, ph_name)

    # M′ = toByte(1, 1) ∥ toByte(|ctx|, 1) ∥ ctx ∥ OID ∥ PHM
    M_prime = bytes([1]) + bytes([len(ctx)]) + ctx + OID + PHM

    return slh_sign_internal(M_prime, SK, addrnd, params)


def hash_slh_verify(
    M: bytes,
    SIG: SlhDsaSignature,
    PK: SlhDsaPublicKey,
    params: SlhDsaParams,
    ctx: bytes = b"",
    ph_name: PreHashName = "sha256",
) -> bool:
    """
    Algorithm 25 hash_slh_verify(M, SIG, ctx, PH, PK)

    Pre-hash SLH-DSA verification.

    - M        : message bytes
    - SIG      : SLH-DSA signature
    - PK       : SLH-DSA public key
    - params   : SlhDsaParams
    - ctx      : context string (<= 255 bytes)
    - ph_name  : "sha256" | "sha512" | "shake128" | "shake256"
    """
    if len(ctx) > 255:
        return False

    OID, PHM = _compute_ph_and_oid(M, ph_name)

    # M′ = toByte(1, 1) ∥ toByte(|ctx|, 1) ∥ ctx ∥ OID ∥ PHM
    M_prime = bytes([1]) + bytes([len(ctx)]) + ctx + OID + PHM

    return slh_verify_internal(M_prime, SIG, PK, params)
