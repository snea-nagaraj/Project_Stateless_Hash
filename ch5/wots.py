# slhdsa/wots.py
"""
Section 5 – Winternitz One-Time Signature Plus (WOTS+) for SLH-DSA.

Implements:
- Algorithm 5: chain
- Algorithm 6: wots_pkGen
- Algorithm 7: wots_sign
- Algorithm 8: wots_pkFromSig

These are generic in n, assuming lgw = 4 (as in FIPS 205).
"""

from __future__ import annotations

from typing import List

from slhdsa.ch4.adrs import ADRS, WOTS_HASH, WOTS_PK, WOTS_PRF
from slhdsa.ch5.params import WotsParams
from slhdsa.ch4.utils import base_2b, to_bytes_be
from slhdsa.ch4.hash_ifaces import F, prf, T_l


# -------------------------------------------------------------------
# Algorithm 5: chain
# -------------------------------------------------------------------

def chain(X: bytes, i: int, s: int, PK_seed: bytes, adrs: ADRS, n: int) -> bytes:
    """
    Algorithm 5 chain(X, i, s, PK.seed, ADRS)
    Chaining function used in WOTS+.

    Input:
        X       : n-byte input string
        i       : start index (0 <= i < w)
        s       : number of steps (i + s < w)
        PK_seed : public seed
        adrs    : address (type must be WOTS_HASH)
        n       : security parameter (bytes)

    Output:
        n-byte result of iterating F s times on X starting at index i.
    """
    tmp = X
    for j in range(i, i + s):
        adrs.set_hash_address(j)
        tmp = F(PK_seed, adrs, tmp, n)
    return tmp


# -------------------------------------------------------------------
# WOTS+ Public-Key Generation (Algorithm 6)
# -------------------------------------------------------------------

def wots_pkgen(SK_seed: bytes, PK_seed: bytes, adrs: ADRS, params: WotsParams) -> bytes:
    """
    Algorithm 6 wots_pkGen(SK.seed, PK.seed, ADRS)

    Generates a WOTS+ public key.

    Input:
        SK_seed : n-byte secret seed
        PK_seed : n-byte public seed
        adrs    : address; must have type = WOTS_HASH and correct layer/tree/keypair
        params  : WotsParams(n, lgw=4)

    Output:
        WOTS+ public key pk (n bytes)
    """
    n = params.n
    w = params.w
    length = params.length

    # 1–3: skADRS ← ADRS; set type to WOTS_PRF; copy keypair address
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    # tmp holds len public values (each n bytes)
    tmp: List[bytes] = [b"\x00" * n for _ in range(length)]

    # 4–9: generate public values
    for i in range(length):
        # 5: skADRS.setChainAddress(i)
        sk_adrs.set_chain_address(i)
        # 6: sk ← PRF(PK.seed, SK.seed, skADRS)
        sk_i = prf(PK_seed, SK_seed, sk_adrs, n)
        # 7: ADRS.setChainAddress(i)
        adrs.set_chain_address(i)
        # 8: tmp[i] ← chain(sk, 0, w − 1, PK.seed, ADRS)
        tmp[i] = chain(sk_i, 0, w - 1, PK_seed, adrs, n)

    # 10–13: compress public key with T_len
    wotspk_adrs = adrs.copy()
    wotspk_adrs.set_type_and_clear(WOTS_PK)
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    # Concatenate tmp[0]||...||tmp[len-1] for T_l
    M_l = b"".join(tmp)
    pk = T_l(PK_seed, wotspk_adrs, M_l, n)

    return pk


# -------------------------------------------------------------------
# WOTS+ Signature Generation (Algorithm 7)
# -------------------------------------------------------------------

def _wots_compute_msg_digits(M: bytes, params: WotsParams) -> List[int]:
    """
    Internal helper: compute base-w digits for message + checksum (Algorithm 7).

    Returns:
        msg_digits: list of length params.length with values in [0, w-1]
    """
    n = params.n
    lgw = params.lgw
    w = params.w
    len1 = params.len1
    len2 = params.len2

    if len(M) != n:
        raise ValueError(f"WOTS sign expects message of length n={n}, got {len(M)}")

    # 2: msg ← base_2b(M, lgw, len1)
    msg = base_2b(M, lgw, len1)

    # 3–5: compute checksum
    csum = 0
    for i in range(len1):
        csum += w - 1 - msg[i]

    # 6: csum ← csum << ((8 − ((len2⋅lgw) mod 8)) mod 8)
    shift = (8 - ((len2 * lgw) % 8)) % 8
    csum <<= shift

    # 7: append base-w digits of checksum
    #    msg ← msg ∥ base_2b(toByte(csum, ceil(len2⋅lgw / 8)), lgw, len2)
    csum_bytes_len = (len2 * lgw + 7) // 8  # ceil(len2*lgw / 8)
    csum_bytes = to_bytes_be(csum, csum_bytes_len)
    csum_digits = base_2b(csum_bytes, lgw, len2)

    msg.extend(csum_digits)  # now msg has length len1 + len2 = len
    return msg


def wots_sign(M: bytes, SK_seed: bytes, PK_seed: bytes, adrs: ADRS, params: WotsParams) -> List[bytes]:
    """
    Algorithm 7 wots_sign(M, SK.seed, PK.seed, ADRS)

    Generates a WOTS+ signature on an n-byte message.

    Input:
        M       : n-byte message
        SK_seed : n-byte secret seed
        PK_seed : n-byte public seed
        adrs    : address; type must be WOTS_HASH with correct layer/tree/keypair
        params  : WotsParams

    Output:
        sig: list of `len` byte-strings, each of length n
    """
    n = params.n
    length = params.length
    w = params.w

    # 1–7: get message+checksum digits
    msg_digits = _wots_compute_msg_digits(M, params)
    assert len(msg_digits) == length

    # 8–10: skADRS
    sk_adrs = adrs.copy()
    sk_adrs.set_type_and_clear(WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    sig: List[bytes] = [b"\x00" * n for _ in range(length)]

    # 11–16: compute signature elements
    for i in range(length):
        # 12: skADRS.setChainAddress(i)
        sk_adrs.set_chain_address(i)
        # 13: sk ← PRF(PK.seed, SK.seed, skADRS)
        sk_i = prf(PK_seed, SK_seed, sk_adrs, n)
        # 14: ADRS.setChainAddress(i)
        adrs.set_chain_address(i)
        # 15: sig[i] ← chain(sk, 0, msg[i], PK.seed, ADRS)
        steps = msg_digits[i]
        if steps > w - 1:
            raise ValueError("msg digit out of range for w")
        sig[i] = chain(sk_i, 0, steps, PK_seed, adrs, n)

    return sig


# -------------------------------------------------------------------
# WOTS+ Public Key from Signature (Algorithm 8)
# -------------------------------------------------------------------

def wots_pk_from_sig(sig: List[bytes], M: bytes, PK_seed: bytes, adrs: ADRS, params: WotsParams) -> bytes:
    """
    Algorithm 8 wots_pkFromSig(sig, M, PK.seed, ADRS)

    Computes a WOTS+ public key from a message and its signature.

    Input:
        sig     : list of `len` n-byte strings
        M       : n-byte message
        PK_seed : n-byte public seed
        adrs    : address; type must be WOTS_HASH
        params  : WotsParams

    Output:
        pksig: n-byte WOTS+ public key derived from sig
    """
    n = params.n
    w = params.w
    length = params.length

    if len(sig) != length:
        raise ValueError(f"Expected sig length {length}, got {len(sig)}")

    for i, s in enumerate(sig):
        if len(s) != n:
            raise ValueError(f"sig[{i}] length {len(s)} != n={n}")

    # 1–7: message+checksum digits (same as wots_sign)
    msg_digits = _wots_compute_msg_digits(M, params)

    # 8–11: chain from sig[i] to end of chain
    tmp: List[bytes] = [b"\x00" * n for _ in range(length)]
    for i in range(length):
        adrs.set_chain_address(i)
        start = msg_digits[i]
        steps = (w - 1) - msg_digits[i]
        if start + steps > w - 1:
            raise ValueError("Invalid msg digit; would exceed chain length")
        tmp[i] = chain(sig[i], start, steps, PK_seed, adrs, n)

    # 12–15: compress to get pksig
    wotspk_adrs = adrs.copy()
    wotspk_adrs.set_type_and_clear(WOTS_PK)
    wotspk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    M_l = b"".join(tmp)
    pksig = T_l(PK_seed, wotspk_adrs, M_l, n)
    return pksig
