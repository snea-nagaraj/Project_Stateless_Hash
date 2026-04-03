# test/test_ch11_sha2.py
#
# Tests for Section 11.2 SHA2 instantiations:
# - compressed ADRS layout
# - Hmsg, PRF, PRFmsg, F, H, Tl for n = 16, 24, 32
#
# We re-implement the formulas from FIPS 205 directly in the test
# using hashlib/hmac and compare with slhdsa.ch11.hash_sha2.

import hashlib
import hmac

from slhdsa.ch4.adrs import ADRS
from slhdsa.ch11.hash_sha2 import (
    hmsg_sha2,
    prf_sha2,
    prf_msg_sha2,
    F_sha2,
    H_sha2,
    T_l_sha2,
    _compress_adrs,
)


# ---------- helpers used only in tests ----------

def mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    """MGF1 from RFC 8017, with SHA-256 or SHA-512."""
    if hash_name == "sha256":
        hfn = hashlib.sha256
        hlen = 32
    elif hash_name == "sha512":
        hfn = hashlib.sha512
        hlen = 64
    else:
        raise ValueError("unsupported hash_name")

    if length == 0:
        return b""

    out = bytearray()
    counter = 0
    while len(out) < length:
        C = counter.to_bytes(4, "big")
        out.extend(hfn(seed + C).digest())
        counter += 1

    return bytes(out[:length])


# ---------- tests ----------


def test_compress_adrs_layout():
    """
    Check ADRS^c = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
    using a synthetic ADRS whose bytes are 0..31.
    """
    raw = bytes(range(32))
    ad = ADRS(raw)
    c = _compress_adrs(ad)

    assert len(c) == 22
    # indices that should appear: 3, 8..15, 19, 20..31
    expected = bytes(
        [3]
        + list(range(8, 16))
        + [19]
        + list(range(20, 32))
    )
    assert c == expected


def _build_adrs_sample() -> ADRS:
    """Build a sample ADRS with some non-trivial values set."""
    ad = ADRS()
    ad.set_layer_address(3)
    ad.set_tree_address(123456789)
    ad.set_type_and_clear(2)  # e.g., TREE
    ad.set_key_pair_address(7)
    ad.set_chain_address(4)
    ad.set_hash_address(5)
    return ad


def _test_sha2_cat1(n: int = 16):
    """
    Category 1 (n = 16) – Section 11.2.1

    Hmsg:    MGF1-SHA-256
    PRF:     SHA-256 with 64-n zero padding
    PRFmsg:  HMAC-SHA-256
    F:       SHA-256 with 64-n zero padding
    H, Tl:   SHA-256 with 64-n zero padding
    """
    m = 30  # any digest length m <= 255 is fine for a test

    R = b"R" * n
    PK_seed = b"P" * n
    PK_root = b"Q" * n
    M = b"hello-SHA2-cat1"

    SK_seed = b"S" * n
    SK_prf = b"K" * n

    ad = _build_adrs_sample()
    adrsc = _compress_adrs(ad)

    # --- spec formulas (direct) ---

    # Hmsg(R, PK.seed, PK.root, M)
    inner = hashlib.sha256(R + PK_seed + PK_root + M).digest()
    hmsg_seed = R + PK_seed + inner
    hmsg_spec = mgf1(hmsg_seed, m, "sha256")

    # PRF(PK.seed, SK.seed, ADRS)
    pad = b"\x00" * (64 - n)
    prf_input = PK_seed + pad + adrsc + SK_seed
    prf_spec = hashlib.sha256(prf_input).digest()[:n]

    # PRFmsg(SK.prf, opt_rand, M)
    opt_rand = b"RND" * 8
    prfmsg_spec = hmac.new(SK_prf, opt_rand + M, hashlib.sha256).digest()[:n]

    # F(PK.seed, ADRS, M1)
    M1 = b"A" * n
    f_spec = hashlib.sha256(PK_seed + pad + adrsc + M1).digest()[:n]

    # H(PK.seed, ADRS, M2)
    M2 = b"B" * (2 * n)
    h_spec = hashlib.sha256(PK_seed + pad + adrsc + M2).digest()[:n]

    # Tl(PK.seed, ADRS, Ml)
    Ml = b"C" * (5 * n)
    tl_spec = hashlib.sha256(PK_seed + pad + adrsc + Ml).digest()[:n]

    # --- implementation under test ---

    hmsg_impl = hmsg_sha2(R, PK_seed, PK_root, M, m, n)
    prf_impl = prf_sha2(PK_seed, SK_seed, ad, n)
    prfmsg_impl = prf_msg_sha2(SK_prf, opt_rand, M, n)
    f_impl = F_sha2(PK_seed, ad, M1, n)
    h_impl = H_sha2(PK_seed, ad, M2, n)
    tl_impl = T_l_sha2(PK_seed, ad, Ml, n)

    assert hmsg_impl == hmsg_spec
    assert prf_impl == prf_spec
    assert prfmsg_impl == prfmsg_spec
    assert f_impl == f_spec
    assert h_impl == h_spec
    assert tl_impl == tl_spec


def _test_sha2_cat3_5(n: int):
    """
    Categories 3 & 5 (n = 24 or 32) – Section 11.2.2

    Hmsg:    MGF1-SHA-512
    PRF:     SHA-256 with 64-n zero padding   (same as cat1)
    PRFmsg:  HMAC-SHA-512
    F:       SHA-256 with 64-n zero padding   (same as cat1)
    H, Tl:   SHA-512 with 128-n zero padding
    """
    assert n in (24, 32)
    m = 47  # e.g., SLH-DSA-SHA2-256s uses m=47

    R = b"R" * n
    PK_seed = b"P" * n
    PK_root = b"Q" * n
    M = b"hello-SHA2-cat3-5"

    SK_seed = b"S" * n
    SK_prf = b"K" * n

    ad = _build_adrs_sample()
    adrsc = _compress_adrs(ad)

    # --- spec formulas (direct) ---

    # Hmsg
    inner = hashlib.sha512(R + PK_seed + PK_root + M).digest()
    hmsg_seed = R + PK_seed + inner
    hmsg_spec = mgf1(hmsg_seed, m, "sha512")

    # PRF, F: SHA-256 with pad 64-n
    pad256 = b"\x00" * (64 - n)

    prf_input = PK_seed + pad256 + adrsc + SK_seed
    prf_spec = hashlib.sha256(prf_input).digest()[:n]

    opt_rand = b"RND" * 8
    prfmsg_spec = hmac.new(SK_prf, opt_rand + M, hashlib.sha512).digest()[:n]

    M1 = b"A" * n
    f_spec = hashlib.sha256(PK_seed + pad256 + adrsc + M1).digest()[:n]

    # H, Tl: SHA-512 with pad 128-n
    pad512 = b"\x00" * (128 - n)

    M2 = b"B" * (2 * n)
    h_spec = hashlib.sha512(PK_seed + pad512 + adrsc + M2).digest()[:n]

    Ml = b"C" * (5 * n)
    tl_spec = hashlib.sha512(PK_seed + pad512 + adrsc + Ml).digest()[:n]

    # --- implementation under test ---

    hmsg_impl = hmsg_sha2(R, PK_seed, PK_root, M, m, n)
    prf_impl = prf_sha2(PK_seed, SK_seed, ad, n)
    prfmsg_impl = prf_msg_sha2(SK_prf, opt_rand, M, n)
    f_impl = F_sha2(PK_seed, ad, M1, n)
    h_impl = H_sha2(PK_seed, ad, M2, n)
    tl_impl = T_l_sha2(PK_seed, ad, Ml, n)

    assert hmsg_impl == hmsg_spec
    assert prf_impl == prf_spec
    assert prfmsg_impl == prfmsg_spec
    assert f_impl == f_spec
    assert h_impl == h_spec
    assert tl_impl == tl_spec


def main():
    print("=== Testing SHA2 Section 11.2 primitives ===")
    _test_sha2_cat1(16)
    _test_sha2_cat3_5(24)
    _test_sha2_cat3_5(32)
    print("all SHA2 primitive tests passed")


if __name__ == "__main__":
    main()
