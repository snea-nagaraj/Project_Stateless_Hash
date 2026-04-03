# test/test_ch11_shake.py
#
# Tests for Section 11.1 SHAKE instantiations.
#
# For all SHAKE parameter sets we have:
#   Hmsg(R,PK.seed,PK.root,M) = SHAKE256(R || PK.seed || PK.root || M, 8m)
#   PRF(PK.seed,SK.seed,ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n)
#   PRFmsg(SK.prf,opt_rand,M) = SHAKE256(SK.prf || opt_rand || M, 8n)
#   F,H,Tl similarly with SHAKE256.

import hashlib

from slhdsa.ch4.adrs import ADRS
from slhdsa.ch11.hash_shake import (
    hmsg_shake,
    prf_shake,
    prf_msg_shake,
    F_shake,
    H_shake,
    T_l_shake,
)


def _build_adrs_sample() -> ADRS:
    ad = ADRS()
    ad.set_layer_address(1)
    ad.set_tree_address(987654321)
    ad.set_type_and_clear(2)
    ad.set_key_pair_address(9)
    ad.set_chain_address(3)
    ad.set_hash_address(7)
    return ad


def _test_shake_for_n(n: int, m: int):
    R = b"R" * n
    PK_seed = b"P" * n
    PK_root = b"Q" * n
    M = b"hello-SHAKE-" + bytes([n])

    SK_seed = b"S" * n
    SK_prf = b"K" * n

    ad = _build_adrs_sample()

    # ----- spec formulas -----

    hmsg_seed = R + PK_seed + PK_root + M
    hmsg_spec = hashlib.shake_256(hmsg_seed).digest(m)

    prf_spec = hashlib.shake_256(PK_seed + ad.to_bytes() + SK_seed).digest(n)

    opt_rand = b"RND" * 8
    prfmsg_spec = hashlib.shake_256(SK_prf + opt_rand + M).digest(n)

    M1 = b"A" * n
    f_spec = hashlib.shake_256(PK_seed + ad.to_bytes() + M1).digest(n)

    M2 = b"B" * (2 * n)
    h_spec = hashlib.shake_256(PK_seed + ad.to_bytes() + M2).digest(n)

    Ml = b"C" * (5 * n)
    tl_spec = hashlib.shake_256(PK_seed + ad.to_bytes() + Ml).digest(n)

    # ----- implementation under test -----

    hmsg_impl = hmsg_shake(R, PK_seed, PK_root, M, m)
    prf_impl = prf_shake(PK_seed, SK_seed, ad, n)
    prfmsg_impl = prf_msg_shake(SK_prf, opt_rand, M, n)
    f_impl = F_shake(PK_seed, ad, M1, n)
    h_impl = H_shake(PK_seed, ad, M2, n)
    tl_impl = T_l_shake(PK_seed, ad, Ml, n)

    assert hmsg_impl == hmsg_spec
    assert prf_impl == prf_spec
    assert prfmsg_impl == prfmsg_spec
    assert f_impl == f_spec
    assert h_impl == h_spec
    assert tl_impl == tl_spec


def main():
    print("=== Testing SHAKE Section 11.1 primitives ===")
    # n=16,24,32 ; choose m according to param sets (any positive works)
    _test_shake_for_n(16, m=30)
    _test_shake_for_n(24, m=39)
    _test_shake_for_n(32, m=47)
    print("all SHAKE primitive tests passed")


if __name__ == "__main__":
    main()
