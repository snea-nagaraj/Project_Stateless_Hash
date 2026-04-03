# test/test_slh_dsa_roundtrip.py
#
# End-to-end SLH-DSA test:
#  - generate key pair (given seeds)
#  - sign a message (hedged variant)
#  - verify the signature

from slhdsa.ch9.params import SlhDsaParams
from slhdsa.ch9.slh_dsa import (
    slh_keygen_internal,
    slh_sign_internal,
    slh_verify_internal,
)


def main():
    # Small toy parameter set (not necessarily one of NIST's official sets).
    # n = 32, d = 2 layers, each XMSS tree height h′ = 3 (h = 6),
    # FORS: k = 3 trees, height a = 4.
    params = SlhDsaParams(n=32, d=2, h_prime=3, k=3, a=4)

    SK_seed = b"\x01" * params.n
    SK_prf = b"\x02" * params.n
    PK_seed = b"\x03" * params.n

    # Key generation
    SK, PK = slh_keygen_internal(SK_seed, SK_prf, PK_seed, params)

    # Message to sign
    M = b"Hello SLH-DSA!"

    # Hedged variant: provide addrnd
    addrnd = b"\xAA" * params.n
    SIG = slh_sign_internal(M, SK, addrnd, params)

    ok = slh_verify_internal(M, SIG, PK, params)

    print("=== SLH-DSA Roundtrip Test ===")
    print(f"n        = {params.n}")
    print(f"d        = {params.d}")
    print(f"h_prime  = {params.h_prime}")
    print(f"h_total  = {params.h_total}")
    print(f"k, a     = {params.k}, {params.a}")
    print(f"PK_root  = {PK.PK_root.hex()}")
    print(f"verify   = {ok}")

    if ok:
        print("\nSLH-DSA roundtrip OK: signature verifies")
    else:
        print("\n SLH-DSA roundtrip FAILED")


if __name__ == "__main__":
    main()
