# test/test_slh_dsa_external.py
#
# Tests for Section 10 external SLH-DSA API:
#  - slh_keygen
#  - slh_sign / slh_verify (pure)
#  - hash_slh_sign / hash_slh_verify (pre-hash)

from slhdsa.ch9.params import SlhDsaParams
from slhdsa.ch10.api import (
    slh_keygen,
    slh_sign,
    slh_verify,
    hash_slh_sign,
    hash_slh_verify,
)


class DummyRng:
    """
    Deterministic RNG for testing: cycles a simple counter through bytes.
    """

    def __init__(self) -> None:
        self._ctr = 0

    def __call__(self, n: int) -> bytes:
        out = bytes((self._ctr + i) & 0xFF for i in range(n))
        self._ctr = (self._ctr + n) & 0xFF
        return out


def main():
    # Same toy parameter set used earlier
    params = SlhDsaParams(n=32, d=2, h_prime=3, k=3, a=4)

    rng = DummyRng()

    # Key generation
    SK, PK = slh_keygen(params, rng=rng)

    M = b"External API test message"
    ctx = b"ctx"

    # -------- Pure signing (hedged) --------
    SIG_pure = slh_sign(M, SK, params, ctx=ctx, deterministic=False, rng=rng)
    ok_pure = slh_verify(M, SIG_pure, PK, params, ctx=ctx)

    print("=== External SLH-DSA API Test ===")
    print(f"n        = {params.n}")
    print(f"d        = {params.d}")
    print(f"h_prime  = {params.h_prime}")
    print(f"h_total  = {params.h_total}")
    print(f"k, a     = {params.k}, {params.a}")
    print(f"PK_root  = {PK.PK_root.hex()}")
    print(f"pure verify         = {ok_pure}")

    # -------- Pure signing (deterministic) --------
    SIG_det1 = slh_sign(M, SK, params, ctx=ctx, deterministic=True)
    SIG_det2 = slh_sign(M, SK, params, ctx=ctx, deterministic=True)
    ok_det = slh_verify(M, SIG_det1, PK, params, ctx=ctx)

    print(f"deterministic verify = {ok_det}")
    print(f"deterministic equal  = {SIG_det1.R == SIG_det2.R and SIG_det1.sig_fors == SIG_det2.sig_fors}")

    # -------- Pre-hash signing (hash_slh_sign) --------
    SIG_ph = hash_slh_sign(M, SK, params, ctx=ctx, ph_name="sha256", deterministic=False, rng=rng)
    ok_ph = hash_slh_verify(M, SIG_ph, PK, params, ctx=ctx, ph_name="sha256")

    print(f"pre-hash verify      = {ok_ph}")

    if ok_pure and ok_det and ok_ph:
        print("\nExternal SLH-DSA API tests passed")
    else:
        print("\nExternal SLH-DSA API tests FAILED")


if __name__ == "__main__":
    main()
