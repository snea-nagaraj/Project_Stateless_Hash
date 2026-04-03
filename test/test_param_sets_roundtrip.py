# test/test_param_sets_roundtrip.py

from slhdsa.ch11 import ALL_PARAM_SETS
from slhdsa.ch4 import hash_ifaces
from slhdsa.ch10.api import slh_keygen, slh_sign, slh_verify


def main():
    print("=== SLH-DSA FIPS ParamSet Roundtrip Test ===")
    for ps in ALL_PARAM_SETS:
        # 1) Select correct hash family for this param set ("shake" or "sha2")
        hash_ifaces.set_hash_family(ps.hash_family)

        # 2) Build internal parameter object
        params = ps.to_params()

        # 3) Key generation
        SK, PK = slh_keygen(params)

        # 4) Message + optional context
        M = f"param set: {ps.name}".encode("ascii")
        ctx = b""  # or some non-empty context if you want

        # NOTE: order is (M, SK, params, ctx)
        SIG = slh_sign(M, SK, params, ctx)

        # And verify has the analogous order (M, SIG, PK, params, ctx)
        ok = slh_verify(M, SIG, PK, params, ctx)

        print(f"{ps.name:24s}  n={ps.n:2d}  h={ps.h:2d}  d={ps.d:2d}  ok={ok}")


if __name__ == "__main__":
    main()
