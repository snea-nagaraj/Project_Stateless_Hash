# test/test_ht_roundtrip.py
#
# End-to-end hypertree test:
#  - compute PK.root as the root of the top XMSS tree
#  - sign a message with ht_sign at layer 0
#  - verify with ht_verify
#

from slhdsa.ch4.adrs import ADRS
from slhdsa.ch6.xmss import xmss_root
from slhdsa.ch7.params import HypertreeParams
from slhdsa.ch7.hypertree import ht_sign, ht_verify


def main():
    # Hypertree parameters: n=32, d=3 layers, each XMSS tree height h′=2.
    params = HypertreeParams(n=32, d=3, h_prime=2)

    SK_seed = b"\x55" * params.n
    PK_seed = b"\x66" * params.n

    # Compute hypertree public key PK.root:
    # top layer is layer d-1, single XMSS tree with treeAddress = 0.
    adrs_top = ADRS()
    adrs_top.set_layer_address(params.d - 1)
    adrs_top.set_tree_address(0)
    PK_root = xmss_root(SK_seed, PK_seed, adrs_top, params.xmss)

    # Choose indices for the lowest-layer XMSS tree and leaf
    idxtree = 0  # index of XMSS tree at layer 0 (keep 0 for simplicity)
    idxleaf = 1  # index of WOTS leaf within that XMSS tree

    # Message to sign (in full SLH-DSA this will be a FORS pk)
    M = bytes(range(params.n))

    # 1) Hypertree sign
    sig_ht = ht_sign(M, SK_seed, PK_seed, idxtree, idxleaf, params)

    # 2) Hypertree verify
    ok = ht_verify(M, sig_ht, PK_seed, idxtree, idxleaf, PK_root, params)

    print("=== Hypertree Roundtrip Test ===")
    print(f"n        = {params.n}")
    print(f"d        = {params.d}")
    print(f"h_prime  = {params.h_prime}")
    print(f"PK_root  = {PK_root.hex()}")
    print(f"verify   = {ok}")

    if ok:
        print("\n Hypertree roundtrip OK: signature verifies against PK_root")
    else:
        print("\n Hypertree roundtrip FAILED")


if __name__ == "__main__":
    main()
