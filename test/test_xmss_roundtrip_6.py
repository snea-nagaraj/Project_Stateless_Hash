# test/test_xmss_roundtrip.py
#
# End-to-end XMSS test:
#   - compute XMSS root from seeds
#   - sign a message with leaf idx
#   - recompute root from (idx, SIGXMSS, M)
#   - check equality

from slhdsa.ch4.adrs import ADRS
from slhdsa.ch6.params import XmssParams
from slhdsa.ch6.xmss import xmss_root, xmss_sign, xmss_pk_from_sig


def main():
    # Choose n and tree height h′
    params = XmssParams(n=32, h_prime=3)  # 2^3 = 8 leaves

    SK_seed = b"\x11" * params.n
    PK_seed = b"\x22" * params.n

    # Base address: same layer/tree for entire XMSS tree
    base_adrs = ADRS()
    base_adrs.set_layer_address(0)
    base_adrs.set_tree_address(0)

    # 1) Compute XMSS root
    root = xmss_root(SK_seed, PK_seed, base_adrs.copy(), params)

    # 2) Sign a message with leaf idx
    idx = 2  # any in [0, 7]
    M = bytes(range(params.n))  # example message

    sig_xmss = xmss_sign(M, SK_seed, idx, PK_seed, base_adrs.copy(), params)

    # 3) Recompute root from signature
    root_from_sig = xmss_pk_from_sig(idx, sig_xmss, M, PK_seed, base_adrs.copy(), params)

    print("=== XMSS Roundtrip Test ===")
    print(f"n        = {params.n}")
    print(f"h_prime  = {params.h_prime}")
    print(f"root        = {root.hex()}")
    print(f"root_from_sig = {root_from_sig.hex()}")

    if root == root_from_sig:
        print("\nXMSS roundtrip OK: root == root_from_sig")
    else:
        print("\nXMSS roundtrip FAILED: root != root_from_sig")


if __name__ == "__main__":
    main()
