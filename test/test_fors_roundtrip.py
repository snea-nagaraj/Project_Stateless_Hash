# test/test_fors_roundtrip.py
#
# End-to-end FORS test:
#  - compute FORS public key from seeds (by building all k trees)
#  - sign a message digest
#  - recompute public key from signature
#  - check equality

from slhdsa.ch4.adrs import ADRS, FORS_TREE
from slhdsa.ch4.hash_ifaces import T_l
from slhdsa.ch8.params import ForsParams
from slhdsa.ch8.fors import ForsSignature, fors_sign, fors_pk_from_sig, fors_node


def compute_fors_pk_from_seeds(SK_seed: bytes, PK_seed: bytes, base_adrs: ADRS, params: ForsParams) -> bytes:
    """
    Helper: compute true FORS public key directly from seeds,
    by computing the root of each tree via fors_node and compressing.
    """
    n = params.n
    k = params.k
    a = params.a

    roots = []
    for i in range(k):
        adrs_i = base_adrs.copy()
        # Top of tree i: height = a, index = i
        root_i = fors_node(SK_seed, i, a, PK_seed, adrs_i, params)
        roots.append(root_i)

    forspk_adrs = base_adrs.copy()
    forspk_adrs.set_type_and_clear(FORS_TREE)  # will be overwritten below anyway
    forspk_adrs.set_type_and_clear(0)  # clear type; we'll set FORS_ROOTS via fors_pk_from_sig helper
    # But we just use T_l here with same layout as fors_pk_from_sig
    from slhdsa.ch4.adrs import FORS_ROOTS
    forspk_adrs.set_type_and_clear(FORS_ROOTS)
    forspk_adrs.set_key_pair_address(base_adrs.get_key_pair_address())

    M_l = b"".join(roots)
    pk = T_l(PK_seed, forspk_adrs, M_l, n)
    return pk


def main():
    # Small test parameters (not necessarily one of NIST's official sets,
    # but structurally correct): n=32, k=3 trees, height a=4 (t=16 leaves/tree).
    params = ForsParams(n=32, k=3, a=4)

    SK_seed = b"\x33" * params.n
    PK_seed = b"\x44" * params.n

    # Base FORS address: layer 0, some XMSS tree addr, some keypair index
    base_adrs = ADRS()
    base_adrs.set_layer_address(0)
    base_adrs.set_tree_address(0)
    base_adrs.set_type_and_clear(FORS_TREE)
    base_adrs.set_key_pair_address(7)  # arbitrary WOTS key index that signs this FORS key

    # Message digest: needs at least md_bytes bytes
    md = bytes(range(params.md_bytes))

    # 1) Compute FORS pk directly from seeds
    pk_true = compute_fors_pk_from_seeds(SK_seed, PK_seed, base_adrs.copy(), params)

    # 2) Sign digest
    sig = fors_sign(md, SK_seed, PK_seed, base_adrs.copy(), params)

    # 3) Recompute pk from signature
    pk_from_sig = fors_pk_from_sig(sig, md, PK_seed, base_adrs.copy(), params)

    print("=== FORS Roundtrip Test ===")
    print(f"n        = {params.n}")
    print(f"k        = {params.k}")
    print(f"a        = {params.a}")
    print(f"md_bytes = {params.md_bytes}")
    print(f"pk_true      = {pk_true.hex()}")
    print(f"pk_from_sig  = {pk_from_sig.hex()}")

    if pk_true == pk_from_sig:
        print("\nFORS roundtrip OK: pk_true == pk_from_sig")
    else:
        print("\nFORS roundtrip FAILED: pk_true != pk_from_sig")


if __name__ == "__main__":
    main()
