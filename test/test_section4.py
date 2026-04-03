# SNEHA/test/test_section4.py
#
# Sanity checks for:
# - slhdsa.utils: to_int, to_bytes_be, base_2b
# - slhdsa.adrs : ADRS structure and member functions

from slhdsa.ch4.utils import to_int, to_bytes_be, base_2b
from slhdsa.ch4.adrs import (
    ADRS,
    WOTS_HASH,
    WOTS_PK,
    TREE,
    FORS_TREE,
    FORS_ROOTS,
    WOTS_PRF,
    FORS_PRF,
)


def test_utils():
    print("=== Testing utils (Section 4.4) ===")

    # ---- to_int / to_bytes_be round-trip ----
    b = b"\x01\x02\x03\x04"
    x = to_int(b)
    back = to_bytes_be(x, 4)

    print(f"Original bytes : {b.hex()}")
    print(f"Integer value  : {x}")
    print(f"Back to bytes  : {back.hex()}")

    assert back == b, "to_int/to_bytes_be round-trip failed"

    # ---- base_2b example ----
    X = b"\xff\x00"  # 11111111 00000000
    b_bits = 4
    out_len = 4
    digits = base_2b(X, b_bits, out_len)

    print(f"\nX              : {X.hex()}")
    print(f"b               = {b_bits}")
    print(f"out_len         = {out_len}")
    print(f"base_2b digits  = {digits}")

    # 1111 1111 0000 0000 → [15, 15, 0, 0]
    assert digits == [15, 15, 0, 0], "base_2b output mismatch"

    print("\nSneha utils tests passed\n")


def test_adrs():
    print("=== Testing ADRS (Section 4.2–4.3) ===")

    ad = ADRS()  # starts all-zero

    # Set layer and tree
    ad.set_layer_address(1)
    ad.set_tree_address(2)

    # Set type to WOTS_HASH and clear last 12 bytes
    ad.set_type_and_clear(WOTS_HASH)

    # Set key pair, chain, and hash components
    ad.set_key_pair_address(5)
    ad.set_chain_address(7)
    ad.set_hash_address(9)

    # Read back values
    layer = ad.get_layer_address()
    tree = ad.get_tree_address()
    addr_type = ad.get_type()
    keypair = ad.get_key_pair_address()
    chain_or_height = ad.get_chain_or_height()
    hash_or_index = ad.get_hash_or_index()
    tree_index = ad.get_tree_index()

    print(f"layer_address     : {layer}")
    print(f"tree_address      : {tree}")
    print(f"type              : {addr_type} (WOTS_HASH={WOTS_HASH})")
    print(f"key_pair_address  : {keypair}")
    print(f"chain/height      : {chain_or_height}")
    print(f"hash/index        : {hash_or_index}")
    print(f"tree_index        : {tree_index}")
    print(f"raw ADRS bytes    : {ad.to_bytes().hex()}")

    assert layer == 1
    assert tree == 2
    assert addr_type == WOTS_HASH
    assert keypair == 5
    assert chain_or_height == 7
    assert hash_or_index == 9
    assert tree_index == 9

    print("\nSNeha ADRS tests passed\n")


if __name__ == "__main__":
    test_utils()
    test_adrs()
    print("All Section 4 passed.")
