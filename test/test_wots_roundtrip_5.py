from slhdsa.ch4.adrs import ADRS, WOTS_HASH
from slhdsa.ch5.params import WotsParams
from slhdsa.ch5.wots import wots_pkgen, wots_sign, wots_pk_from_sig


def main():
    # Try all three n values once each
    for n in (16, 24, 32):
        params = WotsParams(n=n)

        SK_seed = b"\x11" * n
        PK_seed = b"\x22" * n

        ad = ADRS()
        ad.set_layer_address(0)
        ad.set_tree_address(0)
        ad.set_type_and_clear(WOTS_HASH)
        ad.set_key_pair_address(5)

        M = bytes(range(n))  # 00 01 02 ... (n-1)

        print(f"\n=== WOTS+ Roundtrip (n={n}) ===")

        pk = wots_pkgen(SK_seed, PK_seed, ad.copy(), params)
        sig = wots_sign(M, SK_seed, PK_seed, ad.copy(), params)
        pksig = wots_pk_from_sig(sig, M, PK_seed, ad.copy(), params)

        print(f"pk    = {pk.hex()}")
        print(f"pksig = {pksig.hex()}")

        assert pk == pksig, f"WOTS roundtrip failed for n={n}"
        print("OK")

if __name__ == "__main__":
    main()
