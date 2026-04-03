# test/test_wots_msg_digits.py

from slhdsa.ch5.params import WotsParams
from slhdsa.ch5.wots import _wots_compute_msg_digits

def main():
    params = WotsParams(n=32)  # for example; any n = 16,24,32 works
    M = bytes(range(params.n))  # 0x00, 0x01, ..., 0x1f

    digits = _wots_compute_msg_digits(M, params)
    print(f"n          = {params.n}")
    print(f"w          = {params.w}")
    print(f"len1, len2 = {params.len1}, {params.len2}")
    print(f"len        = {params.length}")
    print(f"#digits    = {len(digits)}")
    print(f"First 10 digits: {digits[:10]}")

if __name__ == "__main__":
    main()
