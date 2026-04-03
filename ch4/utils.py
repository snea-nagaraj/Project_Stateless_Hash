# slhdsa/utils.py
"""
Section 4.4 – Arrays, Byte Strings, and Integers
Implements:
- Algorithm 2: toInt
- Algorithm 3: toByte
- Algorithm 4: base_2b
"""

from __future__ import annotations
from typing import List


def to_int(X: bytes) -> int:
    """
    Algorithm 2 toInt(X, n)
    Converts a byte string X of length n to an integer (big-endian).

    total ← 0
    for i from 0 to n − 1 do
        total ← 256 ⋅ total + X[i]
    return total
    """
    total = 0
    for b in X:
        total = 256 * total + b
    return total


def to_bytes_be(x: int, n: int) -> bytes:
    """
    Algorithm 3 toByte(x, n)
    Converts an integer x to a byte string of length n, big-endian.

    Raises ValueError if x does not fit in n bytes or x is negative.
    """
    if x < 0:
        raise ValueError("to_bytes_be: x must be non-negative")
    if x >= 1 << (8 * n):
        raise ValueError(f"to_bytes_be: x={x} does not fit into {n} bytes")

    total = x
    S = bytearray(n)
    # for i from 0 to n − 1:
    for i in range(n):
        # S[n − 1 − i] ← total mod 256
        S[n - 1 - i] = total % 256
        # total ← total ≫ 8
        total >>= 8
    return bytes(S)


def base_2b(X: bytes, b: int, out_len: int) -> List[int]:
    """
    Algorithm 4 base_2b(X, b, out_len)
    Computes the base 2^b representation of X.

    Input:
      - X: byte string of length at least ceil(out_len * b / 8)
      - b: integer bit-length of each "digit"
      - out_len: number of output digits

    Output:
      - list of out_len integers in [0, 2^b − 1]
    """
    if b <= 0:
        raise ValueError("base_2b: b must be positive")

    required_bits = out_len * b
    if len(X) * 8 < required_bits:
        raise ValueError(
            f"base_2b: input too short; need at least {required_bits} bits, got {len(X) * 8}"
        )

    baseb: List[int] = [0] * out_len
    in_idx = 0
    bits = 0
    total = 0

    # for out from 0 to out_len − 1:
    for out_pos in range(out_len):
        # while bits < b:
        while bits < b:
            # total ← (total ≪ 8) + X[in]
            total = (total << 8) + X[in_idx]
            in_idx += 1
            bits += 8

        # bits ← bits − b
        bits -= b
        # baseb[out] ← (total ≫ bits) mod 2^b
        baseb[out_pos] = (total >> bits) & ((1 << b) - 1)

    return baseb
