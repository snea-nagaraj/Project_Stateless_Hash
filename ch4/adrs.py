# slhdsa/adrs.py
"""
Section 4.2–4.3 – Addresses (ADRS) and member functions.

ADRS is a 32-byte structure divided into 4-byte words in big-endian order:

[0:4]   layer address
[4:16]  tree address (12 bytes)
[16:20] type  (0..6; see constants below)
[20:24] key pair address / padding
[24:28] chain address / tree height
[28:32] hash address / tree index

Member functions match Table 1 in Section 4.3.
"""

from __future__ import annotations

from dataclasses import dataclass

from .utils import to_int, to_bytes_be

# Address type constants (Section 4.2)
WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6

ADRS_LEN = 32  # bytes


@dataclass
class ADRS:
    """
    32-byte address structure for SLH-DSA, stored as a mutable bytearray.

    Layout (big-endian words, 4 bytes each):
      0: layer address           [0:4]
      1-3: tree address          [4:16]
      4: type                    [16:20]
      5: key pair address/pad    [20:24]
      6: chain address/height    [24:28]
      7: hash address/index      [28:32]
    """

    _buf: bytearray

    def __init__(self, value: bytes | None = None) -> None:
        if value is None:
            self._buf = bytearray(ADRS_LEN)
        else:
            if len(value) != ADRS_LEN:
                raise ValueError("ADRS must be exactly 32 bytes")
            self._buf = bytearray(value)

    # ---------------- Basic conversions ----------------

    def to_bytes(self) -> bytes:
        """Return the 32-byte address as immutable bytes."""
        return bytes(self._buf)

    @classmethod
    def from_bytes(cls, b: bytes) -> "ADRS":
        """Construct ADRS from a 32-byte sequence."""
        return cls(b)

    def copy(self) -> "ADRS":
        """Deep copy of the address."""
        return ADRS(bytes(self._buf))

    # ---------------- Internal helpers -----------------

    def _set_slice_u32(self, start: int, val: int) -> None:
        self._buf[start : start + 4] = to_bytes_be(val, 4)

    def _get_slice_u32(self, start: int) -> int:
        return to_int(bytes(self._buf[start : start + 4]))

    # ---------------- Member functions (Table 1) -------

    # ADRS.setLayerAddress(l)  : ADRS ← toByte(l, 4) ∥ ADRS[4:32]
    def set_layer_address(self, l: int) -> None:
        self._buf[0:4] = to_bytes_be(l, 4)

    # ADRS.setTreeAddress(t)   : ADRS ← ADRS[0:4] ∥ toByte(t, 12) ∥ ADRS[16:32]
    def set_tree_address(self, t: int) -> None:
        self._buf[4:16] = to_bytes_be(t, 12)

    # ADRS.setTypeAndClear(Y)  : ADRS ← ADRS[0:16] ∥ toByte(Y, 4) ∥ toByte(0, 12)
    def set_type_and_clear(self, Y: int) -> None:
        self._buf[16:20] = to_bytes_be(Y, 4)
        # final 12 bytes zero
        self._buf[20:32] = b"\x00" * 12

    # ADRS.setKeyPairAddress(i): ADRS ← ADRS[0:20] ∥ toByte(i, 4) ∥ ADRS[24:32]
    def set_key_pair_address(self, i: int) -> None:
        self._buf[20:24] = to_bytes_be(i, 4)

    # ADRS.setChainAddress(i) and ADRS.setTreeHeight(i)
    # ADRS ← ADRS[0:24] ∥ toByte(i, 4) ∥ ADRS[28:32]
    def set_chain_address(self, i: int) -> None:
        self._buf[24:28] = to_bytes_be(i, 4)

    def set_tree_height(self, i: int) -> None:
        self._buf[24:28] = to_bytes_be(i, 4)

    # ADRS.setHashAddress(i) and ADRS.setTreeIndex(i)
    # ADRS ← ADRS[0:28] ∥ toByte(i, 4)
    def set_hash_address(self, i: int) -> None:
        self._buf[28:32] = to_bytes_be(i, 4)

    def set_tree_index(self, i: int) -> None:
        self._buf[28:32] = to_bytes_be(i, 4)

    # ------------- Getter member functions -------------

    # i ← ADRS.getKeyPairAddress() : i ← toInt(ADRS[20:24], 4)
    def get_key_pair_address(self) -> int:
        return self._get_slice_u32(20)

    # i ← ADRS.getTreeIndex()      : i ← toInt(ADRS[28:32], 4)
    def get_tree_index(self) -> int:
        return self._get_slice_u32(28)

    # Convenience getters (not explicitly in Table 1, but useful)

    def get_layer_address(self) -> int:
        return self._get_slice_u32(0)

    def get_tree_address(self) -> int:
        """Return the 12-byte tree address as a big-endian integer."""
        return to_int(bytes(self._buf[4:16]))

    def get_type(self) -> int:
        return self._get_slice_u32(16)

    def get_chain_or_height(self) -> int:
        return self._get_slice_u32(24)

    def get_hash_or_index(self) -> int:
        return self._get_slice_u32(28)

    def __repr__(self) -> str:
        return f"ADRS({self._buf.hex()})"
