# slhdsa/ch7/hypertree.py
"""
Section 7 – SLH-DSA Hypertree.

Implements:
- Algorithm 12: ht_sign   (hypertree signature generation)
- Algorithm 13: ht_verify (hypertree signature verification)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from slhdsa.ch4.adrs import ADRS
from slhdsa.ch6.xmss import XmssSignature, xmss_sign, xmss_pk_from_sig
from slhdsa.ch7.params import HypertreeParams


@dataclass
class HypertreeSignature:
    """
    Hypertree signature = sequence of d XMSS signatures.

    signatures[j] is the XMSS signature at layer j, for j = 0..d-1.
    """
    signatures: List[XmssSignature]

    def get_xmss_signature(self, j: int) -> XmssSignature:
        return self.signatures[j]


# ---------------------------------------------------------------------------
# Algorithm 12: ht_sign
# ---------------------------------------------------------------------------

def ht_sign(M: bytes,
            SK_seed: bytes,
            PK_seed: bytes,
            idxtree: int,
            idxleaf: int,
            params: HypertreeParams) -> HypertreeSignature:
    """
    Algorithm 12 ht_sign(M, SK.seed, PK.seed, idxtree, idxleaf)

    Generates a hypertree signature.

    - M       : n-byte message (in SLH-DSA: FORS public key)
    - SK_seed : secret seed
    - PK_seed : public seed
    - idxtree : index of XMSS tree at lowest layer that signs M
    - idxleaf : index of WOTS+ key in that XMSS tree
    """
    d = params.d
    h_prime = params.h_prime
    xmss_params = params.xmss

    # 1: ADRS ← toByte(0, 32)
    adrs = ADRS()  # constructor already gives 32 zero bytes

    # 2: ADRS.setTreeAddress(idxtree)
    adrs.set_tree_address(idxtree)

    signatures: List[XmssSignature] = []

    # 3: SIGtmp ← xmss_sign(M, SK.seed, idxleaf, PK.seed, ADRS)
    sigtmp = xmss_sign(M, SK_seed, idxleaf, PK_seed, adrs.copy(), xmss_params)
    # 4: SIGHT ← SIGtmp
    signatures.append(sigtmp)
    # 5: root ← xmss_pkFromSig(idxleaf, SIGtmp, M, PK.seed, ADRS)
    root = xmss_pk_from_sig(idxleaf, sigtmp, M, PK_seed, adrs.copy(), xmss_params)

    # 6–16: for j from 1 to d−1
    for j in range(1, d):
        # 7: idxleaf ← idxtree mod 2^h′
        idxleaf = idxtree % (1 << h_prime)
        # 8: idxtree ← idxtree >> h′
        idxtree >>= h_prime
        # 9: ADRS.setLayerAddress(j)
        adrs.set_layer_address(j)
        # 10: ADRS.setTreeAddress(idxtree)
        adrs.set_tree_address(idxtree)
        # 11: SIGtmp ← xmss_sign(root, SK.seed, idxleaf, PK.seed, ADRS)
        sigtmp = xmss_sign(root, SK_seed, idxleaf, PK_seed, adrs.copy(), xmss_params)
        # 12: SIGHT ← SIGHT ∥ SIGtmp
        signatures.append(sigtmp)
        # 13–15: if j < d−1 then root ← xmss_pkFromSig(...)
        if j < d - 1:
            root = xmss_pk_from_sig(idxleaf, sigtmp, root, PK_seed, adrs.copy(), xmss_params)

    return HypertreeSignature(signatures=signatures)


# ---------------------------------------------------------------------------
# Algorithm 13: ht_verify
# ---------------------------------------------------------------------------

def ht_verify(M: bytes,
              sig_ht: HypertreeSignature,
              PK_seed: bytes,
              idxtree: int,
              idxleaf: int,
              PK_root: bytes,
              params: HypertreeParams) -> bool:
    """
    Algorithm 13 ht_verify(M, SIGHT, PK.seed, idxtree, idxleaf, PK.root)

    Verifies a hypertree signature.

    Returns True iff the signature is valid for message M and hypertree public key PK_root.
    """
    d = params.d
    h_prime = params.h_prime
    xmss_params = params.xmss

    # 1: ADRS ← toByte(0, 32)
    adrs = ADRS()
    # 2: ADRS.setTreeAddress(idxtree)
    adrs.set_tree_address(idxtree)

    # 3: SIGtmp ← SIGHT.getXMSSSignature(0)
    sigtmp = sig_ht.get_xmss_signature(0)
    # 4: node ← xmss_pkFromSig(idxleaf, SIGtmp, M, PK.seed, ADRS)
    node = xmss_pk_from_sig(idxleaf, sigtmp, M, PK_seed, adrs.copy(), xmss_params)

    # 5–12: for j from 1 to d−1
    for j in range(1, d):
        # 6: idxleaf ← idxtree mod 2^h′
        idxleaf = idxtree % (1 << h_prime)
        # 7: idxtree ← idxtree >> h′
        idxtree >>= h_prime
        # 8: ADRS.setLayerAddress(j)
        adrs.set_layer_address(j)
        # 9: ADRS.setTreeAddress(idxtree)
        adrs.set_tree_address(idxtree)
        # 10: SIGtmp ← SIGHT.getXMSSSignature(j)
        sigtmp = sig_ht.get_xmss_signature(j)
        # 11: node ← xmss_pkFromSig(idxleaf, SIGtmp, node, PK.seed, ADRS)
        node = xmss_pk_from_sig(idxleaf, sigtmp, node, PK_seed, adrs.copy(), xmss_params)

    # 13–16: compare with PK.root
    return node == PK_root
