# slhdsa/ch6/xmss.py
"""
Section 6 – eXtended Merkle Signature Scheme (XMSS).

Implements:
- Algorithm 9: xmss_node   (Merkle subtree root)
- Convenience: xmss_root   (full tree root, i = 0, z = h′)
- Algorithm 10: xmss_sign  (XMSS signature generation)
- Algorithm 11: xmss_pk_from_sig (XMSS public key from signature)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from slhdsa.ch4.adrs import ADRS, WOTS_HASH, TREE
from slhdsa.ch4.hash_ifaces import H
from slhdsa.ch5.wots import wots_pkgen, wots_sign, wots_pk_from_sig
from slhdsa.ch6.params import XmssParams


# ---------------------------------------------------------------------------
# XMSS signature container (matches SIGXMSS = sig || AUTH conceptually)
# ---------------------------------------------------------------------------

@dataclass
class XmssSignature:
    """
    XMSS signature = (WOTS+ sig, AUTH).

    - sig  : WOTS+ signature as list of `len` n-byte strings
    - auth : authentication path as list of h′ n-byte nodes
    """
    sig: List[bytes]
    auth: List[bytes]


# ---------------------------------------------------------------------------
# Algorithm 9: xmss_node
# ---------------------------------------------------------------------------

def xmss_node(SK_seed: bytes, i: int, z: int, PK_seed: bytes, adrs: ADRS, params: XmssParams) -> bytes:
    """
    Algorithm 9 xmss_node(SK.seed, i, z, PK.seed, ADRS)

    Computes the root of a Merkle subtree of WOTS+ public keys.

    - SK_seed : secret seed
    - i       : target node index at height z
    - z       : target node height (0 ≤ z ≤ h′)
    - PK_seed : public seed
    - adrs    : address with correct layer & tree address
    - params  : XmssParams (contains n and WOTS params)
    """
    n = params.n
    wots_params = params.wots

    if z == 0:
        # Lines 2–4: leaf – WOTS+ public key
        adrs.set_type_and_clear(WOTS_HASH)
        adrs.set_key_pair_address(i)
        node = wots_pkgen(SK_seed, PK_seed, adrs, wots_params)
    else:
        # Lines 6–7: compute children
        lnode = xmss_node(SK_seed, 2 * i,     z - 1, PK_seed, adrs, params)
        rnode = xmss_node(SK_seed, 2 * i + 1, z - 1, PK_seed, adrs, params)

        # Lines 8–11: hash kids into parent
        adrs.set_type_and_clear(TREE)
        adrs.set_tree_height(z)
        adrs.set_tree_index(i)
        node = H(PK_seed, adrs, lnode + rnode, n)

    return node


def xmss_root(SK_seed: bytes, PK_seed: bytes, adrs: ADRS, params: XmssParams) -> bytes:
    """
    Convenience wrapper: compute full XMSS tree root.

    Equivalent to xmss_node(SK_seed, 0, h′, PK_seed, ADRS).
    """
    return xmss_node(SK_seed, 0, params.h_prime, PK_seed, adrs, params)


# ---------------------------------------------------------------------------
# Algorithm 10: xmss_sign
# ---------------------------------------------------------------------------

def xmss_sign(M: bytes, SK_seed: bytes, idx: int, PK_seed: bytes, adrs: ADRS, params: XmssParams) -> XmssSignature:
    """
    Algorithm 10 xmss_sign(M, SK.seed, idx, PK.seed, ADRS)

    Generates an XMSS signature on an n-byte message M.

    Input:
      - M       : message (n bytes)
      - SK_seed : secret seed
      - idx     : index of WOTS+ key (leaf) to use in [0, 2^h′ - 1]
      - PK_seed : public seed
      - adrs    : address with correct layer & tree address
      - params  : XmssParams

    Output:
      XmssSignature(sig, auth)
    """
    n = params.n
    h_prime = params.h_prime
    wots_params = params.wots

    if len(M) != n:
        raise ValueError(f"XMSS sign expects message of length n={n}, got {len(M)}")

    # 1–4: build authentication path AUTH[0..h′-1]
    auth: List[bytes] = []
    auth_adrs = adrs.copy()
    for j in range(h_prime):
        # k ← floor(idx / 2^j) ⊕ 1
        k = (idx >> j) ^ 1
        # AUTH[j] ← xmss_node(SK.seed, k, j, PK.seed, ADRS)
        node = xmss_node(SK_seed, k, j, PK_seed, auth_adrs, params)
        auth.append(node)

    # 5–7: WOTS signature with idx-th key
    wots_adrs = adrs.copy()
    wots_adrs.set_type_and_clear(WOTS_HASH)
    wots_adrs.set_key_pair_address(idx)
    sig = wots_sign(M, SK_seed, PK_seed, wots_adrs, wots_params)

    return XmssSignature(sig=sig, auth=auth)


# ---------------------------------------------------------------------------
# Algorithm 11: xmss_pk_from_sig
# ---------------------------------------------------------------------------

def xmss_pk_from_sig(idx: int, sig_xmss: XmssSignature, M: bytes, PK_seed: bytes, adrs: ADRS, params: XmssParams) -> bytes:
    """
    Algorithm 11 xmss_pkFromSig(idx, SIGXMSS, M, PK.seed, ADRS)

    Computes an XMSS public key (root) from an XMSS signature.

    Input:
      - idx      : index of WOTS+ key (leaf) used to sign
      - sig_xmss : XmssSignature(sig, auth)
      - M        : message (n bytes)
      - PK_seed  : public seed
      - adrs     : address with correct layer & tree address
      - params   : XmssParams

    Output:
      n-byte root value node[0]
    """
    n = params.n
    h_prime = params.h_prime
    wots_params = params.wots

    sig = sig_xmss.sig
    AUTH = sig_xmss.auth

    if len(AUTH) != h_prime:
        raise ValueError(f"AUTH length {len(AUTH)} != h_prime={h_prime}")

    # 1–5: compute WOTS+ pk from WOTS+ sig
    wots_adrs = adrs.copy()
    wots_adrs.set_type_and_clear(WOTS_HASH)
    wots_adrs.set_key_pair_address(idx)
    node0 = wots_pk_from_sig(sig, M, PK_seed, wots_adrs, wots_params)

    # 6: ADRS.setTypeAndClear(TREE)
    tree_adrs = adrs.copy()
    tree_adrs.set_type_and_clear(TREE)
    tree_adrs.set_tree_index(idx)

    node = node0
    # 8–18: climb the tree using AUTH
    for k in range(h_prime):
        tree_adrs.set_tree_height(k + 1)

        if ((idx >> k) & 1) == 0:
            # if floor(idx / 2^k) is even
            tree_adrs.set_tree_index(tree_adrs.get_tree_index() // 2)
            node = H(PK_seed, tree_adrs, node + AUTH[k], n)
        else:
            # odd
            tree_adrs.set_tree_index((tree_adrs.get_tree_index() - 1) // 2)
            node = H(PK_seed, tree_adrs, AUTH[k] + node, n)

    return node
