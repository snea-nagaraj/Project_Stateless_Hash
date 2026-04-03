# slhdsa/ch8/fors.py
"""
Section 8 – Forest of Random Subsets (FORS).

Implements:
- Algorithm 14: fors_skGen
- Algorithm 15: fors_node
- Algorithm 16: fors_sign
- Algorithm 17: fors_pkFromSig
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from slhdsa.ch4.adrs import ADRS, FORS_TREE, FORS_ROOTS, FORS_PRF
from slhdsa.ch4.utils import base_2b
from slhdsa.ch4.hash_ifaces import F, H, prf, T_l
from slhdsa.ch8.params import ForsParams


@dataclass
class ForsSignature:
    """
    FORS signature = (k secret values, k authentication paths).

    - sk   : list of k n-byte secret values (one per tree)
    - auth : list of k authentication paths, each a list of a n-byte nodes
    """
    sk: List[bytes]
    auth: List[List[bytes]]


# ---------------------------------------------------------------------------
# Algorithm 14: fors_skGen
# ---------------------------------------------------------------------------

def fors_sk_gen(SK_seed: bytes, PK_seed: bytes, adrs: ADRS, idx: int, params: ForsParams) -> bytes:
    """
    Algorithm 14 fors_skGen(SK.seed, PK.seed, ADRS, idx)

    Generates a single n-byte FORS private-key value.

    - idx is the index of the secret value within the sets of FORS trees.
    """
    n = params.n

    # skADRS ← ADRS
    sk_adrs = adrs.copy()
    # setTypeAndClear(FORS_PRF)
    sk_adrs.set_type_and_clear(FORS_PRF)
    # preserve key pair address from original ADRS
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    # setTreeIndex(idx)
    sk_adrs.set_tree_index(idx)

    return prf(PK_seed, SK_seed, sk_adrs, n)


# ---------------------------------------------------------------------------
# Algorithm 15: fors_node
# ---------------------------------------------------------------------------

def fors_node(SK_seed: bytes, i: int, z: int, PK_seed: bytes, adrs: ADRS, params: ForsParams) -> bytes:
    """
    Algorithm 15 fors_node(SK.seed, i, z, PK.seed, ADRS)

    Computes the root of a Merkle subtree of FORS public values.

    - i : target node index at height z
    - z : target node height (0 ≤ z ≤ a)
    """
    n = params.n

    if z == 0:
        # Leaf node: hash of FORS secret value
        sk = fors_sk_gen(SK_seed, PK_seed, adrs, i, params)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i)
        node = F(PK_seed, adrs, sk, n)
    else:
        # Internal node: recurse on children then hash
        lnode = fors_node(SK_seed, 2 * i,     z - 1, PK_seed, adrs, params)
        rnode = fors_node(SK_seed, 2 * i + 1, z - 1, PK_seed, adrs, params)
        adrs.set_tree_height(z)
        adrs.set_tree_index(i)
        node = H(PK_seed, adrs, lnode + rnode, n)

    return node


# ---------------------------------------------------------------------------
# Algorithm 16: fors_sign
# ---------------------------------------------------------------------------

def fors_sign(md: bytes, SK_seed: bytes, PK_seed: bytes, adrs: ADRS, params: ForsParams) -> ForsSignature:
    """
    Algorithm 16 fors_sign(md, SK.seed, PK.seed, ADRS)

    Generates a FORS signature on a message digest md.

    - md  : ceil(k*a / 8) bytes; we use the first k*a bits.
    - ADRS: must be a FORS_TREE address identifying which XMSS/WOTS key signs this FORS key.
    """
    n = params.n
    k = params.k
    a = params.a
    t = params.t

    if len(md) < params.md_bytes:
        raise ValueError(f"md must be at least {params.md_bytes} bytes")

    # 2: indices ← base_2b(md, a, k)
    indices = base_2b(md, a, k)  # k integers in [0, t-1]

    sig_sk: List[bytes] = []
    sig_auth: List[List[bytes]] = []

    # For each tree i
    for i in range(k):
        # Global leaf index in forest: i * 2^a + indices[i]
        leaf_idx = i * t + indices[i]

        # 4: secret value
        sk_i = fors_sk_gen(SK_seed, PK_seed, adrs, leaf_idx, params)
        sig_sk.append(sk_i)

        # 5–9: authentication path of length a
        auth_path: List[bytes] = []
        for j in range(a):
            # s ← floor(indices[i] / 2^j) ⊕ 1
            s = (indices[i] >> j) ^ 1
            # AUTH[j] ← fors_node(SK.seed, i*2^{a-j} + s, j, PK.seed, ADRS)
            node_index = i * (t >> j) + s
            node = fors_node(SK_seed, node_index, j, PK_seed, adrs, params)
            auth_path.append(node)

        sig_auth.append(auth_path)

    return ForsSignature(sk=sig_sk, auth=sig_auth)


# ---------------------------------------------------------------------------
# Algorithm 17: fors_pkFromSig
# ---------------------------------------------------------------------------

def fors_pk_from_sig(sig_fors: ForsSignature, md: bytes, PK_seed: bytes, adrs: ADRS, params: ForsParams) -> bytes:
    """
    Algorithm 17 fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)

    Computes a FORS public key from a FORS signature and message digest.
    """
    n = params.n
    k = params.k
    a = params.a
    t = params.t

    if len(md) < params.md_bytes:
        raise ValueError(f"md must be at least {params.md_bytes} bytes")

    indices = base_2b(md, a, k)

    if len(sig_fors.sk) != k or len(sig_fors.auth) != k:
        raise ValueError("ForsSignature structure has wrong lengths")

    roots: List[bytes] = []

    # 2–20: compute root of each FORS tree
    for i in range(k):
        sk_i = sig_fors.sk[i]
        auth_i = sig_fors.auth[i]
        if len(auth_i) != a:
            raise ValueError(f"auth path for tree {i} has wrong length {len(auth_i)} != a={a}")

        # 4–6: compute leaf
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + indices[i])
        node = F(PK_seed, adrs, sk_i, n)

        # 8–18: compute root from leaf and AUTH
        for j in range(a):
            adrs.set_tree_height(j + 1)
            if ((indices[i] >> j) & 1) == 0:
                # even
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node = H(PK_seed, adrs, node + auth_i[j], n)
            else:
                # odd
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = H(PK_seed, adrs, auth_i[j] + node, n)

        roots.append(node)

    # 21–24: compress the k roots into the FORS public key using Tl (with ℓ = k)
    forspk_adrs = adrs.copy()
    forspk_adrs.set_type_and_clear(FORS_ROOTS)
    forspk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    M_l = b"".join(roots)  # k*n bytes
    pk = T_l(PK_seed, forspk_adrs, M_l, n)
    return pk
