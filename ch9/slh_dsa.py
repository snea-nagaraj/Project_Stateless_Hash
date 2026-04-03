# slhdsa/ch9/slh_dsa.py
"""
SLH-DSA internal functions (Section 9):

- Algorithm 18: slh_keygen_internal
- Algorithm 19: slh_sign_internal
- Algorithm 20: slh_verify_internal
"""

from __future__ import annotations

from dataclasses import dataclass

from slhdsa.ch4.adrs import ADRS, FORS_TREE
from slhdsa.ch4.utils import to_int
from slhdsa.ch4.hash_ifaces import prf_msg, h_msg
from slhdsa.ch6.xmss import xmss_root
from slhdsa.ch7.hypertree import HypertreeSignature, ht_sign, ht_verify
from slhdsa.ch8.fors import ForsSignature, fors_sign, fors_pk_from_sig
from slhdsa.ch9.params import SlhDsaParams


# ---------------------------------------------------------------------------
# Key and signature data structures
# ---------------------------------------------------------------------------


@dataclass
class SlhDsaPrivateKey:
    SK_seed: bytes
    SK_prf: bytes
    PK_seed: bytes
    PK_root: bytes  # hypertree root


@dataclass
class SlhDsaPublicKey:
    PK_seed: bytes
    PK_root: bytes  # hypertree root


@dataclass
class SlhDsaSignature:
    """
    Structured SLH-DSA signature:

    - R       : n-byte randomizer
    - sig_fors: FORS signature
    - sig_ht  : hypertree signature
    """
    R: bytes
    sig_fors: ForsSignature
    sig_ht: HypertreeSignature


# ---------------------------------------------------------------------------
# Algorithm 18: slh_keygen_internal
# ---------------------------------------------------------------------------


def slh_keygen_internal(SK_seed: bytes,
                        SK_prf: bytes,
                        PK_seed: bytes,
                        params: SlhDsaParams) -> tuple[SlhDsaPrivateKey, SlhDsaPublicKey]:
    """
    Algorithm 18 slh_keygen_internal(SK.seed, SK.prf, PK.seed)

    Generates an SLH-DSA key pair.
    """
    # 1: ADRS ← toByte(0, 32)
    adrs = ADRS()
    # 2: ADRS.setLayerAddress(d − 1)
    adrs.set_layer_address(params.d - 1)
    # top-layer XMSS tree index is 0
    adrs.set_tree_address(0)

    # 3: PK.root ← xmss_node(SK.seed, 0, h′, PK.seed, ADRS)
    # We use the helper xmss_root which wraps xmss_node(…, 0, h′,…)
    PK_root = xmss_root(SK_seed, PK_seed, adrs, params.xmss)

    sk = SlhDsaPrivateKey(SK_seed=SK_seed, SK_prf=SK_prf, PK_seed=PK_seed, PK_root=PK_root)
    pk = SlhDsaPublicKey(PK_seed=PK_seed, PK_root=PK_root)
    return sk, pk


# ---------------------------------------------------------------------------
# Algorithm 19: slh_sign_internal
# ---------------------------------------------------------------------------


def slh_sign_internal(M: bytes,
                      SK: SlhDsaPrivateKey,
                      addrnd: bytes | None,
                      params: SlhDsaParams) -> SlhDsaSignature:
    """
    Algorithm 19 slh_sign_internal(M, SK, addrnd)

    Generates an SLH-DSA signature on message M.

    - If addrnd is provided: hedged variant (opt_rand = addrnd).
    - If addrnd is None   : deterministic variant (opt_rand = PK.seed).
    """
    n = params.n
    h = params.h_total
    h_prime = params.h_prime
    k = params.k
    a = params.a

    # 1: ADRS ← toByte(0, 32)
    adrs = ADRS()

    # 2: opt_rand ← addrnd (or PK.seed if deterministic)
    if addrnd is None:
        opt_rand = SK.PK_seed
    else:
        if len(addrnd) != n:
            raise ValueError(f"addrnd must be {n} bytes")
        opt_rand = addrnd

    # 3: R ← PRFmsg(SK.prf, opt_rand, M)
    R = prf_msg(SK.SK_prf, opt_rand, M, n)

    # 4: SIG ← R   (we’ll embed R in the structured signature object later)

    # 5: digest ← Hmsg(R, PK.seed, PK.root, M)
    m_bytes = params.md_bytes
    digest = h_msg(R, SK.PK_seed, SK.PK_root, M, m_bytes)

    # Split digest:
    #   md        : first ceil(k*a/8) bytes
    #   tmp_tree  : next  ceil((h - h′)/8) bytes
    #   tmp_leaf  : next  ceil(h′/8) bytes
    md_len = (k * a + 7) // 8
    tree_len = (h - h_prime + 7) // 8
    leaf_len = (h_prime + 7) // 8

    md = digest[0:md_len]
    tmp_tree = digest[md_len: md_len + tree_len]
    tmp_leaf = digest[md_len + tree_len: md_len + tree_len + leaf_len]

    # 9: idxtree ← toInt(tmp_idxtree, ...) mod 2^{h - h′}
    idxtree = to_int(tmp_tree) % (1 << (h - h_prime))
    # 10: idxleaf ← toInt(tmp_idxleaf, ...) mod 2^{h′}
    idxleaf = to_int(tmp_leaf) % (1 << h_prime)

    # 11–13: set up FORS address
    adrs.set_tree_address(idxtree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair_address(idxleaf)
    adrs.set_layer_address(0)  # FORS is always signed by layer 0 XMSS tree

    # 14: SIGFORS ← fors_sign(...)
    sig_fors = fors_sign(md, SK.SK_seed, SK.PK_seed, adrs.copy(), params.fors)

    # 16: PKFORS ← fors_pkFromSig(SIGFORS, md, PK.seed, ADRS)
    PK_fors = fors_pk_from_sig(sig_fors, md, SK.PK_seed, adrs.copy(), params.fors)

    # 17: SIGHT ← ht_sign(PKFORS, SK.seed, PK.seed, idxtree, idxleaf)
    sig_ht = ht_sign(PK_fors, SK.SK_seed, SK.PK_seed, idxtree, idxleaf, params.ht)

    # 18–19: bundle signature
    return SlhDsaSignature(R=R, sig_fors=sig_fors, sig_ht=sig_ht)


# ---------------------------------------------------------------------------
# Algorithm 20: slh_verify_internal
# ---------------------------------------------------------------------------


def slh_verify_internal(M: bytes,
                        SIG: SlhDsaSignature,
                        PK: SlhDsaPublicKey,
                        params: SlhDsaParams) -> bool:
    """
    Algorithm 20 slh_verify_internal(M, SIG, PK)

    Verifies an SLH-DSA signature (structured form).

    NOTE: The spec's byte-length check (lines 1–3) assumes a flat byte string.
    Here we rely on the structure and skip an explicit size check.
    """
    n = params.n
    h = params.h_total
    h_prime = params.h_prime
    k = params.k
    a = params.a

    # 4: ADRS ← toByte(0, 32)
    adrs = ADRS()

    # 5: R ← SIG.getR()
    R = SIG.R
    if len(R) != n:
        return False

    sig_fors = SIG.sig_fors
    sig_ht = SIG.sig_ht

    # 8: digest ← Hmsg(R, PK.seed, PK.root, M)
    m_bytes = params.md_bytes
    digest = h_msg(R, PK.PK_seed, PK.PK_root, M, m_bytes)

    # 9–13: parse digest into md, tmp_idxtree, tmp_idxleaf
    md_len = (k * a + 7) // 8
    tree_len = (h - h_prime + 7) // 8
    leaf_len = (h_prime + 7) // 8

    md = digest[0:md_len]
    tmp_tree = digest[md_len: md_len + tree_len]
    tmp_leaf = digest[md_len + tree_len: md_len + tree_len + leaf_len]

    idxtree = to_int(tmp_tree) % (1 << (h - h_prime))
    idxleaf = to_int(tmp_leaf) % (1 << h_prime)

    # 14–16: compute FORS public key
    adrs.set_tree_address(idxtree)
    adrs.set_type_and_clear(FORS_TREE)
    adrs.set_key_pair_address(idxleaf)
    adrs.set_layer_address(0)

    PK_fors = fors_pk_from_sig(sig_fors, md, PK.PK_seed, adrs.copy(), params.fors)

    # 18: return ht_verify(...)
    return ht_verify(PK_fors, sig_ht, PK.PK_seed, idxtree, idxleaf, PK.PK_root, params.ht)
