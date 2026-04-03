# Project_Stateless_Hash — SLH-DSA (FIPS 205)

A Python implementation of the **Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)**, as specified in [NIST FIPS 205](https://doi.org/10.6028/NIST.FIPS.205), published August 13, 2024.

SLH-DSA is based on **SPHINCS+**, selected during the NIST Post-Quantum Cryptography Standardization process. It provides digital signatures that remain secure against attacks from quantum computers.

---

## Overview

Digital signatures allow an entity to:
- Authenticate the **integrity** of signed data
- Verify the **identity** of the signatory
- Provide **non-repudiation** — the signatory cannot easily deny having signed the data

SLH-DSA uses only hash functions as its cryptographic primitive, making it a conservative and well-understood post-quantum signature scheme.

---

## Project Structure

```
slhdsa/
├── ch4/        # Address (ADRS) structures, hash interfaces, and utilities
├── ch5/        # WOTS+ one-time signature scheme
├── ch6/        # XMSS (eXtended Merkle Signature Scheme)
├── ch7/        # Hypertree construction
├── ch8/        # FORS (Forest of Random Subsets)
├── ch9/        # SLH-DSA top-level: keygen, sign, verify
├── ch10/       # API layer
├── ch11/       # Hash function instantiations (SHA-2, SHAKE)
└── __init__.py
```

Each module corresponds to a chapter in FIPS 205, making it straightforward to cross-reference the implementation with the specification.

---

## Usage

```python
from ch9.slh_dsa import slh_keygen, slh_sign, slh_verify
from ch11.param_sets import get_params

# Select a parameter set (e.g. SLH-DSA-SHAKE-128s)
params = get_params("SLH-DSA-SHAKE-128s")

# Key generation
pk, sk = slh_keygen(params)

# Sign a message
message = b"Hello, post-quantum world!"
signature = slh_sign(message, sk, params)

# Verify
valid = slh_verify(message, signature, pk, params)
print("Signature valid:", valid)
```

---

## Parameter Sets

FIPS 205 defines parameter sets at three security levels, using either SHA-2 or SHAKE as the underlying hash:

| Parameter Set           | Security Level | Hash   |
|-------------------------|---------------|--------|
| SLH-DSA-SHA2-128s/f     | 1             | SHA-2  |
| SLH-DSA-SHA2-192s/f     | 3             | SHA-2  |
| SLH-DSA-SHA2-256s/f     | 5             | SHA-2  |
| SLH-DSA-SHAKE-128s/f    | 1             | SHAKE  |
| SLH-DSA-SHAKE-192s/f    | 3             | SHAKE  |
| SLH-DSA-SHAKE-256s/f    | 5             | SHAKE  |

`s` = small (slower, smaller signatures), `f` = fast (faster, larger signatures)

---

## Requirements

- Python 3.10+
- No external dependencies (uses Python's built-in `hashlib`)

---

## Reference

- [NIST FIPS 205](https://doi.org/10.6028/NIST.FIPS.205) — Stateless Hash-Based Digital Signature Standard
- [SPHINCS+ Specification](https://sphincs.org)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## License

This implementation is for educational and research purposes, based on the publicly available NIST FIPS 205 specification.