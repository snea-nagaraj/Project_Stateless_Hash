# slhdsa/__init__.py
"""
Minimal core for NIST FIPS 205 (SLH-DSA).

Section 4 implementation:
- utils.py : to_int, to_bytes_be, base_2b
- adrs.py  : ADRS + address type constants
- hash_ifaces.py : function interfaces (PRFmsg, Hmsg, PRF, Tl, H, F)
"""

# We *don't* re-import things here. Tests and code should import
# from slhdsa.utils, slhdsa.adrs, etc. directly.
