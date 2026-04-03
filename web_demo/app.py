# web_demo/app.py

from __future__ import annotations

import time
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
import sys

from flask import Flask, request, jsonify, send_from_directory

# Make sure the project root (where slhdsa/ lives) is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from slhdsa.ch11.param_sets import SLH_DSA_SHA2_256s
from slhdsa.ch10.api import slh_keygen, slh_sign, slh_verify


# ---------------------------------------------------------------------------
# Initialize SLH-DSA params and a single key pair
# ---------------------------------------------------------------------------

param_info = SLH_DSA_SHA2_256s
params = param_info.to_params()

print(f"[SLH-DSA] Using param set: {param_info.name}")
print(f"  n = {params.n}, d = {params.d}, h' = {params.h_prime}")
SK, PK = slh_keygen(params)
print("[SLH-DSA] Key pair generated.\n")


def _random_message(min_len: int = 32, max_len: int = 256) -> str:
    """
    Generate a random ASCII-ish message between min_len and max_len characters.

    This is just for demo/benchmarking; cryptographically, the message content
    doesn't matter.
    """
    length = min_len + secrets.randbelow(max_len - min_len + 1)
    alphabet = string.ascii_letters + string.digits + " .,;:-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder=".", static_url_path="")


@app.route("/")
def index():
    """Serve the HTML frontend."""
    return send_from_directory(Path(__file__).parent, "index.html")


@app.route("/api/random_test", methods=["POST"])
def random_test():
    """
    Run one random SLH-DSA test:

    - Generate random message
    - Sign (deterministic)
    - Verify
    - Measure timings
    - Return JSON with all the info
    """
    data = request.get_json(silent=True) or {}
    ctx_str = data.get("ctx", "demo")

    msg_str = _random_message()
    msg_bytes = msg_str.encode("utf-8")
    ctx = ctx_str.encode("utf-8")

    # Timestamp when test is started (UTC)
    ts = datetime.now(timezone.utc).isoformat()

    # Sign (deterministic so repeated tests are reproducible)
    t0 = time.perf_counter()
    sig = slh_sign(msg_bytes, SK, params, ctx=ctx, deterministic=True)
    t1 = time.perf_counter()
    sign_time_ms = (t1 - t0) * 1000.0

    # Verify
    t2 = time.perf_counter()
    ok = slh_verify(msg_bytes, sig, PK, params, ctx=ctx)
    t3 = time.perf_counter()
    verify_time_ms = (t3 - t2) * 1000.0

    # Simple preview of the signature object
    sig_repr = repr(sig)
    if len(sig_repr) > 200:
        sig_repr = sig_repr[:200] + " ..."

    return jsonify(
        {
            "timestamp": ts,
            "param_set": param_info.name,
            "message": msg_str,
            "message_len": len(msg_str),
            "ctx": ctx_str,
            "sign_time_ms": sign_time_ms,
            "verify_time_ms": verify_time_ms,
            "verify_ok": ok,
            "signature_preview": sig_repr,
        }
    )


if __name__ == "__main__":
    # Run the server (localhost:8000)
    app.run(host="0.0.0.0", port=8000, debug=True)
