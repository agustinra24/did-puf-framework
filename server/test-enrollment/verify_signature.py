# /// script
# requires-python = ">=3.11"
# dependencies = ["liboqs-python", "requests"]
# ///
"""Cross-verify ML-DSA-87 signatures: ESP32 (mldsa-native) vs server (liboqs).

Fetches enrollment data from the test server, reconstructs the base JSON
that was signed on the ESP32, and verifies the ML-DSA-87 signature using
liboqs (a completely different FIPS 204 implementation).

Tests performed:
  1. Positive: verify signature with correct context string ("enroll")
  2. Negative: verify with wrong context string (must reject)
  3. Negative: verify with tampered message digest (must reject)

Prerequisites:
  Build liboqs shared library (only needed once):
    git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git
    cd liboqs && cmake -B build -DBUILD_SHARED_LIBS=ON && cmake --build build -j$(nproc)

Usage:
  1. Start the test server:        uv run server.py
  2. Enroll an ESP32 device (Step 0 enrollment must complete)
  3. Run this script:
     DYLD_LIBRARY_PATH=/path/to/liboqs/build/lib uv run \\
       --with 'liboqs-python @ git+https://github.com/open-quantum-safe/liboqs-python.git' \\
       --with requests verify_signature.py
"""

import base64
import hashlib
import json
import sys

import oqs
import requests

SERVER = "http://localhost:8000"
CONTEXT_STRING = b"enroll"
ML_DSA_PK_BYTES = 2592
ML_DSA_SIG_BYTES = 4627


def reconstruct_base_json(device_name: str, mac_hex: str, puf_hash_b64: str) -> str:
    """Reconstruct the exact JSON string that cJSON_PrintUnformatted() produced.

    The ESP32 signs SHA-512 of this JSON (without MLDSA_PK/MLDSA_Sig fields).
    json.dumps with separators=(',',':') matches cJSON_PrintUnformatted output:
    no spaces, keys in insertion order, integers without decimals.
    """
    mac_bytes = bytes.fromhex(mac_hex.replace(":", ""))
    mac_b64 = base64.b64encode(mac_bytes).decode()

    base = {
        "Step": 0,
        "Device_Name": device_name,
        "Mac_Address": mac_b64,
        "PUF_Hash": puf_hash_b64,
    }
    return json.dumps(base, separators=(",", ":"))


def verify_device(name: str, record: dict) -> bool:
    """Verify one device's ML-DSA-87 enrollment signature."""
    print(f"\n{'='*60}")
    print(f"Device: {name}")
    print(f"MAC:    {record['mac']}")

    if "mldsa_pk_b64" not in record or "mldsa_sig_b64" not in record:
        print("SKIP: No ML-DSA signature data")
        return True

    pk_bytes = base64.b64decode(record["mldsa_pk_b64"])
    sig_bytes = base64.b64decode(record["mldsa_sig_b64"])

    print(f"PK:     {len(pk_bytes)} bytes (expected {ML_DSA_PK_BYTES})")
    print(f"Sig:    {len(sig_bytes)} bytes (expected {ML_DSA_SIG_BYTES})")

    if len(pk_bytes) != ML_DSA_PK_BYTES:
        print(f"FAIL: PK size mismatch")
        return False
    if len(sig_bytes) != ML_DSA_SIG_BYTES:
        print(f"FAIL: Sig size mismatch")
        return False

    # Reconstruct the signed message
    base_json = reconstruct_base_json(name, record["mac"], record["puf_hash_b64"])
    digest = hashlib.sha512(base_json.encode()).digest()

    print(f"JSON:   {base_json[:80]}...")
    print(f"SHA512: {digest[:16].hex()}...")

    # Positive test: verify with correct context
    verifier = oqs.Signature("ML-DSA-87")
    try:
        valid = verifier.verify_with_ctx_str(digest, sig_bytes, CONTEXT_STRING, pk_bytes)
        print(f"\nVerify (ctx='enroll'):  {'PASS' if valid else 'FAIL'}")
    except Exception as e:
        print(f"\nVerify (ctx='enroll'):  FAIL ({e})")
        valid = False

    # Negative test: wrong context must fail
    try:
        wrong = verifier.verify_with_ctx_str(digest, sig_bytes, b"wrong", pk_bytes)
        neg_pass = not wrong
        print(f"Verify (ctx='wrong'):   {'PASS (rejected)' if neg_pass else 'FAIL (accepted!)'}")
    except Exception:
        neg_pass = True
        print(f"Verify (ctx='wrong'):   PASS (rejected)")

    # Negative test: tampered digest must fail
    tampered = bytearray(digest)
    tampered[0] ^= 0xFF
    try:
        tampered_result = verifier.verify_with_ctx_str(bytes(tampered), sig_bytes, CONTEXT_STRING, pk_bytes)
        tamper_pass = not tampered_result
        print(f"Verify (tampered msg):  {'PASS (rejected)' if tamper_pass else 'FAIL (accepted!)'}")
    except Exception:
        tamper_pass = True
        print(f"Verify (tampered msg):  PASS (rejected)")

    all_pass = valid and neg_pass and tamper_pass
    print(f"\nResult: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
    return all_pass


def main():
    print("ML-DSA-87 Cross-Verification: mldsa-native (ESP32) <-> liboqs (server)")
    print(f"liboqs version: {oqs.oqs_version()}")
    print(f"Context string: '{CONTEXT_STRING.decode()}'")

    try:
        resp = requests.get(f"{SERVER}/api/v1/devices", timeout=5)
        resp.raise_for_status()
    except requests.ConnectionError:
        print(f"\nERROR: Cannot connect to {SERVER}. Start the test server first.")
        sys.exit(1)

    data = resp.json()
    print(f"Devices enrolled: {data['count']}")

    if data["count"] == 0:
        print("No devices to verify. Run enrollment first.")
        sys.exit(1)

    all_ok = True
    for name, record in data["devices"].items():
        if not verify_device(name, record):
            all_ok = False

    print(f"\n{'='*60}")
    if all_ok:
        print("CROSS-VERIFICATION PASSED")
        print("ML-DSA-87 signatures from ESP32 (mldsa-native) verified by liboqs.")
    else:
        print("CROSS-VERIFICATION FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
