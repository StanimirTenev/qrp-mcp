"""LMS and XMSS through library APIs, not only by parameter-set name (ZA-OPRAVYANE row 50,
raised in public by Dhiraj S., 22.10.2026).

A firmware verifier calling wolfSSL's `wc_LmsKey_Verify` or hash-sigs'
`hss_validate_signature` scanned as nothing; only `LMS_SHA256_M32_H10` was matched.
wolfSSL names checked against wolfssl/wolfcrypt/lms.h and xmss.h in the corpus copy; the
Bouncy Castle classes (org.bouncycastle.pqc.crypto.lms) against the IBM
sonar-cryptography rule that lists them. XMSS was already matched by its name inside the
identifier; pinned here so it stays so.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("name, line", [
    ("a_wolf.c", "int v(LmsKey *k) { wc_LmsKey_SetParameters(k, 1, 10, 8); "
                 "return wc_LmsKey_Verify(k, s, n, m, mn); }"),
    ("b_hashsigs.c", "return hss_validate_signature(pub, msg, len, sig, siglen, 0);"),
    ("c_hashsigs.c", "ok = hss_generate_private_key(rng, levels, lm_type, ots_type, "
                     "write, ctx, pub, publen, aux, auxlen, 0);"),
    ("Fw.java", "LMSSigner signer = new LMSSigner();"),
    ("Hss.java", "HSSSigner signer = new HSSSigner();"),
])
def test_lms_through_its_api(tmp_path, name, line):
    (tmp_path / name).write_text(line + "\n", encoding="utf-8")
    assert "HSS/LMS" in scan_directory(tmp_path)["detected_algorithms"]


@pytest.mark.parametrize("line", [
    "wc_XmssKey_Verify(&key, sig, sigLen, msg, msgLen);",
    "if (xmss_sign_open(m, &mlen, sm, smlen, pk)) return -1;",
    "XMSSSigner signer = new XMSSSigner();",
])
def test_xmss_through_its_api(tmp_path, line):
    (tmp_path / "x.c").write_text(line + "\n", encoding="utf-8")
    assert "XMSS" in scan_directory(tmp_path)["detected_algorithms"]


@pytest.mark.parametrize("line", [
    "hss_config = load_home_subscriber_server()",
    "lms_course = fetch_learning_management_system()",
])
def test_lookalikes_are_not_lms(tmp_path, line):
    (tmp_path / "x.py").write_text(line + "\n", encoding="utf-8")
    assert "HSS/LMS" not in scan_directory(tmp_path)["detected_algorithms"]
