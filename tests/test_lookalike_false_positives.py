"""Identifiers that are not the algorithm (ZA-OPRAVYANE row 78, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_fp_false_positives`).

Node's createSign takes a digest name and the key decides the algorithm
(doc/api/crypto.md, `crypto.createSign(algorithm)`), so `createSign('SHA256')` says nothing
about RSA; `createSign('RSA-SHA256')` still does. Each lookalike is pinned beside the true
spelling it was confused with, so the fix cannot drop the real one.
"""

import pytest

from qrp_mcp.scan import scan_directory


def _found(tmp_path, name, line):
    (tmp_path / name).write_text(line + "\n", encoding="utf-8")
    return set(scan_directory(tmp_path)["detected_algorithms"])


@pytest.mark.parametrize("family, name, line", [
    ("HSS/LMS", "a.py", 'LMS_SHARED_SECRET = os.environ["LMS_SHARED_SECRET"]'),
    ("ECDSA", "a.py", "user.personal_signature = form.cleaned_data['sig']"),
    ("RSA", "a.js", "const s = crypto.createSign('SHA256'); s.update(d); const sig = s.sign(pem);"),
    ("DSA", "a.py", "sig = ml_dsa.sign(sk, msg)"),
])
def test_lookalike_is_not_the_family(tmp_path, family, name, line):
    assert family not in _found(tmp_path, name, line)


@pytest.mark.parametrize("family, name, line", [
    ("HSS/LMS", "a.c", "param = LMS_SHA256_M32_H10;"),
    ("ECDSA", "a.js", "await provider.send('personal_sign', [msg, addr]);"),
    ("ECDSA", "a.js", "await provider.send('eth_signTypedData_v4', [addr, data]);"),
    ("RSA", "a.js", "const s = crypto.createSign('RSA-SHA256');"),
    ("DSA", "a.go", "r, s, err := dsa.Sign(rand.Reader, priv, hash)"),
])
def test_the_real_spelling_still_is(tmp_path, family, name, line):
    assert family in _found(tmp_path, name, line)
