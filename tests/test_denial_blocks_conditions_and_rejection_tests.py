"""Two shapes of the denial block (ZA-OPRAVYANE rows 90 and 91; raised by the 0.34.0 agent as
А and reproduced 23.10.2026).

Row 90: a block opened by a condition -- `} catch (UnsupportedAlgorithmError) {` -- is code
that runs in that case, not a list of banned names. Row 54 (0.34.0) stopped it from turning
calls into bans; a declaration inside (`const curve = 'prime256v1'`) was still a ban, and EC
landed in named_but_not_used.

Row 91: `with pytest.raises(..., match='Unsupported ...'):` is a test that the call inside is
rejected. Since row 54 that call read as a use (certbot crypto_util_test.py:236).
"""

from qrp_mcp.scan import scan_directory

JS = """async function makeKey() {
  try {
    return await subtle.generateKey({ name: 'X25519' }, true, ['deriveKey']);
  } catch (UnsupportedAlgorithmError) {
    const curve = 'prime256v1';
    return curve;
  }
}
"""

PY = """import pytest

def test_unsupported_curve():
    with pytest.raises(errors.Error, match='Unsupported elliptic curve: nothere'):
        make_key(elliptic_curve="nothere", key_type='ecdsa')
"""

BANNED = """forbiddenAlgorithms:
  - ssh-rsa
  - ssh-dss
"""


def _kinds(result, family):
    return [i["evidence_kind"] for i in result["evidence"]["source_code"] if i["algorithm"] == family]


def test_declaration_in_a_condition_block_is_a_use(tmp_path):
    (tmp_path / "keys.js").write_text(JS)
    result = scan_directory(tmp_path)
    assert _kinds(result, "EC") == ["declaration"]
    assert "EC" in result["detected_algorithms"]


def test_call_under_pytest_raises_is_not_a_use(tmp_path):
    (tmp_path / "test_keys.py").write_text(PY)
    result = scan_directory(tmp_path)
    assert _kinds(result, "ECDSA") == ["ban"]
    assert "ECDSA" not in result["detected_algorithms"]


def test_a_real_denial_block_still_bans(tmp_path):
    (tmp_path / "policy.yaml").write_text(BANNED)
    result = scan_directory(tmp_path)
    assert set(_kinds(result, "RSA")) == {"ban"}
