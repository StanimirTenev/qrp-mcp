"""A denial block forbids names, not calls (ZA-OPRAVYANE row 54, the summary probe of
22.10.2026).

A line that ends by opening a block and carries a denial word -- `forbiddenAlgorithms:` --
makes the names indented below it bans. The same test also fired on control flow:
`if (err.code === 'ERR_UNSUPPORTED') {` and `except UnsupportedAlgorithm:` opened a
"denial block", and the classical fallback CALL inside it became a ban. EC went to
`named_but_not_used`, the summary said `pqc_ready`, and the CBOM listed ML-KEM alone,
for code that generates a P-256 key whenever ML-KEM is unavailable. A call is a use
wherever it sits; the block now governs list entries and declarations only.
"""

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

JS = """const crypto = require('node:crypto');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');

function keypair() {
  try {
    return ml_kem768.keygen();
  } catch (err) {
    if (err.code === 'ERR_UNSUPPORTED') {
      return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    }
    throw err;
  }
}
"""

PY = """from cryptography.exceptions import UnsupportedAlgorithm
from pqcrypto.kem.ml_kem_768 import generate_keypair


def keypair(fallback):
    try:
        return generate_keypair()
    except UnsupportedAlgorithm:
        return fallback.ec.generate_private_key(fallback.ec.SECP256R1())
"""

# The block the rule exists for: names listed under a denial word stay bans.
BANNED_LIST = """security:
  forbiddenAlgorithms:
    - ssh-rsa
    - ecdsa-sha2-nistp256
"""


def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)


def test_js_fallback_call_is_a_use(tmp_path):
    result = _scan(tmp_path, "keys.js", JS)
    ec = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "EC"]
    assert ec and all(e["evidence_kind"] != "ban" for e in ec)
    assert "EC" not in result["named_but_not_used"]
    assert result["summary"]["pqc_readiness"] == "hybrid_partial"
    assert "EC" in {c["name"] for c in build(result)["components"]}


def test_python_except_unsupported_fallback_is_a_use(tmp_path):
    result = _scan(tmp_path, "kex.py", PY)
    assert "EC" in result["detected_algorithms"]
    assert result["summary"]["pqc_readiness"] == "hybrid_partial"


def test_a_list_under_a_denial_word_is_still_a_ban(tmp_path):
    result = _scan(tmp_path, "policy.yaml", BANNED_LIST)
    assert {"RSA", "ECDSA"} <= set(result["named_but_not_used"])
    assert result["detected_algorithms"] == []
