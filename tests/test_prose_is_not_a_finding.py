"""Prose in a comment or in a string is not a finding (ZA-OPRAVYANE row 132, decided
24.10.2026).

The measurement's negative control (`qrp-kachestvo/imena-2026-10-23/a-c-biblioteki`, §6) had
two: `// ECDH was considered and rejected` and `"supports Ed25519 and ML-KEM"`. The comment
was already comment evidence, out of the inventory; the string was a finding. A sentence in
a string is now read as a comment is: kept as evidence, named, not counted as a use.
"""

import pytest

from qrp_mcp.scan import scan_directory


def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text + "\n", encoding="utf-8")
    return scan_directory(tmp_path)


@pytest.mark.parametrize("name, line", [
    ("a.c", "// ECDH was considered and rejected"),
    ("a.c", 'const char *help = "supports Ed25519 and ML-KEM";'),
    ("a.c", 'ctx = EVP_PKEY_CTX_new_from_name(NULL, "The CRL is signed with an unacceptable PK '
            'alg (eg RSA vs ECDSA).", NULL);'),
    ("a.py", 'raise ValueError("ECDSA keys are not used here")'),
])
def test_prose_names_but_is_not_used(tmp_path, name, line):
    result = _scan(tmp_path, name, line)
    assert result["detected_algorithms"] == [] and result["summary"]["total_findings"] == 0
    assert result["named_but_not_used"]
    assert {f["evidence_kind"] for f in result["evidence"]["source_code"]} == {"comment"}


@pytest.mark.parametrize("family, name, line", [
    ("RSA", "a.py", 'subprocess.run("openssl genrsa -out key.pem 2048", shell=True)'),
    ("ECDH", "a.c", 'SSL_CTX_set1_groups_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256");'),
    ("ML-KEM", "a.py", 'groups = "X25519MLKEM768:X25519"'),
    ("RSA", "a.py", 'parser.add_argument("--rsa-key-size", help="Size of the RSA key.")'),
])
def test_a_name_in_a_string_that_is_not_a_sentence_is_still_used(tmp_path, family, name, line):
    assert family in _scan(tmp_path, name, line)["detected_algorithms"]
