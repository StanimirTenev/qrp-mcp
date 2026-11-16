"""ZA-OPRAVYANE row 497, D1 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8
(MCUboot f30be48, 0.46.0).

MCUboot's headline was `algorithm_key_sizes.RSA: 1024` and a finding "RSA-1024", `weak_key`,
severity `critical`. It came from `scripts/tests/keys/test_rsa.py:39`:

    with self.assertRaises(RSAUsageError):
        RSA.generate(key_size=1024)

a test that 1024 is refused. A `with pytest.raises(...)` / `self.assertRaises(...)` block was a
rejection test (row 91) only when its line also held a denial word (`match='Unsupported ...'`);
without one the call inside was a use. Now the block itself is the rejection test, its calls
included, and it ends where its indentation does.

The other half of D1 -- the comments in Mbed TLS `rsa.h` ("128 Bytes if RSA-1024 is used") --
did not reproduce: they are `comment` rows, and comment rows never reached the headline size
(the filter of 0.11.0's retest). Pinned here, no code changed for it.
"""

import json
from pathlib import Path

from qrp_mcp import cyclonedx, server
from qrp_mcp import detectors as d
from qrp_mcp.scan import scan_directory

TEST_RSA = """import unittest

from imgtool.keys import RSA, RSAUsageError, load
from imgtool.keys.rsa import RSA_KEY_SIZES


class KeyGeneration(unittest.TestCase):

    def test_keygen(self):
        # Try generating a RSA key with non-supported size
        with self.assertRaises(RSAUsageError):
            RSA.generate(key_size=1024)

        for key_size in RSA_KEY_SIZES:
            k = RSA.generate(key_size=key_size)
            k.export_private(name1, b'secret')
"""

# No family in the exception's name: the `with` line holds no rule's match, so the gate passes
# over it unless it is asked for.
TEST_PYTEST = """import pytest
from cryptography.hazmat.primitives.asymmetric import rsa


def test_small_key_is_refused():
    with pytest.raises(ValueError):
        rsa.generate_private_key(public_exponent=65537, key_size=512)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
"""

RSA_H = """/**
 * \\brief            This function performs a PKCS#1 v2.1 OAEP encryption
 *
 * \\note             The output buffer must be as large as the size
 *                   of ctx->N. For example, 128 Bytes if RSA-1024 is used.
 */
int mbedtls_rsa_rsaes_oaep_encrypt( mbedtls_rsa_context *ctx );
"""


def _tree(root):
    (root / "scripts/tests/keys").mkdir(parents=True)
    (root / "scripts/tests/keys/test_rsa.py").write_text(TEST_RSA)
    (root / "tests").mkdir()
    (root / "tests/test_small.py").write_text(TEST_PYTEST)
    (root / "ext/mbedtls/include/mbedtls").mkdir(parents=True)
    (root / "ext/mbedtls/include/mbedtls/rsa.h").write_text(RSA_H)
    return root


def _kind(result, path, line):
    return [e["evidence_kind"] for e in result["evidence"]["source_code"]
            if e["path"] == path and e["line"] == line and e["algorithm"] == "RSA"]


def _check(result):
    assert _kind(result, "scripts/tests/keys/test_rsa.py", 12) == ["ban"]
    assert _kind(result, "tests/test_small.py", 7) == ["ban"]
    # The block ends with its indentation: the calls after it are uses.
    assert _kind(result, "scripts/tests/keys/test_rsa.py", 15) == ["call"]
    assert _kind(result, "tests/test_small.py", 8) == ["call"]
    assert result["algorithm_key_sizes"]["RSA"] == 3072, result["algorithm_key_sizes"]
    assert result["algorithm_key_sizes_observed"]["RSA"] == [3072]
    rsa_findings = [f for f in result["findings"] if f["algorithm_family"] == "RSA"]
    assert rsa_findings and all(f["severity"] != "critical" and not f.get("weak_key")
                                and "1024" not in f["raw_value"] and "512" not in f["raw_value"]
                                for f in rsa_findings), rsa_findings


def test_rejection_block_in_the_scan_json(tmp_path):
    tree = _tree(tmp_path / "repo")
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    _check(json.loads(out.read_text()))


def test_rejection_block_in_the_mcp_tool(tmp_path):
    _check(server.scan_repo(str(_tree(tmp_path / "repo"))))


def test_rejection_block_in_the_cbom(tmp_path):
    tree = _tree(tmp_path / "repo")
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        names = {c["name"] for c in doc["components"]}
        assert not {n for n in names if n.startswith(("RSA-1024", "RSA-512"))}, names


def test_comments_alone_do_not_set_the_headline(tmp_path):
    (tmp_path / "rsa.h").write_text(RSA_H)
    result = scan_directory(tmp_path)
    assert _kind(result, "rsa.h", 5) == ["comment"]
    assert 1024 not in result["algorithm_key_sizes_observed"].get("RSA", [])
    assert not [f for f in result["findings"] if "1024" in f["raw_value"]]


def test_the_gate_and_the_full_read_agree():
    for name, text in (("scripts/tests/keys/test_rsa.py", TEST_RSA),
                       ("tests/test_small.py", TEST_PYTEST)):
        lines = text.split("\n")
        assert (d.scan_source_file(Path(name), name, lines, hot=None)
                == d.scan_source_file(Path(name), name, lines, hot=d.hot_lines(lines, ".py")))
