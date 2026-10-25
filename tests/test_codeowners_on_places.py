"""The owner of each place, from CODEOWNERS (ZA-OPRAVYANE row 94; Dhiraj S., 23.10.2026,
"one CBOM, many owners ... the device teams own their rows").

The probe of 23.10.2026 (qrp-mcp 0.34.0): firmware/verify.c (RSA_verify) and payments/tls.py
(RSA + EC), .github/CODEOWNERS naming two teams. The CBOM's RSA component carried both places
and neither team appeared anywhere; CODEOWNERS was "no extension", unread. Rules from GitHub
Docs "About code owners" (read 23.10.2026): .github/, root, docs/ in that order, the last
matching line wins, gitignore-like patterns, `docs/*` not reaching nested files.
"""

import pytest

from qrp_mcp.cyclonedx import build
from qrp_mcp import detectors
from qrp_mcp.scan import scan_directory

OWNERS = """# owners
*                @platform
/firmware/       @device-team
payments/*.py    @payments-team
/payments/legacy.py
"""


def _tree(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text(OWNERS)
    (tmp_path / "firmware").mkdir()
    (tmp_path / "firmware" / "verify.c").write_text(
        "int ok = RSA_verify(NID_sha256, d, 32, sig, siglen, rsa);\n")
    (tmp_path / "payments").mkdir()
    (tmp_path / "payments" / "tls.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (tmp_path / "payments" / "legacy.py").write_text(
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "sign.py").write_text(
        "k = ec.generate_private_key(ec.SECP256R1())\n")
    return scan_directory(tmp_path)


def _owners(result, path):
    return {(tuple(i.get("owners") or ()), i.get("owners_source"))
            for i in result["evidence"]["source_code"] if i["path"] == path}


def test_each_place_carries_its_owner(tmp_path):
    result = _tree(tmp_path)
    assert result["codeowners"]["path"] == ".github/CODEOWNERS"
    assert ".github/CODEOWNERS" in result["files_read"]
    assert _owners(result, "firmware/verify.c") == {(("@device-team",), ".github/CODEOWNERS:3")}
    assert _owners(result, "payments/tls.py") == {(("@payments-team",), ".github/CODEOWNERS:4")}
    assert _owners(result, "tools/sign.py") == {(("@platform",), ".github/CODEOWNERS:2")}


def test_a_line_without_owners_leaves_the_place_unowned(tmp_path):
    assert _owners(_tree(tmp_path), "payments/legacy.py") == {((), None)}


def test_the_cbom_names_owners_per_occurrence(tmp_path):
    bom = build(_tree(tmp_path))
    # Every RSA component: the family's and one per key size read (release 3b, M4c).
    contexts = {o["location"]: o["additionalContext"] for c in bom["components"]
                if c["name"].startswith("RSA") for o in c.get("evidence", {}).get("occurrences", [])}
    assert "@device-team" in contexts["firmware/verify.c"]
    assert "@payments-team" in contexts["payments/tls.py"]


def test_codeowners_is_not_matched_for_algorithms(tmp_path):
    (tmp_path / "CODEOWNERS").write_text("/crypto/rsa/ @crypto-team\n")
    result = scan_directory(tmp_path)
    assert "CODEOWNERS" in result["files_read"]
    assert result["detected_algorithms"] == []


@pytest.mark.parametrize("pattern, path, matches", [
    ("docs/*", "docs/getting-started.md", True),
    ("docs/*", "docs/build-app/troubleshooting.md", False),
    ("apps/", "deep/apps/x.py", True),
    ("/build/logs/", "build/logs/a/b.txt", True),
    ("/build/logs/", "x/build/logs/b.txt", False),
    ("**/logs", "deeply/nested/logs/x", True),
    ("*.js", "a/b/c.js", True),
    ("/apps/github", "apps/github/x.py", True),
])
def test_pattern_rules_from_the_github_docs(pattern, path, matches):
    assert bool(detectors._codeowners_pattern(pattern).match(path)) is matches
