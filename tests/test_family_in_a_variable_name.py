"""ZA-OPRAVYANE row 421 (the L1 self-seeded control, 04.11.2026): a family named only in the
name of a variable being assigned is an identifier, for ECDSA and Ed25519 as it already was for
RSA.

`ecdsa_fallback_count = 0` and `ed25519_rollout_pct = 100` were declarations at medium in every
language, while `rsa_migration_done = True` was an identifier at low: 19 of 21 planted lines.
The name carries the family; nothing on the line uses it.
"""

from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("name, line, family", [
    ("a.py", "ecdsa_fallback_count_x = 0", "ECDSA"),
    ("a.py", "ed25519_rollout_pct_x = 100", "Ed25519"),
    ("a.rb", "ecdsa_fallback_count_x = 0", "ECDSA"),
    ("a.rs", "const ECDSA_FALLBACK_COUNT_X: u32 = 0;", "ECDSA"),
    ("a.rs", "const ED25519_ROLLOUT_PCT_X: u32 = 100;", "Ed25519"),
    ("a.php", "$ecdsaFallbackCount_x = 0;", "ECDSA"),
    ("a.ts", "const ed25519RolloutPctX = 100;", "Ed25519"),
    ("A.java", "    static final int ecdsaFallbackCountX = 0;", "ECDSA"),
    ("a.go", "const ed25519RolloutPctX = 100", "Ed25519"),
])
def test_the_family_in_the_assigned_name_is_an_identifier(tmp_path, name, line, family):
    (tmp_path / name).write_text(line + "\n")
    rows = [r for r in scan_directory(tmp_path, settings=None)["evidence"]["source_code"]
            if r["algorithm"] == family]
    assert rows, "the name is still reported"
    assert {r["evidence_kind"] for r in rows} == {"identifier"}
    assert {r["confidence"] for r in rows} == {"low"}


@pytest.mark.parametrize("name, line, family, kind", [
    # The family on the right of the assignment is what is assigned.
    ("a.py", 'ecdsa_curve = "ECDSA"', "ECDSA", "declaration"),
    ("a.ts", "const ecdsaKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });", "ECDSA", "call"),
    ("a.py", "ECDSA = 1", "ECDSA", "declaration"),
])
def test_a_use_beside_the_name_is_still_read(tmp_path, name, line, family, kind):
    (tmp_path / name).write_text(line + "\n")
    rows = [r for r in scan_directory(tmp_path, settings=None)["evidence"]["source_code"]
            if r["algorithm"] == family]
    assert rows and rows[0]["evidence_kind"] == kind


def test_a_terraform_key_named_after_the_family_is_the_setting(tmp_path):
    """In Terraform the key names the setting: tls_private_key's ecdsa_curve chooses the curve.
    The first cut of row 421 turned it into an identifier at medium; the L1 harness re-run
    caught it on its terraform_tls_key style (high -> medium in 6 of 7 trees)."""
    (tmp_path / "k.tf").write_text('resource "tls_private_key" "x" {\n  algorithm   = "ECDSA"\n'
                                    '  ecdsa_curve = "P256"\n}\n')
    rows = [r for rows in scan_directory(tmp_path, settings=None)["evidence"].values() for r in rows
            if r.get("line") == 3 and r.get("algorithm") == "ECDSA"]
    assert rows and {r["evidence_kind"] for r in rows} == {"declaration"}
