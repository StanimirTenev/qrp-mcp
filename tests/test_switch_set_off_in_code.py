"""ZA-OPRAVYANE row 422 (the L1 self-seeded control, 04.11.2026): a switch set off in Rust,
TypeScript, PHP, Java and Go is a ban, as it already was in Python and Ruby (rows 203, 196).

`const ECDSA_ENABLED: bool = false;`, `static final boolean ECDSA_ENABLED = false;`,
`$ecdsaEnabled = false;`, `const ecdsaEnabled = false` were declarations at medium: 12 of 21
planted lines wrong. The 0.42.0 rule anchored the name at the start of the line, so a keyword,
a type, a `$` or a type annotation in front of it, and a camelCase name, were not a switch.
`= 0` is off as `= false` is, with the same requirement that the name is a switch.
"""

from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory


def _kinds(tmp_path, name, line, family):
    (tmp_path / name).write_text(line + "\n")
    return {r["evidence_kind"] for r in scan_directory(tmp_path, settings=None)["evidence"]["source_code"]
            if r["algorithm"] == family}


@pytest.mark.parametrize("name, line, family", [
    ("a.rs", "const ECDSA_ENABLED: bool = false;", "ECDSA"),
    ("a.rs", "pub const ED25519_ENABLED: bool = false;", "Ed25519"),
    ("a.ts", "const ECDSA_ENABLED = false;", "ECDSA"),
    ("a.ts", "export const ED25519_ALLOWED: boolean = false;", "Ed25519"),
    ("a.php", "$ecdsaEnabled = false;", "ECDSA"),
    ("a.php", "$ed25519Enabled = 0;", "Ed25519"),
    ("A.java", "    static final boolean ECDSA_ENABLED = false;", "ECDSA"),
    ("A.java", "    private static final boolean ed25519Enabled = false;", "Ed25519"),
    ("a.go", "const ecdsaEnabled = false", "ECDSA"),
    ("a.go", "var ed25519Enabled = false", "Ed25519"),
    ("a.py", "ECDSA_ENABLED = 0", "ECDSA"),
])
def test_a_switch_set_off_is_a_ban(tmp_path, name, line, family):
    assert _kinds(tmp_path, name, line, family) == {"ban"}


@pytest.mark.parametrize("name, line, family", [
    # A switch set on is not a ban.
    ("a.rs", "const ECDSA_ENABLED: bool = true;", "ECDSA"),
    ("a.go", "const ecdsaEnabled = true", "ECDSA"),
    # A count set to zero is not a switch: its name says nothing about enabling.
    ("a.ts", "const ecdsaFallbackCount = 0;", "ECDSA"),
])
def test_not_every_false_or_zero_is_a_ban(tmp_path, name, line, family):
    kinds = _kinds(tmp_path, name, line, family)
    assert kinds and "ban" not in kinds
