"""ZA-OPRAVYANE row 423 (the L1 self-seeded control, 04.11.2026): a string handed to a log or
print call is text, never a `call` at high.

`log::info!("Ed25519 key expires soon")` in Rust and ``console.info(`ECDSA verifier not
configured for ${tenant}`)`` in TypeScript were calls at high: the three high-confidence false
alarms of the whole control. A sentence was recognised only by its small words (`not`, `for`),
and a template literal not at all.
"""

from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("name, line, family", [
    ("a.rs", 'fn log_x() { log::info!("Ed25519 key expires soon"); }', "Ed25519"),
    ("a.rs", 'fn log_x() { tracing::warn!("rotating RSA signing key"); }', "RSA"),
    ("a.rs", 'println!("ECDSA key loaded");', "ECDSA"),
    ("a.ts", "console.info(`ECDSA verifier not configured for ${tenantX}`);", "ECDSA"),
    ("a.ts", "console.info(`Ed25519 key for ${tenantX} expires soon`);", "Ed25519"),
    ("a.ts", "logger.warn('Ed25519 key expires soon');", "Ed25519"),
    ("a.go", 'func logX(t string) { log.Printf("Ed25519 key expires soon %s", t) }', "Ed25519"),
    ("A.java", '    static void logX(String t) { LOG.info("Ed25519 key expires soon {}", t); }', "Ed25519"),
    ("a.php", '$log->info("Ed25519 key expires soon");', "Ed25519"),
    ("a.py", "logger.info('Ed25519 key expires soon')", "Ed25519"),
])
def test_a_logged_string_is_not_a_use(tmp_path, name, line, family):
    (tmp_path / name).write_text(line + "\n")
    rows = [r for r in scan_directory(tmp_path, settings=None)["evidence"]["source_code"]
            if r["algorithm"] == family]
    assert all(r["evidence_kind"] in {"comment", "ban"} for r in rows), rows
    assert not any(r["confidence"] == "high" for r in rows)


def test_a_call_beside_a_log_line_is_still_a_call(tmp_path):
    (tmp_path / "a.go").write_text(
        'key, _ := rsa.GenerateKey(rand.Reader, 2048); log.Printf("generated")\n')
    rows = [r for r in scan_directory(tmp_path, settings=None)["evidence"]["source_code"]
            if r["algorithm"] == "RSA"]
    assert rows and rows[0]["evidence_kind"] == "call"


def test_a_call_inside_a_log_call_is_still_a_call(tmp_path):
    (tmp_path / "a.ts").write_text(
        "console.log(generateKeyPairSync('rsa', { modulusLength: 2048 }));\n")
    rows = [r for r in scan_directory(tmp_path, settings=None)["evidence"]["source_code"]
            if r["algorithm"] == "RSA"]
    assert rows and rows[0]["evidence_kind"] == "call"
