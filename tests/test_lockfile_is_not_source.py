"""A package name in a lockfile is not a use of the algorithm (ZA-OPRAVYANE row 88, swarm C of
22.10.2026, `roy-2026-10-22/c-korpus` test_c10: android/security-samples, a negative control
using only AES, whose one quantum-vulnerable finding was `ecdsa-sig-formatter` in
package-lock.json as "ECDSA usage")."""

import json

from qrp_mcp.scan import scan_directory

LOCK = {
    "name": "app", "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "dependencies": {"jws": "^4.0.0"}},
        "node_modules/ecdsa-sig-formatter": {
            "version": "1.0.11",
            "resolved": "https://registry.npmjs.org/ecdsa-sig-formatter/-/"
                        "ecdsa-sig-formatter-1.0.11.tgz"},
    },
}


def test_lockfile_names_are_not_source_usage(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps(LOCK, indent=2), encoding="utf-8")
    result = scan_directory(tmp_path)
    assert not [r for r in result["evidence"]["source_code"] if r["path"] == "package-lock.json"]
    assert "ECDSA" not in result["detected_algorithms"]
    assert "package-lock.json" in result["files_read"]


def test_poetry_lock_too(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "ecdsa"\nversion = "0.19.0"\n', encoding="utf-8")
    result = scan_directory(tmp_path)
    assert "ECDSA" not in result["detected_algorithms"]
    # Still declared, by the manifest reader.
    assert any(d["package"] == "ecdsa" for d in result["evidence"]["dependencies"])
