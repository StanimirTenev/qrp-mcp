"""Row 144, the same class one step further: the files release A itself writes and reads.

A SARIF log -- ours from `--format sarif`, or any other scanner's -- names algorithms in its
rule texts and messages, so a rescan of a tree that commits one read the report as code.
Our baseline is JSON naming a family per entry. `.qrp.toml` is the owner's settings, and its
comments name the very algorithms it excludes. None of them is cryptography in use: a SARIF
log is a report document, named with its reason; a baseline is one too; a `.qrp.toml` is
left out by name wherever it sits, whether or not this run loaded it.
"""

from __future__ import annotations

import json
from pathlib import Path

from qrp_mcp import server
from qrp_mcp.scan import scan_directory

EC = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
      "k = ec.generate_private_key(ec.SECP256R1())\n")
RSA = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
       "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")

# Another scanner's SARIF, in the shape the 01-tablo probes captured (rule per algorithm,
# message naming it): nothing of ours in it, no `bomFormat`, no "qrp-mcp".
FOREIGN_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "OtherScanner", "rules": [
            {"id": "RSA-001", "shortDescription": {"text": "RSA key generation"}},
            {"id": "MLKEM-001", "shortDescription": {"text": "ML-KEM-768 key encapsulation"}}]}},
        "results": [
            {"ruleId": "RSA-001", "message": {"text": "RSA-2048 detected"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                                 "region": {"startLine": 2,
                                                            "snippet": {"text": RSA}}}}]},
            {"ruleId": "MLKEM-001", "message": {"text": "ML-KEM-768 in use"}}],
    }],
}


def _reports(result: dict) -> list[str]:
    return next((r["paths"] for r in result["coverage"]["not_examined"]
                 if r["reason"] == "report_document"), [])


def _rows(result: dict) -> list[tuple[str, int]]:
    return [(e["path"], e["line"]) for items in result["evidence"].values() for e in items
            if "path" in e and "line" in e]


def test_a_foreign_sarif_log_is_a_report_document(tmp_path):
    (tmp_path / "app.py").write_text(EC)
    # Formatted like a real log and not named .sarif: content decides.
    (tmp_path / "scan-results.json").write_text(json.dumps(FOREIGN_SARIF, indent=2))
    r = scan_directory(tmp_path)
    assert _reports(r) == ["scan-results.json"]
    assert all(p == "app.py" for p, _ in _rows(r))
    assert "RSA" not in r["detected_algorithms"]
    assert r["summary"]["pqc_readiness"] == "classical_only"


def test_a_sarif_log_without_schema_is_recognised_by_version_and_runs(tmp_path):
    (tmp_path / "app.py").write_text(EC)
    log = {k: v for k, v in FOREIGN_SARIF.items() if k != "$schema"}
    (tmp_path / "out.sarif").write_text(json.dumps(log))
    r = scan_directory(tmp_path)
    assert _reports(r) == ["out.sarif"]
    assert "RSA" not in r["detected_algorithms"]


def test_our_own_sarif_in_the_tree_is_a_report_document(tmp_path):
    rich = tmp_path / "rich"
    rich.mkdir()
    (rich / "a.py").write_text(RSA)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text(EC)
    assert server.scan_to_file([str(rich), "--format", "sarif",
                                "--out", str(tree / "qrp.sarif")]) == 0
    r = scan_directory(tree)
    assert _reports(r) == ["qrp.sarif"]
    assert r["detected_algorithms"] == ["EC"]


def test_a_json_with_runs_alone_is_still_read(tmp_path):
    # A CI file that happens to have a `runs` list is not a SARIF log.
    (tmp_path / "pipeline.json").write_text(json.dumps({
        "runs": [{"step": "sign", "cmd": "openssl genrsa 2048"}]}))
    r = scan_directory(tmp_path)
    assert "pipeline.json" in r["files_read"]
    assert _reports(r) == []


def test_a_committed_baseline_is_a_report_document(tmp_path):
    old = tmp_path / "old"
    old.mkdir()
    (old / "a.py").write_text(RSA)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text(EC)
    # Written into the tree and not passed to this run: read as a file of the tree.
    assert server.scan_to_file([str(old), "--write-baseline", str(tree / ".qrp-baseline.json"),
                                "--out", str(tmp_path / "r.json")]) == 0
    assert '"RSA"' in (tree / ".qrp-baseline.json").read_text()
    r = scan_directory(tree)
    assert _reports(r) == [".qrp-baseline.json"]
    assert r["detected_algorithms"] == ["EC"]
    assert all(p == "app.py" for p, _ in _rows(r))


# The comment names RSA-2048 and ML-DSA: saved under any other name it is read and matched,
# which is the positive control below.
CONFIG = ('# legacy/ holds the RSA-2048 signer, kept until the HSM moves to ML-DSA\n'
          'profile = "us-cnsa2"\nexclude = ["legacy/"]\n')


def test_the_config_text_is_matched_under_another_name(tmp_path):
    (tmp_path / "settings.toml").write_text(CONFIG)
    assert ("settings.toml", 1) in _rows(scan_directory(tmp_path))


def test_a_qrp_toml_never_produces_findings_even_when_not_loaded(tmp_path):
    (tmp_path / "app.py").write_text(EC)
    (tmp_path / ".qrp.toml").write_text(CONFIG)
    sub = tmp_path / "service"
    sub.mkdir()
    (sub / ".qrp.toml").write_text(CONFIG)
    for kwargs in ({}, {"settings": None}):  # loaded; `--no-config`
        r = scan_directory(tmp_path, **kwargs)
        assert all(p == "app.py" for p, _ in _rows(r)), kwargs
        # Left out and named, never silently.
        assert sorted(r["files_left_out"]) == [".qrp.toml", "service/.qrp.toml"], kwargs


def test_the_names_detectors_spells_out_are_the_ones_the_modules_use():
    from qrp_mcp import baseline, config, detectors
    assert detectors.BASELINE_FORMAT == baseline.FORMAT
    assert detectors.CONFIG_FILENAME == config.FILENAME
