"""`.qrp.toml` at the root of the scanned tree: profile, level, excludes, baseline, mandates.

The command line overrides it; `--no-config` ignores it; `--config FILE` names another. A
path it excludes is still present: it is listed in `coverage.not_examined` with the reason
`excluded_by_config`, so the coverage figure says it was not read. The file that did it is
named, with its digest, in `coverage.config` -- an in-tree file that silently zeroes the scan
is CryptoScan #9.
"""

import json

import pytest

from qrp_mcp import server
from qrp_mcp.scan import scan_directory

RSA = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
       "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")


def _tree(tmp_path, config=None):
    tree = tmp_path / "repo"
    (tree / "legacy").mkdir(parents=True)
    (tree / "app.py").write_text(RSA)
    (tree / "legacy" / "old.py").write_text(RSA)
    if config is not None:
        (tree / ".qrp.toml").write_text(config)
    return tree


def _paths(result):
    return {e["path"] for e in result["evidence"]["source_code"]}


def test_excluded_path_is_present_not_examined_with_its_reason(tmp_path):
    tree = _tree(tmp_path, 'exclude = ["legacy/"]\n')
    r = scan_directory(tree)
    assert _paths(r) == {"app.py"}
    reasons = {e["reason"]: e for e in r["coverage"]["not_examined"]}
    assert reasons["excluded_by_config"]["paths"] == ["legacy/old.py"]
    assert reasons["excluded_by_config"]["count"] == 1
    assert r["coverage"]["accounts_for_every_file"] is True
    assert r["coverage"]["scope"]["files_not_examined"] == 1
    cfg = r["coverage"]["config"]
    assert cfg["path"] == ".qrp.toml" and cfg["sha256"] and cfg["exclude"] == ["legacy/"]
    # The config file itself is left out of the reading and named.
    assert ".qrp.toml" in r["files_left_out"]


def test_glob_patterns(tmp_path):
    tree = _tree(tmp_path, 'exclude = ["legacy/*.py"]\n')
    assert _paths(scan_directory(tree)) == {"app.py"}


def test_no_config_file_changes_nothing(tmp_path):
    tree = _tree(tmp_path)
    r = scan_directory(tree)
    assert _paths(r) == {"app.py", "legacy/old.py"}
    assert "config" not in r["coverage"]
    assert "excluded_by_config" not in {e["reason"] for e in r["coverage"]["not_examined"]}


def test_cli_no_config_ignores_it(tmp_path):
    tree = _tree(tmp_path, 'exclude = ["legacy/"]\n')
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--no-config", "--out", str(out)]) == 0
    assert _paths(json.loads(out.read_text())) == {"app.py", "legacy/old.py"}


def test_cli_config_names_another_file(tmp_path):
    tree = _tree(tmp_path)
    cfg = tmp_path / "ci.toml"
    cfg.write_text('exclude = ["app.py"]\nlevel = "trimmed"\nprofile = "us-cnsa2"\n')
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--config", str(cfg), "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    assert _paths(r) == {"legacy/old.py"}
    assert r["excerpt_level"] == "trimmed" and r["replacement_profile"] == "us-cnsa2"


def test_command_line_overrides_the_file(tmp_path):
    tree = _tree(tmp_path, 'level = "trimmed"\nprofile = "us-cnsa2"\n')
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--level", "full", "--profile", "uk-ncsc",
                                "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    assert r["excerpt_level"] == "full" and r["replacement_profile"] == "uk-ncsc"


def test_baseline_path_in_the_config_is_relative_to_it(tmp_path):
    tree = _tree(tmp_path, 'baseline = ".qrp-baseline.json"\n')
    assert server.scan_to_file([str(tree), "--write-baseline",
                                str(tree / ".qrp-baseline.json"),
                                "--out", str(tmp_path / "a.json")]) == 0
    r = scan_directory(tree)
    assert r["baseline"]["new"] == 0 and r["baseline"]["baselined"] >= 2


def test_an_unknown_key_is_an_error(tmp_path, capsys):
    tree = _tree(tmp_path, 'exclud = ["legacy/"]\n')
    with pytest.raises(SystemExit) as e:
        server.scan_to_file([str(tree)])
    assert e.value.code == 2 and "exclud" in capsys.readouterr().err


def test_an_invalid_value_is_an_error(tmp_path, capsys):
    tree = _tree(tmp_path, 'level = "loud"\n')
    with pytest.raises(SystemExit) as e:
        server.scan_to_file([str(tree)])
    assert e.value.code == 2 and "level" in capsys.readouterr().err


def test_readiness_is_withheld_while_config_excludes_files(tmp_path):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "kem.py").write_text("from oqs import KeyEncapsulation\n"
                                 "kem = KeyEncapsulation('ML-KEM-768')\n")
    (tree / "old.py").write_text(RSA)
    (tree / ".qrp.toml").write_text('exclude = ["old.py"]\n')
    r = scan_directory(tree)
    assert r["summary"]["pqc_readiness"] == "not_established"
