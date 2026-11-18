"""S1 of the 0.50.0 review (PREGLED.md, 18.11): a credential in a dependency URL stayed in the
clear at `masked` and `trimmed`. `evidence.dependencies[].requested` keeps the PEP 508 request
as written, userinfo included: `paramiko @ git+https://tok:secret@host/p.git`. From
pyproject.toml since before 0.50.0; 0.50.0 added setup.py and setup.cfg as sources.

Below `full`, the userinfo of a URL in `requested` is masked as a line is, from every manifest a
dependency row comes from. `full` keeps it as written; the fingerprint does not read `requested`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.server import scan_repo

SRC = str(Path(__file__).resolve().parents[1] / "src")
URL = "git+https://tok-zzuser:zzpass-77@github.example/p.git"
MANIFESTS = {
    "pyproject.toml": f'[project]\nname = "x"\ndependencies = [\n  "paramiko @ {URL}",\n]\n',
    "setup.py": f'from setuptools import setup\nsetup(\n    install_requires=["paramiko @ {URL}"],\n)\n',
    "setup.cfg": f"[options]\ninstall_requires =\n    paramiko @ {URL}\n",
}
# requirements.txt is not among them: a `name @ url` line there gives no `requested` (checked
# 18.11), so it has nothing to mask.
NEEDLES = ("zzuser", "zzpass")


def _tree(tmp_path: Path, name: str) -> Path:
    root = tmp_path / "t"
    root.mkdir()
    (root / name).write_text(MANIFESTS[name])
    return root


def _cli(root: Path, out: Path, *args: str) -> dict:
    run = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                          str(root), "--out", str(out), "--no-config", *args],
                         capture_output=True, text=True, env={"PYTHONPATH": SRC, "PATH": "/usr/bin"})
    assert run.returncode == 0, run.stderr
    return json.loads(out.read_text())


def _rows(result: dict) -> list[dict]:
    return [r for r in result["evidence"]["dependencies"] if r["package"] == "paramiko"]


@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_the_credential_is_masked_below_full_through_scan_out(tmp_path, name):
    root = _tree(tmp_path, name)
    full = _cli(root, tmp_path / "f.json", "--level", "full")
    assert [r["requested"] for r in _rows(full)] == [f"@ {URL}"]
    for args in ((), ("--level", "masked"), ("--level", "trimmed")):
        result = _cli(root, tmp_path / "m.json", *args)
        text = json.dumps(result)
        assert not [n for n in NEEDLES if n in text], (name, args)
        assert [r["requested"] for r in _rows(result)] == [
            "@ git+https://***-******:******-**@github.example/p.git"]
        assert result["findings_fingerprint"] == full["findings_fingerprint"]


@pytest.mark.parametrize("name", sorted(MANIFESTS))
def test_the_credential_is_masked_below_full_through_scan_repo(tmp_path, name):
    root = _tree(tmp_path, name)
    for level in ("masked", "trimmed"):
        assert not [n for n in NEEDLES if n in json.dumps(scan_repo(path=str(root), level=level))]
    assert "zzpass-77" in json.dumps(scan_repo(path=str(root), level="full"))


def test_a_request_without_userinfo_is_unchanged(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n'
        '  "paramiko @ https://files.example/paramiko-3.4.0.tar.gz",\n  "cryptography>=42",\n]\n')
    result = scan_repo(path=str(root), level="masked")
    requested = {r["package"]: r.get("requested") for r in result["evidence"]["dependencies"]}
    assert requested == {"paramiko": "@ https://files.example/paramiko-3.4.0.tar.gz",
                         "cryptography": ">=42"}
