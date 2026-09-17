from __future__ import annotations

import re
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "src" / "qrp_mcp"


def _write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_scan_directory_classifies_what_it_detects(tmp_path: Path) -> None:
    _write(tmp_path, "app/crypto.py", "from Crypto.PublicKey import RSA\nimport hashlib\nhashlib.md5(b'x')\n")
    _write(tmp_path, ".github/workflows/release.yml", "jobs:\n  sign:\n    run: cosign sign $IMAGE\n")

    result = scan_directory(tmp_path)

    assert result["detected_algorithms"] == ["MD5", "RSA"]

    families = {f["algorithm_family"]: f for f in result["findings"]}
    # Detected algorithms must arrive classified, not as unlabelled evidence.
    assert families["RSA"]["classification"] == "classical_vulnerable"
    assert families["RSA"]["quantum_vulnerable"] is True
    assert families["MD5"]["classification"] == "deprecated_weak"

    assert result["summary"]["quantum_vulnerable_count"] == 1
    assert result["summary"]["pqc_readiness"] == "classical_only"

    ci = result["evidence"]["ci_pipeline"]
    assert len(ci) == 1 and ci[0]["command_type"] == "cosign_sign"


def test_pqc_only_project_reports_ready(tmp_path: Path) -> None:
    _write(tmp_path, "main.go", "// uses ML-KEM-768 for key exchange\n")
    result = scan_directory(tmp_path)
    assert result["summary"]["quantum_vulnerable_count"] == 0


def test_missing_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        scan_directory(tmp_path / "does-not-exist")


def test_package_makes_no_network_calls() -> None:
    """The zero-network promise in the README is enforced here, not just stated."""
    forbidden = re.compile(r"\b(httpx|requests|urllib|urllib3|socket|http\.client|aiohttp)\b")
    offenders = []
    for path in PACKAGE_DIR.rglob("*.py"):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith(("import ", "from ")) and forbidden.search(line):
                offenders.append(f"{path.name}:{line_no}: {line.strip()}")
    assert offenders == [], f"network-capable imports found: {offenders}"


# --- the instrument's own commit must not be borrowed from a surrounding tree ---

import json
import shutil as _shutil
import subprocess as _subprocess
import sys as _sys
import pytest as _pytest

_PKG = Path(__file__).resolve().parents[1] / "src" / "qrp_mcp"


def _pin_from(pkg_parent: Path) -> dict:
    code = "import json; from qrp_mcp.coverage import _tool_pin; print(json.dumps(_tool_pin()))"
    out = _subprocess.run([_sys.executable, "-c", code], capture_output=True, text=True,
                          env={"PYTHONPATH": str(pkg_parent), "PATH": "/usr/bin:/bin"},
                          check=True)
    return json.loads(out.stdout)


def _client_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "client"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n")
    for args in (["init", "-q"], ["add", "app.py"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c"]):
        _subprocess.run(["git", "-C", str(repo), *args], check=True)
    return repo


@_pytest.mark.skipif(not _shutil.which("git"), reason="needs git")
def test_installed_copy_inside_a_client_checkout_names_no_commit(tmp_path):
    # Found in the field: qrp-mcp installed into a virtualenv that lived inside
    # another repository reported that repository's HEAD as its own commit.
    repo = _client_repo(tmp_path)
    site = repo / ".venv" / "lib" / "python3" / "site-packages"
    _shutil.copytree(_PKG, site / "qrp_mcp")
    pin = _pin_from(site)
    assert pin["pinned"] is False and pin["reason"] == "no_checkout"


@_pytest.mark.skipif(not _shutil.which("git"), reason="needs git")
def test_untracked_copy_inside_a_foreign_repository_names_no_commit(tmp_path):
    repo = _client_repo(tmp_path)
    _shutil.copytree(_PKG, repo / "vendored" / "qrp_mcp")
    pin = _pin_from(repo / "vendored")
    assert pin["pinned"] is False and pin["reason"] == "not_a_repository"


def test_scan_command_writes_the_same_result_as_the_tool(tmp_path, capsys):
    import hashlib
    from qrp_mcp.server import scan_to_file
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                               "k = rsa.generate_private_key(65537, 2048)\n")
    out = tmp_path / "result.json"
    assert scan_to_file([str(tree), "--out", str(out)]) == 0
    written = json.loads(out.read_text())
    direct = scan_directory(str(tree))
    assert written["findings"] == direct["findings"]
    assert written["coverage"]["instrument"]["tool"] == "qrp-mcp"
    err = capsys.readouterr().err
    assert hashlib.sha256(out.read_bytes()).hexdigest() in err


def test_trimmed_level_drops_code_but_keeps_locations(tmp_path):
    from qrp_mcp.server import scan_to_file
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    out = tmp_path / "trimmed.json"
    scan_to_file([str(tree), "--out", str(out), "--level", "trimmed"])
    items = [i for v in json.loads(out.read_text())["evidence"].values()
             if isinstance(v, list) for i in v]
    assert items, "the fixture should produce evidence"
    assert all("excerpt" not in i for i in items)
    assert all("line" in i for i in items if "path" in i)
