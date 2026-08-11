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
