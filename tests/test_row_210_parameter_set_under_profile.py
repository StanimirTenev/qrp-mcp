"""ZA-OPRAVYANE row 210 (LinkedIn, 04.11.2026; fixture from the room's probe `ra-azure`).

`oqs.KeyEncapsulation("ML-KEM-768")` under `--profile au-ism` read `pqc_ready` with nothing
said, though the ISM's own text, which the profile quotes, approves ML-KEM-768 only until
2030; under `--mandate cnsa-2.0` (ML-KEM-1024 only) the 768 occurrence had no clause at all.
Profiles and mandates were applied to the classical findings only.

The classification stays `pqc_ready` (detection is the same under every profile). The finding
and its role's part now carry `profile_parameter_sets`, quoting what the profile says of the
parameter set read; under `--mandate cnsa-2.0` the occurrence gets a clause saying the set is
not among the mandate's."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "row-210" / "token.py"


def _tree(tmp_path: Path, text: str | None = None) -> Path:
    tree = tmp_path / "t"
    tree.mkdir()
    if text is None:
        shutil.copy(FIXTURE, tree / "token.py")
    else:
        (tree / "token.py").write_text(text)
    return tree


def _mlkem(result):
    return [f for f in result["findings"] if f["algorithm_family"] == "ML-KEM"][0]


def test_au_ism_dates_ml_kem_768(tmp_path):
    from qrp_mcp.scan import scan_directory
    result = scan_directory(_tree(tmp_path), profile="au-ism")
    finding = _mlkem(result)
    assert finding["classification"] == "pqc_ready"
    said = finding["profile_parameter_sets"]
    assert said[0]["parameter_set"] == "ML-KEM-768"
    assert "2030" in said[0]["standing"] and said[0]["places"] == ["token.py:16"]
    part = result["summary"]["by_role"]["key_establishment"]
    assert part["profile_parameter_sets"] == said


def test_nist_says_nothing_of_768(tmp_path):
    from qrp_mcp.scan import scan_directory
    result = scan_directory(_tree(tmp_path))
    assert "profile_parameter_sets" not in _mlkem(result)
    assert "profile_parameter_sets" not in result["summary"]["by_role"]["key_establishment"]


def test_au_ism_says_nothing_of_1024(tmp_path):
    from qrp_mcp.scan import scan_directory
    result = scan_directory(_tree(tmp_path, FIXTURE.read_text().replace("ML-KEM-768",
                                                                         "ML-KEM-1024")),
                            profile="au-ism")
    assert "profile_parameter_sets" not in _mlkem(result)


def test_cnsa_mandate_names_768_through_the_cli(tmp_path):
    out = tmp_path / "r.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(_tree(tmp_path)),
                        "--mandate", "cnsa-2.0", "--as-of", "2026-11-04", "--out", str(out)],
                       capture_output=True, text=True)
    result = json.loads(out.read_text())
    row = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "ML-KEM"][0]
    clause = row["mandates"]["cnsa-2.0"]
    assert clause["status"] == "parameter_set_not_in_mandate"
    assert "ML-KEM-1024" in clause["clause"]
    assert result["mandates"]["cnsa-2.0"]["by_status"]["parameter_set_not_in_mandate"] == 1
    # Not a deadline: the gate is unchanged by it.
    assert r.returncode == 0
