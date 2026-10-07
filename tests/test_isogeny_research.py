"""Row 15 (John Preuss Mattsson, 6 Oct 2026): MIKE, CSIDH and CTIDH were not recognised.

Reproduced on 0.28.0 + 178dcf2: `mike_keypair(pk, sk)`, the CIRCL `dh/csidh` import and
`highctidh` gave 0 findings, so code doing post-quantum isogeny key exchange read as
having no post-quantum cryptography at all.

Status `research`: MIKE is in no standardisation process (NIST's was KEM-only, no IETF
draft, code weeks old); CSIDH-512 is below its claimed level against quantum attack
(Peikert; Bonnetain-Schrottenloher) -- a cost estimate, not a classical break, so
SIKE's `broken` is not carried over (Maino et al.: the attack "does not apply to CSIDH").
`mike` alone is a person, the MkDocs versioning tool on PyPI, and MIKEY; it never matches.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.classifier import FingerprintRequest, fingerprint
from qrp_mcp.server import export_cbom, list_algorithms, scan_repo


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(tree: Path, out: Path) -> dict:
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def _both(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    tree = _tree(tmp_path / "tree", files)
    return [_cli(tree, tmp_path / "out.json"), _tool(scan_repo)(str(tree))]


def _families(result: dict) -> dict[str, tuple]:
    return {f["algorithm_family"]: (f.get("pqc_family"), f.get("pqc_status"), f["classification"])
            for f in result["findings"]}


RESEARCH = ("isogeny-based", "research", "pqc_pre_standard")


@pytest.mark.parametrize("name, text", [
    ("nike.c", "mike_keypair(pk, sk);\n"),
    ("CMakeLists.txt", "set(MIKE_PRIME_CHOICE fast)\n"),
    ("main.rs", "use mike_rs::mike::MIKE_I;\n"),
    ("t.py", "from mike.mike import Mike, PARAMS_I\n"),
])
def test_mike_is_research(tmp_path, name, text):
    for result in _both(tmp_path, {name: text}):
        assert _families(result) == {"MIKE": RESEARCH}
        assert result["summary"]["pqc_readiness"] == "pqc_pre_standard"
        assert result["summary"]["pqc_ready_count"] == 0
        assert result["summary"]["broken_pqc_count"] == 0


@pytest.mark.parametrize("name, text", [
    ("a.go", 'import "github.com/cloudflare/circl/dh/csidh"\n'),
    ("a.py", "ctidh512 = highctidh.ctidh(512)\n"),
    ("a.c", "secsidh_CTIDH2047m1l226_keygen(pk, sk);\n"),
    ("requirements.txt", "highctidh==1.0.2025051200\n"),
])
def test_csidh_and_ctidh_are_research_not_broken(tmp_path, name, text):
    for result in _both(tmp_path, {name: text}):
        assert _families(result) == {"CSIDH/CTIDH": RESEARCH}


@pytest.mark.parametrize("text", [
    "pip install mike\n",
    "import mike\nmike.deploy('1.0')\n",
    "# reviewed by Mike\nauthor = 'Mike Smith'\n",
    "MIKEY-SAKKE key exchange (RFC 3830 mikey)\n",
    "mike_version = 2\n",
])
def test_bare_mike_never_matches(tmp_path, text):
    result = _tool(scan_repo)(str(_tree(tmp_path, {"a.py": text})))
    assert "MIKE" not in _families(result)


@pytest.mark.parametrize("value", ["MIKEY", "MIKEY-SAKKE", "mike smith"])
def test_the_classifier_api_does_not_read_mike_into_a_word(value):
    finding = fingerprint(FingerprintRequest(asset_name="x", algorithms=[value])).findings[0]
    assert finding.algorithm_family != "MIKE"


def test_the_reason_carries_what_is_known(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "a.go": 'import "github.com/cloudflare/circl/dh/csidh"\n'})))
    reason = result["findings"][0]["reason"]
    assert "CSIDH-512" in reason and "not a classical break" in reason


def test_sike_stays_broken_beside_csidh(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "a.c": "sikep434_keygen();\ncsidh_private(&priv);\n"})))
    found = _families(result)
    assert found["SIKE"][1] == "broken"
    assert found["CSIDH/CTIDH"] == RESEARCH
    assert result["summary"]["pqc_readiness"] == "broken_pqc_present"


def test_list_algorithms_and_the_cbom(tmp_path):
    table = {a["family"]: a["classification"] for a in _tool(list_algorithms)()["algorithms"]}
    assert table["MIKE"] == "pqc_pre_standard"
    assert table["CSIDH/CTIDH"] == "pqc_pre_standard"
    doc = _tool(export_cbom)(str(_tree(tmp_path, {"nike.c": "mike_exchange(ss, pk, sk);\n"})))
    mike = next(c for c in doc["components"] if c["name"] == "MIKE")
    # A non-interactive key exchange, not a KEM.
    assert mike["cryptoProperties"]["algorithmProperties"]["primitive"] == "key-agree"
    props = {p["name"]: p["value"] for p in mike["properties"]}
    assert props["qrp:pqc_status"] == "research"
    assert props["qrp:classification"] == "pqc_pre_standard"
