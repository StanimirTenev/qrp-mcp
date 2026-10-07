"""Where a post-quantum scheme stands decides what the summary may say.

Three findings raised in public on 5 Oct 2026, each reproduced on 0.28.0 (4a59058)
before anything was changed:

- Row 8 (Mehrdad Daei): round-3 Kyber was reported as standardised ML-KEM. FIPS 203,
  Appendix C: ML-KEM uses a different Fujisaki-Okamoto variant from the round-3
  submission (no hash of the ciphertext into the shared key, m not hashed), so the
  two do not interoperate. `from pqcrypto.kem import kyber768` and
  `X25519Kyber768Draft00` both came out `ML-KEM / standardised / pqc_ready`.
- Row 9 (Bill Buchanan): HQC is `selected` -- chosen, standard not published -- and
  was counted `pqc_ready`. An implementation of today's specification need not match
  the standard; FIPS 203 itself changed between its 2023 draft and the final text.
- Row 11 (Larisa Ghazaryan): a file holding only SIKE, a broken scheme, gave
  `summary.pqc_readiness = no_quantum_vulnerable_detected` -- the most reassuring
  thing the summary can say, about the one scheme in the table with a public break.

Every check runs the way a user reaches it: the CLI writing a file, the MCP tools,
the CBOM export and, for Kyber, closure.
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
    """The same tree through the CLI file and through the MCP tool."""
    tree = _tree(tmp_path / "tree", files)
    return [_cli(tree, tmp_path / "out.json"), _tool(scan_repo)(str(tree))]


def _families(result: dict) -> dict[str, tuple]:
    return {f["algorithm_family"]: (f.get("pqc_status"), f["classification"])
            for f in result["findings"]}


# ---------------------------------------------------------------------------
# Row 11: a broken post-quantum scheme never yields a reassuring summary
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("text", [
    "k = sikep434_keygen()\n",
    # Withdrawn, the same branch: HAWK must not read as nothing found either.
    "sig = hawk_512_sign(sk, msg)\n",
])
def test_broken_pqc_alone_is_named_in_the_summary(tmp_path, text):
    for result in _both(tmp_path, {"a.py": text}):
        assert result["summary"]["pqc_readiness"] == "broken_pqc_present"
        assert result["summary"]["broken_pqc_count"] == 1


@pytest.mark.parametrize("extra", [
    "pk = mlkem768_keygen()\n",          # beside a standard: not "pqc_ready"
    "from Crypto.PublicKey import RSA\n",  # beside a classical one: still named
])
def test_broken_pqc_is_not_hidden_by_what_sits_beside_it(tmp_path, extra):
    result = _tool(scan_repo)(str(_tree(tmp_path, {"a.py": "k = sikep434_keygen()\n" + extra})))
    assert result["summary"]["pqc_readiness"] == "broken_pqc_present"


def test_md5_alone_is_not_broken_pqc():
    """The discriminator is the post-quantum status, not `deprecated_weak` alone."""
    summary = fingerprint(FingerprintRequest(asset_name="x", algorithms=["MD5"])).summary
    assert summary.pqc_readiness == "no_quantum_vulnerable_detected"
    assert summary.broken_pqc_count == 0


def test_list_algorithms_does_not_call_sike_ready():
    table = {a["family"]: a["classification"] for a in _tool(list_algorithms)()["algorithms"]}
    assert table["SIKE"] == "deprecated_weak"
    assert table["HAWK"] == "deprecated_weak"


# ---------------------------------------------------------------------------
# Row 9: chosen is not published
# ---------------------------------------------------------------------------
def test_hqc_is_pre_standard_not_ready(tmp_path):
    for result in _both(tmp_path, {"a.py": "kp = hqc_128_keypair()\n"}):
        assert _families(result)["HQC"] == ("selected", "pqc_pre_standard")
        assert result["summary"]["pqc_readiness"] == "pqc_pre_standard"
        assert result["summary"]["pqc_ready_count"] == 0
        assert result["summary"]["pqc_pre_standard_count"] == 1


def test_a_candidate_is_pre_standard_too(tmp_path):
    """One rule, not one family: a candidate cannot read as more ready than a
    selected scheme."""
    result = _tool(scan_repo)(str(_tree(tmp_path, {"a.py": "k = bike_l1_keygen()\n"})))
    assert _families(result)["BIKE"] == ("candidate", "pqc_pre_standard")


def test_pre_standard_beside_classical_is_not_hybrid_partial(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "a.py": "kp = hqc_128_keypair()\nfrom Crypto.PublicKey import RSA\n"})))
    assert result["summary"]["pqc_readiness"] == "hybrid_pre_standard"


def test_pqc_ready_only_when_every_scheme_is_standardised(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "a.py": "pk = mlkem768_keygen()\nkp = hqc_128_keypair()\n"})))
    assert result["summary"]["pqc_readiness"] == "pqc_pre_standard"
    assert result["summary"]["pqc_ready_count"] == 1


def test_list_algorithms_says_pre_standard():
    table = {a["family"]: a["classification"] for a in _tool(list_algorithms)()["algorithms"]}
    assert table["HQC"] == "pqc_pre_standard"
    assert table["ML-KEM"] == "pqc_ready"


def test_the_cbom_carries_pre_standard(tmp_path):
    doc = _tool(export_cbom)(str(_tree(tmp_path, {"a.py": "kp = hqc_128_keypair()\n"})))
    hqc = next(c for c in doc["components"] if c["name"] == "HQC")
    props = {p["name"]: p["value"] for p in hqc["properties"]}
    assert props["qrp:classification"] == "pqc_pre_standard"
    assert props["qrp:pqc_status"] == "selected"


# ---------------------------------------------------------------------------
# Row 8: round-3 Kyber is not ML-KEM
# ---------------------------------------------------------------------------
KYBER_IDENTIFIERS = [
    ("a.py", "from pqcrypto.kem import kyber768\n"),
    ("a.py", "import pqcrypto.kem.kyber768 as kem\n"),
    ("nginx.conf", "ssl_ecdh_curve X25519Kyber768Draft00;\n"),
    ("a.c", "pqcrystals_kyber768_ref_keypair(pk, sk);\n"),
    ("a.c", "OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);\n"),
    ("a.go", 'import "github.com/cloudflare/circl/kem/kyber/kyber768"\n'),
    ("a.c", "crypto_kem_keypair_kyber768(pk, sk);\n"),
]


@pytest.mark.parametrize("name, text", KYBER_IDENTIFIERS)
def test_a_kyber_identifier_is_pre_standard_kyber(tmp_path, name, text):
    for result in _both(tmp_path, {name: text}):
        found = _families(result)
        assert "ML-KEM" not in found, found
        assert found["Kyber"] == ("superseded", "pqc_pre_standard")
        assert result["summary"]["pqc_ready_count"] == 0


@pytest.mark.parametrize("name, text", [
    ("nginx.conf", "ssl_ecdh_curve X25519MLKEM768;\n"),
    ("a.go", 'import "crypto/mlkem"\nfunc f() { k, _ := mlkem.GenerateKey768() }\n'),
    ("a.py", "kem = ml_kem_768.keygen()\n"),
])
def test_ml_kem_stays_standardised(tmp_path, name, text):
    """Positive control: the fix must not cost ML-KEM its standing."""
    for result in _both(tmp_path, {name: text}):
        found = _families(result)
        assert found["ML-KEM"] == ("standardised", "pqc_ready")
        assert "Kyber" not in found


def test_bare_kyber_is_not_counted_as_standardised(tmp_path):
    """The decision for the word alone. `kyber` with no identifier is the name of the
    round-3 scheme, and also an old name people still use for ML-KEM; the line does
    not say which. Reported as Kyber (pre-standard): the cost of being wrong that way
    is an under-claim the reason explains, and the cost of the other way is a
    standard claimed for code that may not interoperate with it."""
    result = _tool(scan_repo)(str(_tree(tmp_path, {"a.py": "ct, ss = kyber.encapsulate(pk)\n"})))
    assert _families(result) == {"Kyber": ("superseded", "pqc_pre_standard")}


def test_a_line_that_names_ml_kem_resolves_the_old_name(tmp_path):
    """`ML-KEM (Kyber)` names the standard and gives its old name; it is ML-KEM."""
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "a.py": 'ALG = "ML-KEM-768"  # ML-KEM (Kyber)\n'})))
    assert "Kyber" not in _families(result)


def test_the_classifier_api_reads_the_draft_hybrid_as_kyber():
    finding = fingerprint(FingerprintRequest(
        asset_name="x", algorithms=["X25519Kyber768Draft00"])).findings[0]
    assert (finding.algorithm_family, finding.classification) == ("Kyber", "pqc_pre_standard")
    assert "X25519" in finding.also_present


def test_the_cbom_calls_kyber_a_kem(tmp_path):
    doc = _tool(export_cbom)(str(_tree(tmp_path, {"a.py": "from pqcrypto.kem import kyber768\n"})))
    kyber = next(c for c in doc["components"] if c["name"] == "Kyber")
    assert kyber["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem"
    props = {p["name"]: p["value"] for p in kyber["properties"]}
    assert props["qrp:pqc_status"] == "superseded"


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_closure_sees_the_move_from_kyber_to_ml_kem(tmp_path):
    tree = _tree(tmp_path / "tree", {"nginx.conf": "ssl_ecdh_curve X25519Kyber768Draft00;\n"})
    _git(tree, "init", "-q")
    _git(tree, "add", "-A")
    _git(tree, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "before")
    scans = []
    for label in ("before", "after"):
        if label == "after":
            (tree / "nginx.conf").write_text("ssl_ecdh_curve X25519MLKEM768;\n")
            _git(tree, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "after")
        data = _cli(tree, tmp_path / f"{label}.json")
        # The instrument is this dirty working tree; pin both runs to one name.
        data["coverage"]["instrument"]["source_commit"] = {
            "pinned": True, "commit": "instrument", "dirty": False}
        (tmp_path / f"{label}.json").write_text(json.dumps(data))
        scans.append(tmp_path / f"{label}.json")
    out = tmp_path / "closure.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "closure", *map(str, scans),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    verdict = json.loads(out.read_text())
    assert verdict["comparability"]["verdict"] == "comparable"
    per_family = verdict["closure"]["per_family_before_after"]
    assert per_family["Kyber"] == [1, 0]
    assert per_family["ML-KEM"] == [0, 1]
