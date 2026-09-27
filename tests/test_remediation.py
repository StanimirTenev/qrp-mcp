"""Replacement suggestions: every family is either covered or explicitly not, and nothing is invented."""

from qrp_mcp import remediation
from qrp_mcp.classifier import FingerprintRequest, fingerprint, known_algorithms


def _find(alg):
    return fingerprint(FingerprintRequest(asset_name="x", algorithms=[alg])).findings[0].model_dump()


def test_every_classical_family_has_a_row():
    classical = {a["family"] for a in known_algorithms() if a["classification"] == "classical_vulnerable"}
    assert classical <= remediation.covered_families(), classical - remediation.covered_families()


def test_post_quantum_gets_nothing():
    for a in known_algorithms():
        if a["classification"] in ("pqc_ready", "quantum_resistant_mechanism"):
            f = {"classification": a["classification"], "algorithm_family": a["family"]}
            assert remediation.suggest(f) is None, a["family"]


def test_key_exchange_gets_ml_kem_only():
    s = remediation.suggest(_find("X25519"))
    assert [o["for"] for o in s["options"]] == ["key establishment"]
    assert s["options"][0]["sources"][0]["standard"] == "FIPS 203"


def test_rsa_role_unknown_gets_both():
    fors = {o["for"] for o in remediation.suggest(_find("RSA"))["options"]}
    assert "key establishment" in fors and "signatures" in fors


def test_weak_rsa_is_two_steps():
    s = remediation.suggest(_find("RSA-1024"))
    assert s["note"].startswith("Two steps") and s["sources_first_step"][0]["standard"] == "SP 800-131A r2"


def test_bls_says_no_drop_in_replacement():
    s = remediation.suggest(_find("BLS"))
    assert s["options"] == [] and "No approved drop-in replacement" in s["note"]


def test_weak_primitives_by_classifier_token():
    for alg in ("MD5", "SHA1", "RC4", "DES", "3DES", "TRIPLEDES"):
        assert remediation.suggest(_find(alg)) is not None, alg


def test_unstandardised_pqc_points_to_standards():
    s = remediation.suggest(_find("SIKE"))
    assert {c["standard"] for c in s["options"][0]["sources"]} == {"FIPS 203", "FIPS 204", "FIPS 205"}


def test_every_citation_has_an_address():
    for name, (what, url) in remediation.SOURCES.items():
        assert url.startswith("https://") and what, name


def test_suggestion_is_never_an_action():
    s = remediation.suggest(_find("ECDSA"))
    assert s["kind"] == "suggestion, not applied"


def test_scan_attaches_replacement_only_where_due(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "a.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                                   "k = rsa.generate_private_key(65537, 2048)\n")
    r = scan_directory(tmp_path)
    rsa = [f for f in r["findings"] if f["algorithm_family"] == "RSA"]
    assert rsa and "replacement" in rsa[0]
    assert all("replacement" not in f for f in r["findings"] if f["classification"] == "pqc_ready")
