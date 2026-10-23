"""The summary says key establishment and signatures apart (ZA-OPRAVYANE row 100; Ivezic #19 on
LinkedIn, 23.10.2026; probe qrp-kachestvo/linkedin-2026-10-23/kex-vs-podpis).

nginx offering X25519MLKEM768 with an ECDSA certificate read `hybrid_partial` and nothing
else: true of the whole, silent on which half is post-quantum. The roles were already read
for RSA and EC (`scan._read_roles`); the rest have the classifier's own kind.
"""

from qrp_mcp.scan import scan_directory

NGINX = """server {
    listen 443 ssl;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519MLKEM768;
}
"""


def test_kex_post_quantum_signature_classical(tmp_path):
    (tmp_path / "nginx.conf").write_text(NGINX)
    (tmp_path / "sign.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "sig = key.sign(data, ec.ECDSA(hashes.SHA256()))\n")
    by_role = scan_directory(tmp_path)["summary"]["by_role"]
    assert by_role["key_establishment"]["pqc_readiness"] == "hybrid_partial"
    assert "ML-KEM" in by_role["key_establishment"]["families"]
    assert by_role["signature"]["pqc_readiness"] == "classical_only"
    assert "ECDSA" in by_role["signature"]["families"]


def test_rsa_goes_where_its_lines_say(tmp_path):
    (tmp_path / "Sign.java").write_text(
        'Signature s = Signature.getInstance("SHA256withRSA");\n')
    (tmp_path / "kem.py").write_text("import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')\n")
    by_role = scan_directory(tmp_path)["summary"]["by_role"]
    assert by_role["signature"] == {"families": ["RSA"], "pqc_readiness": "classical_only"}
    assert by_role["role_not_determined"] == []
    assert by_role["key_establishment"] == {"families": ["ML-KEM"], "pqc_readiness": "pqc_ready"}


def test_a_part_with_nothing_says_so(tmp_path):
    (tmp_path / "nginx.conf").write_text(NGINX)
    by_role = scan_directory(tmp_path)["summary"]["by_role"]
    assert by_role["signature"] == {"families": [], "pqc_readiness": "none_found"}


def test_a_reassuring_part_is_withheld_with_the_whole(tmp_path):
    (tmp_path / "kem.py").write_text("import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')\n")
    (tmp_path / "edge.tmpl").write_text("curves x25519\n")      # a type no reader claims
    summary = scan_directory(tmp_path)["summary"]
    assert summary["pqc_readiness"] == "not_established"
    assert summary["by_role"]["key_establishment"]["pqc_readiness"] == "not_established"
