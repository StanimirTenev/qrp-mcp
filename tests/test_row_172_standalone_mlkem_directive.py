"""ZA-OPRAVYANE row 172(a): `ssl_ecdh_curve MLKEM768;` -- a post-quantum group alone -- reported
ECDH, which is not there, because the directive's name says `ecdh`; the tree read
`hybrid_partial`. On a group setting the family comes from the values, not the setting's name."""

from qrp_mcp.scan import scan_directory


def _scan(tmp_path, value):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "nginx.conf").write_text(f"server {{\n    listen 443 ssl;\n    ssl_ecdh_curve {value};\n}}\n")
    return scan_directory(t)


def _families(r):
    return {e["algorithm"] for e in r["evidence"]["source_code"] if e["line"] == 3}


def test_mlkem_alone_is_not_ecdh(tmp_path):
    r = _scan(tmp_path, "MLKEM768")
    assert _families(r) == {"ML-KEM"}
    assert r["summary"]["pqc_readiness"] != "hybrid_partial"


def test_a_classical_value_still_gives_ecdh(tmp_path):
    assert "ECDH" in _families(_scan(tmp_path, "secp384r1"))


def test_a_hybrid_keeps_its_classical_half(tmp_path):
    fams = _families(_scan(tmp_path, "X25519MLKEM768"))
    assert {"X25519", "ML-KEM"} <= fams


def test_a_table_naming_the_directive_keeps_its_row(tmp_path):
    # Corpus regression, 30.10.2026: nginxinc/crossplane analyzer.py lists nginx directives.
    t = tmp_path / "repo"
    t.mkdir()
    (t / "analyzer.py").write_text("DIRECTIVES = {\n    'ssl_ecdh_curve': [\n        NGX_CONF,\n    ],\n}\n")
    r = scan_directory(t)
    assert "ECDH" in {e["algorithm"] for e in r["evidence"]["source_code"] if e["line"] == 2}
