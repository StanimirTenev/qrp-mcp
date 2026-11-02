"""ZA-OPRAVYANE row 111 (agent 0.35.0, 23.10.2026): a Caddyfile is read since 0.35.0 and
`x25519` in it is found, but its `curves` and `protocols` lines were not a TLS place: no
group row, no TLS version, nothing in tls_termination. Caddy's `tls` directive: `curves
<curves...>` and `protocols <min> [<max>]` with values `tls1.2`, `tls1.3`
(caddyserver.com/docs/caddyfile/directives/tls)."""

import json
import subprocess
import sys

CADDYFILE = ("example.com {\n"
             "\ttls {\n"
             "\t\tcurves x25519 secp256r1\n"
             "\t\tprotocols tls1.2 tls1.3\n"
             "\t}\n"
             "}\n")


def _scan(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "Caddyfile").write_text(CADDYFILE, encoding="utf-8")
    out = tmp_path / "scan.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out), "--level", "full"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def test_the_curves_line_is_a_group_setting(tmp_path):
    result = _scan(tmp_path)
    groups = {(g["line"], g["group"]) for g in result["evidence"]["tls_groups"]}
    assert (3, "x25519") in {(n, g.lower()) for n, g in groups}
    places = {(p["line"], p["basis"]) for p in result["tls_termination"]["configured_in"]}
    assert (3, "configured_group") in places


def test_the_protocols_line_names_its_versions(tmp_path):
    result = _scan(tmp_path)
    versions = [(a["line"], a["version"]) for a in result["evidence"]["protocols"]]
    assert versions == [(4, "TLSv1.2"), (4, "TLSv1.3")]
    places = {(p["line"], p["basis"]) for p in result["tls_termination"]["configured_in"]}
    assert (4, "configured_protocol") in places


def test_prose_with_the_word_is_not_a_setting(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "notes.md").write_text("Elliptic curves are fast; x25519 is one.\n"
                                   "protocols are tls1.2 and tls1.3 here.\n", encoding="utf-8")
    from qrp_mcp.scan import scan_directory
    result = scan_directory(str(tree))
    assert result["evidence"]["protocols"] == []
    assert result["evidence"]["tls_groups"] == []
