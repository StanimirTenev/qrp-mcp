"""ZA-OPRAVYANE rows 164 and 167 (Daniel Stokes). A pyOpenSSL server that sets no group gave no
key-exchange row and `pqc_readiness: unknown`, the same word an empty directory gets; yet the
handshake was X25519 with cryptography 42.0.5 and X25519MLKEM768 with 45.0.4. The scan cannot
resolve the default; it now says that it applies and is not resolved, with the pinned library
version beside it, and the headline is `not_established` with that reason.
"""

import json

from qrp_mcp import server
from qrp_mcp.scan import scan_directory

SERVER = ("from OpenSSL import SSL\n"
          "def make_context():\n"
          "    ctx = SSL.Context(SSL.TLS_METHOD)\n"
          "    ctx.set_min_proto_version(SSL.TLS1_3_VERSION)\n"
          "    return ctx\n")


def _tree(tmp_path, files):
    t = tmp_path / "repo"
    t.mkdir()
    for name, text in files.items():
        (t / name).write_text(text)
    return t


def test_tls_without_a_group_says_the_default_is_not_resolved(tmp_path):
    t = _tree(tmp_path, {"server.py": SERVER,
                         "requirements.txt": "pyOpenSSL==24.0.0\ncryptography==42.0.5\n"})
    r = scan_directory(t)
    kx = r["tls_termination"]["key_exchange"]
    assert kx["configured"] is False and "not resolve" in kx["statement"]
    assert {"package": "cryptography", "version": "42.0.5", "path": "requirements.txt",
            "line": 2} in kx["libraries_pinned"]
    tls = [p for p in r["evidence"]["protocols"] if p.get("protocol") == "tls"]
    assert tls and all("groups" in p["library_defaults"] for p in tls)
    s = r["summary"]
    assert s["pqc_readiness"] == "not_established"
    assert s["readiness_not_established"]["would_read"] == "unknown"
    assert any("library" in b for b in s["readiness_not_established"]["because"])
    assert s["by_role"]["key_establishment"]["pqc_readiness"] == "not_established"


def test_empty_tree_is_still_unknown(tmp_path):
    r = scan_directory(_tree(tmp_path, {"README.md": "nothing\n"}))
    assert r["summary"]["pqc_readiness"] == "unknown"
    assert r["summary"]["readiness_not_established"] is None


def test_a_configured_group_is_not_a_default(tmp_path):
    t = _tree(tmp_path, {"server.py": SERVER + 'ctx.set_ecdh_curve("prime256v1")\n'})
    r = scan_directory(t)
    assert "key_exchange" not in r["tls_termination"]
    assert r["summary"]["pqc_readiness"] != "not_established"


def test_the_flag_reaches_the_cbom(tmp_path):
    t = _tree(tmp_path, {"server.py": SERVER})
    out = tmp_path / "c.json"
    assert server.scan_to_file([str(t), "--out", str(out)], cbom=True) == 0
    tls = [c for c in json.loads(out.read_text())["components"]
           if c.get("cryptoProperties", {}).get("assetType") == "protocol"]
    props = [p for c in tls for p in c["properties"] if p["name"] == "qrp:library_defaults"]
    assert props and "groups" in props[0]["value"]
