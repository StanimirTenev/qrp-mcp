"""A comment is not a use (ZA-OPRAVYANE row 45, the network-vs-code probe of 22.10.2026).

The probe counted two comments as uses: `# Hybrid post-quantum key exchange first,
classical X25519 as fallback.` above HAProxy's curves line, and `# TLS 1.3 only, hybrid
ML-KEM group preferred.` in an nginx file whose server, on the wire, did not offer
ML-KEM at all. Restated and reproduced against 0.32.0: the scanner already marks both
`evidence_kind: comment`, keeps them out of `detected_algorithms`, out of the TLS
places, and tags them `[comment]` in the CBOM. The count that carried them unmarked
was qrp-dora's CBOM, which rebuilt the occurrences and dropped the tag. This test pins
the scanner's side so it stays that way.
"""

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

FILES = {
    "haproxy.cfg": ("global\n"
                    "    # Hybrid post-quantum key exchange first, classical X25519 as fallback.\n"
                    "    ssl-default-bind-curves X25519MLKEM768:X25519\n"),
    "nginx.conf": ("# TLS 1.3 only, hybrid ML-KEM group preferred.\n"
                   "server {\n    ssl_protocols TLSv1.3;\n}\n"),
}


def test_the_probe_comments_are_marked_and_not_counted(tmp_path):
    for name, text in FILES.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    result = scan_directory(tmp_path)
    comments = {(f["path"], f["line"], f["algorithm"]) for f in result["evidence"]["source_code"]
                if f["evidence_kind"] == "comment"}
    assert comments == {("haproxy.cfg", 2, "X25519"), ("nginx.conf", 1, "ML-KEM")}
    # ML-KEM is named only in the nginx comment and on the HAProxy line: it stays in the
    # inventory from the HAProxy line, not from the comment.
    assert "ML-KEM" in result["detected_algorithms"]
    places = {(p["path"], p["line"]) for p in result["tls_termination"]["configured_in"]}
    assert ("haproxy.cfg", 2) not in places and ("nginx.conf", 1) not in places
    contexts = [o["additionalContext"] for c in build(result)["components"]
                for o in c.get("evidence", {}).get("occurrences", [])
                if (o["location"], o["line"]) in {("haproxy.cfg", 2), ("nginx.conf", 1)}]
    assert contexts and all(c.startswith("[comment]") for c in contexts)


def test_a_family_named_only_in_a_comment_is_not_detected(tmp_path):
    (tmp_path / "nginx.conf").write_text("# hybrid ML-KEM group preferred\nserver {}\n")
    result = scan_directory(tmp_path)
    assert "ML-KEM" not in result["detected_algorithms"]
    assert "ML-KEM" in result["named_but_not_used"]
