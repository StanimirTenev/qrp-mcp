"""Deprecated TLS versions reach the summary (ZA-OPRAVYANE row 63, the summary probe of
22.10.2026).

`evidence.protocols` said TLSv1.0 and TLSv1.1 were configured, `deprecated: true`, and the
summary had no field that carried them: a reader of the summary saw no weakness. The
summary now lists `deprecated_protocols`, the versions enabled somewhere in the tree. A
version struck out (`-TLSv1`) is not enabled and is not listed. Not folded into
`weak_count`, which counts keys and algorithms.
"""

from qrp_mcp.scan import scan_directory


def test_enabled_deprecated_versions_are_listed(tmp_path):
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n}\n")
    (tmp_path / "a.conf").write_text("SSLProtocol TLSv1.2 -SSLv3\n")
    summary = scan_directory(tmp_path)["summary"]
    assert summary["deprecated_protocols"] == ["TLSv1.0", "TLSv1.1"]


def test_none_when_none_is_enabled(tmp_path):
    (tmp_path / "nginx.conf").write_text("server {\n  ssl_protocols TLSv1.2 TLSv1.3;\n}\n")
    assert scan_directory(tmp_path)["summary"]["deprecated_protocols"] == []
