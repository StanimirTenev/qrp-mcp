"""FreeRADIUS's bare TLS version (ZA-OPRAVYANE row 103b; Georgi Ivanov #12, EAP-TLS, probe
qrp-kachestvo/linkedin-2026-10-23/eap-tls). `tls_min_version = "1.0"` gave `protocols: []`;
the setting and its values are FreeRADIUS's own (raddb/mods-available/eap, v3.2.x). The file
itself is read since row 103a (test_extensionless_config_names.py)."""

from qrp_mcp.scan import scan_directory

EAP = """eap {
\tdefault_eap_type = tls
\ttls-config tls-common {
\t\tcipher_list = "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA"
\t\tecdh_curve = "prime256v1"
\t\t#\ttls_min_version = "1.2"
\t\ttls_min_version = "1.0"
\t}
}
"""


def test_eap_tls_minimum_is_a_deprecated_protocol(tmp_path):
    (tmp_path / "raddb" / "mods-available").mkdir(parents=True)
    (tmp_path / "raddb" / "mods-available" / "eap").write_text(EAP)
    result = scan_directory(tmp_path)
    versions = [(p["version"], p["line"]) for p in result["evidence"]["protocols"]
                if p.get("protocol") == "tls"]
    assert versions == [("TLSv1.0", 7)]
    assert result["summary"]["deprecated_protocols"] == ["TLSv1.0"]
