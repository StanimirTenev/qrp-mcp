"""Rows 224, 301 and 230 (04.11.2026): a PEM block inside a value or a string.

224: a FortiOS backup keeps its certificates as `set certificate "-----BEGIN CERTIFICATE-----`
... `-----END CERTIFICATE-----"`; the `.conf` was read and gave nothing, and the verdict said
every file was read. 301: the same certificate in a C# raw string (indented) and a verbatim
string, in a Go raw-string constant, in source concatenated with `+`: nothing. The blocks are
now put together from their base64 and parsed in any file read as text; one that does not
parse is named in `examined_partly`. RFC 7468 (https://www.rfc-editor.org/rfc/rfc7468) is the
textual encoding: the label line, base64, the end line; whitespace in the body is not data.

230: a private-key block in a `.conf` whose body is not a key got `confidence: high`, "key
material parsed". It now carries `key_unread` and the medium level the `.pem` path gives."""

from __future__ import annotations

import shutil
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures" / "b042"


def _certs(result):
    return {(e["path"], e["line"], e["algorithm"], e.get("key_size"))
            for e in result["evidence"]["source_code"] if e.get("certificate")}


def test_certificate_in_a_fortios_set_value(tmp_path):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURES / "forti-cert.conf", tmp_path / "forti.conf")
    assert _certs(scan_directory(tmp_path)) == {("forti.conf", 3, "RSA", 2048)}


def test_certificate_in_csharp_raw_and_verbatim_strings(tmp_path):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURES / "Certs.cs", tmp_path / "Certs.cs")
    assert _certs(scan_directory(tmp_path)) == {("Certs.cs", 3, "RSA", 2048),
                                               ("Certs.cs", 24, "RSA", 2048)}


def test_certificate_concatenated_in_source(tmp_path):
    from qrp_mcp.scan import scan_directory
    body = (FIXTURES / "forti-cert.conf").read_text().split("-----")[2].split()
    joined = ' +\n    "'.join(f'{line}"' for line in body)
    (tmp_path / "cert.js").write_text(
        'const ca = "-----BEGIN CERTIFICATE-----" +\n    "' + joined
        + ' +\n    "-----END CERTIFICATE-----";\n')
    assert _certs(scan_directory(tmp_path)) == {("cert.js", 1, "RSA", 2048)}


def test_a_broken_block_in_source_is_named(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "c.go").write_text(
        "package c\n\nconst ca = `-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----`\n")
    result = scan_directory(tmp_path)
    assert not _certs(result)
    items = result["coverage"]["examined_partly"]["items"]
    assert [(i["path"], i["line"], i["reason"]) for i in items] == [
        ("c.go", 3, "not_parsed_as_certificate")]


def test_unparsed_key_in_a_conf_is_not_called_parsed(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "fw.conf").write_text(
        'config vpn certificate local\n    edit "k"\n'
        '        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
        'ZmFrZS1wcml2YXRlLWtleS1ub3QtcmVhbA==\n-----END ENCRYPTED PRIVATE KEY-----"\n'
        '    next\nend\n')
    result = scan_directory(tmp_path)
    [key] = result["evidence"]["embedded_keys"]
    assert key["key_unread"] == "body_not_a_key"
    assert key["confidence"] == "medium"
    assert key["confidence_basis"] != "key material parsed"
    items = result["coverage"]["examined_partly"]["items"]
    assert [(i["path"], i["reason"]) for i in items] == [("fw.conf", "not_parsed_as_key")]


def test_marker_strings_in_code_are_not_a_block(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "t.py").write_text(
        'def is_pem(s):\n    return s.startswith("-----BEGIN CERTIFICATE-----") and \\\n'
        '        s.rstrip().endswith("-----END CERTIFICATE-----")\n')
    result = scan_directory(tmp_path)
    assert result["coverage"]["examined_partly"]["items"] == []


def test_a_certificate_on_a_line_that_names_its_family(tmp_path):
    """Found by the positive control on Vault (`path_issue_sign_test.go:1082`,
    `const ed25519CaAndKey = \`-----BEGIN CERTIFICATE-----`): the decoded certificate row
    (key_size 256) and the family named by the identifier on the same line (no size) at one
    place broke the sort under `findings_fingerprint`, and the scan raised."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID
    from qrp_mcp.scan import scan_directory
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.datetime(2026, 1, 1)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, None))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode().strip()
    (tmp_path / "c_test.go").write_text(
        "package c\n\nconst ed25519CaAndKey = `" + pem + "`\n")
    result = scan_directory(tmp_path)
    assert result["findings_fingerprint"]["sha256"]
