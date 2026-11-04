"""Postfix main.cf and master.cf are read (ZA-OPRAVYANE row 336; fixture L2/12-postfix). On
0.41.0 `.cf` was skipped by type. postconf(5), https://www.postfix.org/postconf.5.html (read
04.11.2026): smtpd_tls_protocols "TLS protocols accepted by the Postfix SMTP server with
opportunistic TLS encryption." ... "The valid protocol names (see SSL_get_version(3)) are
"SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2" and "TLSv1.3"." ... "To require at least
TLS 1.0, set "smtpd_tls_protocols = !SSLv2, !SSLv3"." ... "To set the lower bound include an
element of the form: ">=version"". smtpd_tls_mandatory_protocols, smtp_tls_protocols and
lmtp_tls_protocols take the same syntax.

Not read (the minimum): the cipher grade (`smtpd_tls_mandatory_ciphers = low`), the versions
an exclusion list leaves enabled, and the size of a DH parameter file named by path.
"""

from qrp_mcp.scan import scan_directory

MAIN_CF = """smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3
smtpd_tls_mandatory_protocols = TLSv1
smtp_tls_protocols = >=TLSv1.1
lmtp_tls_mandatory_protocols = >=TLSv1.2, <=TLSv1.3
tls_ffdhe_auto_groups = ffdhe2048
"""


def test_main_cf_protocols(tmp_path):
    (tmp_path / "main.cf").write_text(MAIN_CF)
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["main.cf"]
    rows = sorted((p["line"], p["version"], p["banned"]) for p in result["evidence"]["protocols"]
                  if p.get("version"))
    assert rows == [(2, "SSLv2", True), (2, "SSLv3", True), (3, "TLSv1.0", False),
                    (4, "TLSv1.1", False), (5, "TLSv1.2", False), (5, "TLSv1.3", False)]
    assert result["summary"]["deprecated_protocols"] == ["TLSv1.0", "TLSv1.1"]


def test_master_cf_is_read(tmp_path):
    (tmp_path / "master.cf").write_text(
        "submission inet n - y - - smtpd\n  -o smtpd_tls_mandatory_protocols=TLSv1.1\n")
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["master.cf"]
    # master.cf overrides a main.cf setting per service with `-o name=value`.
    assert [(p["line"], p["version"]) for p in result["evidence"]["protocols"]] == [(2, "TLSv1.1")]


def test_other_cf_files_stay_unclaimed(tmp_path):
    (tmp_path / "other.cf").write_text(MAIN_CF)
    result = scan_directory(tmp_path)
    assert result["files_skipped_by_type"] == {".cf": 1}
