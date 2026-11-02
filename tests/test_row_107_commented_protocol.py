"""ZA-OPRAVYANE row 107 (agent 0.35.0, 23.10.2026): certbot keeps
`#	ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;` in an nginx sites-available/default, and
since that file is read (0.35.0) the commented line gave four protocol assets -- SSLv3 and
TLS 1.0/1.1 among the deprecated ones. A commented setting configures nothing; the group,
cipher and SSH scanners beside it already skip such a line."""

import json
import subprocess
import sys


def test_a_commented_ssl_protocols_line_is_not_a_protocol_setting(tmp_path):
    tree = tmp_path / "t"
    site = tree / "nginx" / "sites-available"
    site.mkdir(parents=True)
    (site / "default").write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "#\tssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;\n"
        "    ssl_protocols TLSv1.3;\n"
        "}\n", encoding="utf-8")
    out = tmp_path / "scan.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out), "--level", "full"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    result = json.loads(out.read_text())
    protocols = result["evidence"]["protocols"]
    assert [(a["line"], a["version"]) for a in protocols] == [(4, "TLSv1.3")]
    assert result["summary"]["deprecated_protocols"] == []


def test_a_known_hosts_pattern_starting_with_a_star_is_not_a_comment(tmp_path):
    """OpenSSH's regress/unittests/hostkeys/testdata/known_hosts:12-14 begin with the host
    pattern `*.example.com,...`; the positive control on OpenSSH showed them dropped by the
    first form of this fix."""
    from qrp_mcp.scan import scan_directory
    (tmp_path / "known_hosts").write_text(
        "*.example.com,192.0.2.* ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIBlYfExtYZAPqYvYdrlpGlSWxh4jWbCs\n"
        "# ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDX8F93W3SH4ZSus4XUQ2c\n", encoding="utf-8")
    protocols = scan_directory(str(tmp_path))["evidence"]["protocols"]
    assert [(a["line"], a["protocol"]) for a in protocols] == [(1, "ssh")]
