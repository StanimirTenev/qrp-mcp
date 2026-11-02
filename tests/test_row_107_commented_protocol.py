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
