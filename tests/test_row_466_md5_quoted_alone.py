"""Row 466 (15.11.2026, QCI CBOM-Benchmark 2.6.6 cross-run): a hash literal passed to a wrapper
or held in a constant was not reported -- `digest("MD5", ...)`, `static final String
AUDIT_DIGEST = "MD5"`, `AUDIT_DIGEST = "md5"` -- while `TOKEN_DIGEST = "sha1"` gave SHA1: the
rules disagreed. MD5 quoted alone is now read as SHA-1 quoted alone already was. Fixtures are
written here after the shape of QCI's T2Wrapper.java, AppModule.java and defaults.py
(Apache-2.0); no file is copied.
"""

import json
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

FILES = {
    "Wrapper.java": ("import java.security.MessageDigest;\n"
                     "class Wrapper {\n"
                     "  static byte[] digest(String a, byte[] d) throws Exception {\n"
                     "    return MessageDigest.getInstance(a).digest(d); }\n"
                     "  void m() throws Exception { byte[] etag = digest(\"MD5\", b); }\n"
                     "}\n", 5),
    "AppModule.java": ("final class AppModule {\n"
                       "    static final String AUDIT_DIGEST = \"MD5\";\n"
                       "}\n", 2),
    "defaults.py": ('"""Deployment defaults."""\n\nAUDIT_DIGEST = "md5"\n', 3),
    "settings.py": ('TOKEN_DIGEST = "sha1"\n', 1),   # the rule MD5 now agrees with
}


def _check(result):
    rows = {(o["path"], o["line"], o["algorithm"]) for o in result["evidence"]["source_code"]}
    for name, (_, line) in FILES.items():
        family = "SHA1" if name == "settings.py" else "MD5"
        assert (name, line, family) in rows, (name, rows)


def test_md5_quoted_alone_is_a_row(tmp_path):
    for name, (text, _) in FILES.items():
        (tmp_path / name).write_text(text)
    _check(scan_directory(tmp_path))


def test_md5_inside_a_longer_string_or_a_comment_is_not(tmp_path):
    (tmp_path / "n.py").write_text(
        'msg = "md5 checksum mismatch"\n'
        'name = "md5sum"\n'
        '# AUDIT_DIGEST = "md5"\n')
    rows = [o for o in scan_directory(tmp_path)["evidence"]["source_code"]
            if o["algorithm"] == "MD5" and o["evidence_kind"] != "comment"]
    assert rows == [], rows


def test_md5_quoted_alone_on_every_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for name, (text, _) in FILES.items():
        (src / name).write_text(text)
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    _check(json.loads(out.read_text()))
    _check(getattr(scan_repo, "fn", scan_repo)(str(src)))
    for b in (json.loads(bom.read_text()), build(scan_directory(src)),
              getattr(export_cbom, "fn", export_cbom)(str(src))):
        b = b if isinstance(b, dict) else json.loads(b)
        md5 = [c for c in b["components"] if c["name"] == "MD5"]
        assert md5 and {o["location"] for o in md5[0]["evidence"]["occurrences"]} >= {
            "Wrapper.java", "AppModule.java", "defaults.py"}
