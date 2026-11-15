"""Row 464 (15.11.2026, QCI CBOM-Benchmark 2.6.6 cross-run): an openssl.cnf was read and gave no
evidence for `default_bits = 1024`, `default_md = sha1` or `MinProtocol = TLSv1` / `TLSv1.3`.
From OpenSSL's manuals: req(1) default_bits (the RSA size `openssl req` uses when none is
given, [req] only), req(1)/ca(1) default_md, SSL_CONF_cmd(3) MinProtocol/MaxProtocol. The
fixture is written here after the shape of QCI's `corpus/tier4/assets/tls/openssl.cnf`
(Apache-2.0); no file is copied.
"""

import json
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

CNF = """# build image OpenSSL configuration
openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1
MaxProtocol = TLSv1.3
CipherString = DEFAULT@SECLEVEL=1

[ req ]
default_bits       = 1024
default_md         = sha1
# default_md       = md5
distinguished_name = req_distinguished_name

[ CA_default ]
default_bits = 4096
default_md   = sha256
"""


def _check(result):
    rows = {(o["line"], o["algorithm"]): o for o in result["evidence"]["source_code"]}
    assert rows[(16, "RSA")]["key_size"] == 1024
    assert (17, "SHA1") in rows
    # A comment configures nothing; default_bits outside [req] is not req's; sha256 is not named.
    assert not any(line in (18, 22, 23) for line, _ in rows), rows
    versions = {(p["line"], p["version"]) for p in result["evidence"]["protocols"]}
    assert (11, "TLSv1.0") in versions and (12, "TLSv1.3") in versions, versions
    assert result["algorithm_key_sizes"]["RSA"] == 1024
    assert result["summary"]["weak_count"] >= 1


def test_openssl_cnf_keys_and_protocols(tmp_path):
    (tmp_path / "openssl.cnf").write_text(CNF)
    result = scan_directory(tmp_path)
    _check(result)
    tls = [p for p in result["evidence"]["protocols"] if p["line"] == 11]
    assert tls[0]["deprecated"] is True and "lowest" in tls[0]["description"]


def _bom_has(bom):
    names = {c["name"] for c in bom["components"]}
    assert {"RSA-1024", "SHA1", "TLSv1.0", "TLSv1.3"} <= names, names


def test_openssl_cnf_on_every_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "openssl.cnf").write_text(CNF)
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    _check(json.loads(out.read_text()))
    _bom_has(json.loads(bom.read_text()))
    _check(getattr(scan_repo, "fn", scan_repo)(str(src)))
    tool_bom = getattr(export_cbom, "fn", export_cbom)(str(src))
    _bom_has(tool_bom if isinstance(tool_bom, dict) else json.loads(tool_bom))
    _bom_has(build(scan_directory(src)))


def test_the_settings_are_read_only_in_an_openssl_config(tmp_path):
    (tmp_path / "app.ini").write_text("[req]\ndefault_bits = 1024\ndefault_md = sha1\n")
    result = scan_directory(tmp_path)
    assert not any(o["algorithm"] == "RSA" for o in result["evidence"]["source_code"])
