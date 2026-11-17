"""Row 517, the first half (17.11.2026, Georgi Ivanov: who relies on a PQC certificate; probe
`linkedin-postove/2026-11-17/stai-qrp/proba-ivanov/r/`).

The roots were read (RSA-3072, P-384, `self_signed: true`), but nothing said who trusts them:
Python's `load_verify_locations(cafile=...)`, Go's `AppendCertsFromPEM` of a file read from
/etc, and nginx's `ssl_client_certificate` gave no output at all. `trust_stores` now lists each
place that loads a trust store: the file and line, the setting, the path it names, the files
read that path is (relative to the root or to the file's directory, as `tls_listeners` links a
certificate), the anchors in them with their families, and whether the path is outside the
tree. In the scan JSON, the MCP tools and the CBOM (`qrp:trust_stores`).

Bounded to these forms: Python `load_verify_locations` / `create_default_context` with a
`cafile`/`capath`, Go `AppendCertsFromPEM` with the path of an `os.ReadFile` in the ten lines
above, nginx `ssl_client_certificate` / `ssl_trusted_certificate`. Not claimed: Java
`TrustManagerFactory`/keystores, a system store chosen by default, or what a peer presents. A
path outside the tree is said, not put in `chosen_outside_files` (that block is for values read
at run time).
"""

import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

CLIENT = '''import ssl

def make_ctx():
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(cafile="trust/ca-bundle.pem")
    return ctx
'''
VERIFY = '''package app

import (
\t"crypto/x509"
\t"os"
)

func Pool() *x509.CertPool {
\tpem, _ := os.ReadFile("/etc/device/factory-root.pem")
\tpool := x509.NewCertPool()
\tpool.AppendCertsFromPEM(pem)
\treturn pool
}
'''
NGINX = '''server {
    listen 443 ssl;
    ssl_client_certificate /etc/nginx/trust/ca-bundle.pem;
    ssl_verify_client on;
}
'''


def _root(key, cn: str) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(len(cn)).not_valid_before(start)
            .not_valid_after(start + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA384()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _tree(root: Path) -> Path:
    files = {
        "app/client.py": CLIENT, "app/verify.go": VERIFY, "conf/nginx.conf": NGINX,
        "trust/ca-bundle.pem": _root(rsa.generate_private_key(public_exponent=65537,
                                                              key_size=3072), "Old Root")
        + _root(ec.generate_private_key(ec.SECP384R1()), "New Root"),
    }
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _short(result):
    return [(p["path"], p["line"], p["setting"], p["file"], p["file_read"], p["outside_the_tree"],
             [(a["family"], a.get("key_size")) for a in p["anchors"]])
            for p in result["trust_stores"]["places"]]


EXPECTED = [
    ("app/client.py", 5, "load_verify_locations", "trust/ca-bundle.pem",
     ["trust/ca-bundle.pem"], False, [("RSA", 3072), ("EC", 384)]),
    ("app/verify.go", 11, "AppendCertsFromPEM", "/etc/device/factory-root.pem", [], True, []),
    ("conf/nginx.conf", 3, "ssl_client_certificate", "/etc/nginx/trust/ca-bundle.pem", [], True,
     []),
]


def test_each_place_that_loads_a_trust_store_is_named(tmp_path):
    result = scan_directory(_tree(tmp_path))
    assert _short(result) == EXPECTED
    assert [p["in_test_code"] for p in result["trust_stores"]["places"]] == [False] * 3


def test_it_reaches_the_tools_the_command_line_and_the_cbom(tmp_path):
    root = _tree(tmp_path / "t")
    assert _short(scan_repo(str(root), level="full")) == EXPECTED
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out), "--level", "full"], check=True,
                   capture_output=True, env=dict(os.environ))
    assert _short(json.loads(out.read_text())) == EXPECTED
    props = {p["name"]: p["value"] for p in build(scan_directory(root))["properties"]}
    said = json.loads(props["qrp:trust_stores"])
    assert [(s["location"], s["line"], s["outside_the_tree"]) for s in said] == [
        (p[0], p[1], p[5]) for p in EXPECTED]


def test_nothing_without_a_trust_store(tmp_path):
    (tmp_path / "a.py").write_text("import ssl\nctx = ssl.create_default_context()\n")
    assert scan_directory(tmp_path)["trust_stores"] is None


def test_a_path_outside_the_tree_is_masked_below_full(tmp_path):
    """The written path is source text: below `--level full` it is masked as a line is, in the
    scan, the tools and the CBOM. A path that is a file read stays, as every row's path does."""
    root = _tree(tmp_path / "t")
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out)], check=True, capture_output=True,
                   env=dict(os.environ))
    cbom = tmp_path / "c.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "cbom",
                    str(root), "--out", str(cbom)], check=True, capture_output=True,
                   env=dict(os.environ))
    props = {p["name"]: p["value"] for p in json.loads(cbom.read_text())["properties"]}
    for files in ([p["file"] for p in json.loads(out.read_text())["trust_stores"]["places"]],
                  [p["file"] for p in scan_repo(str(root))["trust_stores"]["places"]],
                  [p["file"] for p in json.loads(props["qrp:trust_stores"])]):
        assert files[0] == "trust/ca-bundle.pem"
        assert "etc" not in files[1] and "factory" not in files[1] and files[1].startswith("/")
        assert "nginx" not in files[2]
