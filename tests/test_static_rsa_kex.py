"""RSA key exchange in a cipher-suite setting, and Apache's `SSLProtocol all`
(ZA-OPRAVYANE row 43, the network-vs-code probe of 22.10.2026).

`SSLCipherSuite HIGH:!aNULL:AES256-SHA:DES-CBC3-SHA` gave 3DES and nothing else:
AES256-SHA is TLS_RSA_WITH_AES_256_CBC_SHA, RSA key exchange, but no word in OpenSSL's
name says RSA. On an nginx line the RSA came from `ECDHE-RSA-...` -- authentication --
and the two static suites beside it were not named. And `SSLProtocol all -SSLv3` was
reported only as "SSLv3 is forbidden here", though mod_ssl's `all` enables TLS 1.0 to 1.3.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.assets import TLS_SETTING_NOTE
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

APACHE = ("<VirtualHost *:443>\n"
          "    SSLProtocol all -SSLv3\n"
          "    SSLCipherSuite HIGH:!aNULL:AES256-SHA:DES-CBC3-SHA\n"
          "</VirtualHost>\n")
NGINX = ("server {\n"
         "    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-SHA;\n"
         "}\n")


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def _static(result):
    return {(i["path"], i["line"]): i["suites"] for i in result["evidence"]["static_rsa_kex"]}


def test_static_rsa_suites_are_a_key_exchange_finding(tmp_path):
    result = scan_directory(_tree(tmp_path, {"ssl.conf": APACHE, "nginx.conf": NGINX}))
    assert _static(result) == {("ssl.conf", 3): ["AES256-SHA", "DES-CBC3-SHA"],
                               ("nginx.conf", 2): ["AES128-GCM-SHA256", "AES256-SHA"]}
    for item in result["evidence"]["static_rsa_kex"]:
        assert item["key_exchange"] == "RSA" and item["family"] == "RSA"
        assert "no forward secrecy" in item["description"]
        assert item["tls_termination"] == TLS_SETTING_NOTE
    # The Apache line now names RSA as well as 3DES, and RSA is quantum-vulnerable.
    apache = {f["algorithm"] for f in result["evidence"]["source_code"]
              if f["path"] == "ssl.conf" and f["line"] == 3}
    # SHA1 is the suites' record MAC, `-SHA` (reported since row 136).
    assert apache == {"RSA", "3DES", "SHA1"}
    rsa = next(f for f in result["findings"] if f["algorithm_family"] == "RSA")
    assert rsa["quantum_vulnerable"] is True


def test_authentication_and_bans_are_not_key_exchange(tmp_path):
    files = {
        "a.conf": "ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA;\n",
        "b.conf": "ssl_ciphers HIGH:!AES256-SHA:!kRSA:-AES128-SHA;\n",
        "c.conf": "# ssl_ciphers AES256-SHA;\n",
        # A C constant configures nothing; a strongSwan proposal is not a TLS suite.
        "tls1.h": '# define TLS1_TXT_RSA_WITH_AES_256_SHA "AES256-SHA"\n',
        "ipsec.conf": "conn a\n  esp=aes128-sha256-modp2048\n",
    }
    assert _static(scan_directory(_tree(tmp_path, files))) == {}


def test_kRSA_and_the_iana_spelling(tmp_path):
    files = {"a.cnf": "[s]\nCipherString = kRSA:HIGH\n",
             "b.properties": "cipher_suites=TLS_RSA_WITH_AES_128_GCM_SHA256\n"}
    assert _static(scan_directory(_tree(tmp_path, files))) == {
        ("a.cnf", 2): ["kRSA"], ("b.properties", 1): ["TLS_RSA_WITH_AES_128_GCM_SHA256"]}


def test_sslprotocol_all_enables_tls_1_0_and_1_1(tmp_path):
    result = scan_directory(_tree(tmp_path, {"ssl.conf": APACHE}))
    on_line = {(p["version"], p["banned"]) for p in result["evidence"]["protocols"]
               if p["line"] == 2}
    assert on_line == {("SSLv3", True), ("TLSv1.0", False), ("TLSv1.1", False),
                       ("TLSv1.2", False), ("TLSv1.3", False)}
    old = [p for p in result["evidence"]["protocols"]
           if p["version"] in ("TLSv1.0", "TLSv1.1")]
    assert all(p["deprecated"] and p["included_by"] == "all" for p in old)


def test_sslprotocol_subtractions_and_minus_all(tmp_path):
    files = {"a.conf": "SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n",
             "b.conf": "SSLProtocol -all +TLSv1.2 +TLSv1.3\n"}
    result = scan_directory(_tree(tmp_path, files))
    enabled = {(p["path"], p["version"]) for p in result["evidence"]["protocols"]
               if not p["banned"]}
    assert enabled == {("a.conf", "TLSv1.2"), ("a.conf", "TLSv1.3"),
                       ("b.conf", "TLSv1.2"), ("b.conf", "TLSv1.3")}


def test_it_reaches_the_command_and_the_tool(tmp_path):
    (tmp_path / "t").mkdir()
    tree = _tree(tmp_path / "t", {"ssl.conf": APACHE})
    out = tmp_path / "s.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert _static(json.loads(out.read_text())) == {("ssl.conf", 3): ["AES256-SHA", "DES-CBC3-SHA"]}
    for level in ("masked", "trimmed", "full"):
        assert _static(_tool(scan_repo)(str(tree), level=level)) == {
            ("ssl.conf", 3): ["AES256-SHA", "DES-CBC3-SHA"]}


def test_it_reaches_the_cbom_and_the_cbom_is_valid(tmp_path):
    tree = _tree(tmp_path, {"ssl.conf": APACHE, "nginx.conf": NGINX})
    cbom = _tool(export_cbom)(str(tree))
    comp = next(c for c in cbom["components"]
                if c["name"] == "RSA key exchange (static RSA cipher suites)")
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qrp:key_exchange"] == "RSA"
    assert props["qrp:suites"] == "AES128-GCM-SHA256, AES256-SHA, DES-CBC3-SHA"
    assert len(comp["evidence"]["occurrences"]) == 2
    names = [c["name"] for c in cbom["components"]]
    assert "TLSv1.0" in names and "TLSv1.1" in names
    jsonschema = pytest.importorskip("jsonschema")
    schema_dir = Path(__file__).parent / "schema"
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schema_dir / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schema_dir / "jsf-0.82.schema.json").read_text()),
    }
    validator = jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store))
    errors = sorted(validator.iter_errors(cbom), key=str)
    assert not errors, errors[0].message
