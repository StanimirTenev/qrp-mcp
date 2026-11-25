"""Row 555 (25.11.2026, Alan Braggins; probe `linkedin-postove/2026-11-25/stai/proba/braggins`).

`ssl_ecdh_curve MLKEM768` and Go's `mlkem.GenerateKey768()` were "ML-KEM usage" and nothing more,
while only the hybrid was listed (`hybrid_names`). On the day a weakness in lattices is announced,
the places where ML-KEM stands with no classical half are the ones to find first, and they were the
same rows as the hybrid's ML-KEM half. Now an ML-KEM occurrence that the line offers or uses without a
classical half carries `standalone_pqc: true` and `standalone_basis`; the finding and
`summary.by_role.key_establishment` list the places (`standalone_pqc`), and the CBOM component says
it (`qrp:standalone_pqc`).

Spellings, from the documentation:
* the IANA TLS Supported Groups registry: MLKEM512 (512), MLKEM768 (513), MLKEM1024 (514), the
  pure groups; X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 are the hybrids
  (https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml);
* nginx `ssl_ecdh_curve` ("Specifies a curve for ECDHE ciphers", ngx_http_ssl_module), and every
  other group setting the tlsgroups/nginx catalogue reads (ssl_conf_command Groups, HAProxy curves);
* Go crypto/mlkem: GenerateKey768, GenerateKey1024, NewDecapsulationKey768/1024,
  NewEncapsulationKey768/1024 (https://pkg.go.dev/crypto/mlkem); crypto/tls `MLKEM1024 CurveID =
  514` beside the hybrids X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024
  (https://pkg.go.dev/crypto/tls).

Said of the line only: Go code that combines ML-KEM with a classical KEM by hand elsewhere is not
read as a hybrid.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

NGINX = "http {{\n  server {{\n    listen 443 ssl;\n    {directive}\n  }}\n}}\n"


def _scan(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)


def _mlkem(result: dict) -> list[tuple]:
    return sorted((i["path"], i["line"], i.get("parameter_set"), i.get("standalone_pqc"))
                  for i in result["evidence"]["source_code"] if i["algorithm"] == "ML-KEM")


@pytest.mark.parametrize("group,size", [("MLKEM512", "512"), ("MLKEM768", "768"),
                                        ("MLKEM1024", "1024"), ("mlkem768", "768")])
def test_a_pure_ml_kem_group_in_ssl_ecdh_curve_stands_alone(tmp_path, group, size):
    result = _scan(tmp_path, {"nginx.conf": NGINX.format(directive=f"ssl_ecdh_curve {group};")})
    assert _mlkem(result) == [("nginx.conf", 4, size, True)]
    assert result["summary"]["by_role"]["key_establishment"]["standalone_pqc"] == {
        "ML-KEM": ["nginx.conf:4"]}


@pytest.mark.parametrize("directive", [
    "ssl_conf_command Groups MLKEM768;",
    "ssl_conf_command Curves MLKEM768;",
    "ssl_ecdh_curve X25519:MLKEM768;",
    "ssl_ecdh_curve MLKEM768:X25519MLKEM768;",
])
def test_a_pure_group_in_any_list_stands_alone(tmp_path, directive):
    result = _scan(tmp_path, {"nginx.conf": NGINX.format(directive=directive)})
    assert [r[3] for r in _mlkem(result)] == [True]


@pytest.mark.parametrize("line", [
    "global\n  ssl-default-bind-curves MLKEM768\n",
    "frontend fe\n  bind :443 ssl crt /e/s.pem curves MLKEM1024\n",
])
def test_haproxy_curves(tmp_path, line):
    result = _scan(tmp_path, {"haproxy.cfg": line})
    assert [r[3] for r in _mlkem(result)] == [True]


@pytest.mark.parametrize("group", ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
                                   "X25519MLKEM768:X25519"])
def test_a_hybrid_does_not_stand_alone(tmp_path, group):
    result = _scan(tmp_path, {"nginx.conf": NGINX.format(directive=f"ssl_ecdh_curve {group};")})
    assert [r[3] for r in _mlkem(result)] == [None]
    assert "standalone_pqc" not in result["summary"]["by_role"]["key_establishment"]


GO = 'package main\n\nimport "crypto/mlkem"\n\nfunc f(seed, ek []byte) {{\n\t{call}\n}}\n'


@pytest.mark.parametrize("call,size", [
    ("dk, _ := mlkem.GenerateKey768()", "768"),
    ("dk, _ := mlkem.GenerateKey1024()", "1024"),
    ("dk, _ := mlkem.NewDecapsulationKey768(seed)", "768"),
    ("dk, _ := mlkem.NewDecapsulationKey1024(seed)", "1024"),
    ("k, _ := mlkem.NewEncapsulationKey768(ek)", "768"),
    ("k, _ := mlkem.NewEncapsulationKey1024(ek)", "1024"),
])
def test_go_crypto_mlkem_stands_alone(tmp_path, call, size):
    result = _scan(tmp_path, {"kem.go": GO.format(call=call)})
    assert _mlkem(result) == [("kem.go", 6, size, True)]
    item = next(i for i in result["evidence"]["source_code"] if i["algorithm"] == "ML-KEM")
    assert "not read" in item["standalone_basis"]


def test_go_tls_pure_group_stands_alone_and_hybrid_does_not(tmp_path):
    result = _scan(tmp_path, {"t.go": (
        'package main\n\nimport "crypto/tls"\n\n'
        'var a = &tls.Config{CurvePreferences: []tls.CurveID{tls.MLKEM1024}}\n'
        'var b = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}\n')})
    assert [(r[1], r[3]) for r in _mlkem(result)] == [(5, True), (6, None)]


def test_the_probe_tree(tmp_path):
    result = _scan(tmp_path, {
        "a/nginx.conf": "server { listen 443 ssl; ssl_ecdh_curve X25519MLKEM768:X25519; }\n",
        "b/nginx.conf": "server { listen 8443 ssl; ssl_ecdh_curve MLKEM768; }\n",
        "go/kem.go": ('package main\nimport "crypto/mlkem"\nfunc main() {\n'
                      '\tdk, _ := mlkem.GenerateKey768()\n\t_ = dk.EncapsulationKey()\n}\n')})
    part = result["summary"]["by_role"]["key_establishment"]
    assert part["standalone_pqc"] == {"ML-KEM": ["b/nginx.conf:1", "go/kem.go:4"]}
    assert part["fallback_beside_hybrid"] == {"X25519": ["a/nginx.conf:1"]}
    finding = next(f for f in result["findings"] if f["algorithm_family"] == "ML-KEM")
    assert finding["standalone_pqc"] == ["b/nginx.conf:1", "go/kem.go:4"]


def test_standalone_is_not_identity(tmp_path):
    from qrp_mcp import baseline, closure
    assert "standalone_pqc" in closure._CONTEXT_FIELDS and "standalone_basis" in closure._CONTEXT_FIELDS
    assert {"standalone_pqc", "standalone_basis"} <= baseline._NOT_IDENTITY


def test_cli_mcp_and_cbom_carry_it(tmp_path):
    root = tmp_path / "tree"
    _scan(root, {"nginx.conf": NGINX.format(directive="ssl_ecdh_curve MLKEM768;")})
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out)], check=True, capture_output=True,
                   env=dict(os.environ))
    for result in (json.loads(out.read_text()), scan_repo(str(root))):
        assert result["summary"]["by_role"]["key_establishment"]["standalone_pqc"] == {
            "ML-KEM": ["nginx.conf:4"]}
    cbom = build(scan_directory(root))
    props = [p for c in cbom["components"] for p in c.get("properties", [])
             if p["name"] == "qrp:standalone_pqc"]
    assert props and json.loads(props[0]["value"]) == ["nginx.conf:4"]
