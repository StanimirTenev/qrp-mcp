"""The FIPS provider in openssl.cnf, and the pinned version beside the provider.

ZA-OPRAVYANE row 35 (Paul J. Lilly, CMVP, 22.10.2026), extending row 24a. On 0.31.0 an
openssl.cnf that activates OpenSSL's FIPS provider (`.include fipsmodule.cnf`,
`fips = fips_sect`, `default_properties = fips=yes`) was read and gave nothing: "fips"
did not occur in the output, and the ML-KEM line read "OpenSSL 3" either way. And an EC
key from Python's cryptography, pinned `cryptography==44.0.0` in requirements.txt, got
no provider.

Now the activation is `evidence.fips_provider` -- activated in configuration, never
"validated" -- and is named beside every "OpenSSL 3" finding, with the caveat that
whether a process loads that file is not in the files. The pinned version of a provider
package is joined to the provider where the import names that package.
"""

import json
import shutil
from pathlib import Path

import pytest

from qrp_mcp.closure import _identity
from qrp_mcp.cyclonedx import PROVIDER_VALIDATION, build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

FIXTURES = Path(__file__).parent / "fixtures" / "fips"


def _tool(obj):
    return getattr(obj, "fn", obj)


def _copy(tmp_path, name):
    shutil.copytree(FIXTURES / name, tmp_path / name)
    return tmp_path / name


def test_the_activation_is_named_line_by_line(tmp_path):
    result = scan_directory(_copy(tmp_path, "cnf"))
    fips = result["evidence"]["fips_provider"]
    assert [(f["path"], f["line"], f["activation"]) for f in fips] == [
        ("openssl.cnf", 3, "includes_fips_module_config"),
        ("openssl.cnf", 8, "loads_fips_provider"),
        ("openssl.cnf", 13, "fips_default_property")]
    assert all("validated" not in f["description"].replace("not validated", "")
               for f in fips)
    assert fips[1]["description"].startswith("FIPS provider activated in openssl.cnf:8")


def test_it_is_named_beside_the_openssl_finding(tmp_path):
    result = scan_directory(_copy(tmp_path, "cnf"))
    mlkem = [f for f in result["evidence"]["source_code"] if f["algorithm"] == "ML-KEM"]
    assert mlkem and all(f["provider"] == "OpenSSL 3" for f in mlkem)
    assert all(f["fips_provider_configured_in"] == ["openssl.cnf:8", "openssl.cnf:13"]
               for f in mlkem)
    finding = next(f for f in result["findings"] if f["algorithm_family"] == "ML-KEM")
    assert finding["fips_provider_configured_in"] == ["openssl.cnf:8", "openssl.cnf:13"]
    # Not part of the occurrence's identity: it comes from another file.
    item = mlkem[0]
    assert _identity("source_code", item) == _identity(
        "source_code", {k: v for k, v in item.items() if k != "fips_provider_configured_in"})
    cbom = build(result)
    comp = next(c for c in cbom["components"] if c["name"] == "ML-KEM")
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert "openssl.cnf:8" in props["qrp:provider_configuration"]
    assert props["qrp:provider_validation"] == PROVIDER_VALIDATION


def test_settings_that_do_not_activate_it(tmp_path):
    (tmp_path / "openssl.cnf").write_text(
        "openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n"
        "[provider_sect]\ndefault = default_sect\nfips = fips_sect\n"
        "[fips_sect]\nactivate = 0\n[algorithm_sect]\ndefault_properties = fips=no\n"
        "# .include fipsmodule.cnf\n", encoding="utf-8")
    (tmp_path / "app.ini").write_text("fips = fips_sect\n", encoding="utf-8")
    assert scan_directory(tmp_path)["evidence"]["fips_provider"] == []


def test_the_pinned_version_is_joined_to_the_provider(tmp_path):
    result = scan_directory(_copy(tmp_path, "pins"))
    ec = [f for f in result["evidence"]["source_code"] if f["path"] == "kem.py"]
    assert ec and all(f["provider"] == "pyca/cryptography" for f in ec)
    assert all(f["provider_pin"] == {"package": "cryptography", "version": "44.0.0",
                                     "pinned_in": "requirements.txt:1"} for f in ec)
    finding = next(f for f in result["findings"] if f["algorithm_family"] == "EC")
    assert finding["provider_pins"] == {"pyca/cryptography": "44.0.0 (requirements.txt:1)"}
    # The Go standard library is no package, and OpenSSL is not in a manifest here.
    assert not [f for f in result["evidence"]["source_code"]
                if f["path"] != "kem.py" and "provider_pin" in f]
    cbom = build(result)
    comp = next(c for c in cbom["components"] if c["name"] == "EC")
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert json.loads(props["qrp:provider_pins"]) == {
        "pyca/cryptography": "44.0.0 (requirements.txt:1)"}


def test_go_mod_and_two_pins_that_disagree(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module x\nrequire (\n\tgithub.com/cloudflare/circl v1.6.1\n)\n", encoding="utf-8")
    (tmp_path / "k.go").write_text(
        'import "github.com/cloudflare/circl/kem/mlkem/mlkem768"\n'
        "func f() { mlkem768.GenerateKeyPair(nil) }\n", encoding="utf-8")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "requirements.txt").write_text("cryptography==43.0.1\n", encoding="utf-8")
    (tmp_path / "a" / "constraints").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "requirements.txt").write_text("cryptography>=42\n", encoding="utf-8")
    for d in ("a", "b"):
        (tmp_path / d / "k.py").write_text(
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "ec.generate_private_key(ec.SECP256R1())\n", encoding="utf-8")
    result = _tool(scan_repo)(str(tmp_path), level="full")
    items = {(f["path"], f["algorithm"]): f for f in result["evidence"]["source_code"]}
    assert items[("k.go", "ML-KEM")]["provider_pin"]["version"] == "v1.6.1"
    assert items[("a/k.py", "EC")]["provider_pin"]["version"] == "43.0.1"
    # `>=42` is not a pin: no version, rather than a guess.
    assert "provider_pin" not in items[("b/k.py", "EC")]
