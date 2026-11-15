"""Rows 475 and 465 (15.11.2026): the TLS protocol component is empty for a CBOM reader.

Row 475 (a CBOM consumer, 15.11.2026): a reader of the standard fields saw "TLS 1.3" with
nothing under it. The groups the same file configures (X25519MLKEM768, X25519) were algorithm
components of their own, linked to no protocol, so the reader classed the key exchange as
"unknown". Row 465 (QCI CBOM-Benchmark 2.6.6): the suites of an `ssl_ciphers` line were split
into RSA/ECDH/3DES on the right line, but the suite itself never reached
`protocolProperties.cipherSuites`.

Now a TLS protocol component carries, in CycloneDX 1.6's own fields:
- `protocolProperties.cryptoRefArray`: the bom-refs of the TLS groups the same file configures;
- `protocolProperties.cipherSuites[]`: each suite the same file enables, by its IANA name where
  OpenSSL's table gives one, with `algorithms` pointing at the families it names.

The reader's view is tested with every `properties` array removed first. The suite identity is
taken from the detector, so it is the same at the default `masked` level as at `full`.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import _at_level, export_cbom, scan_repo

jsonschema = pytest.importorskip("jsonschema")
SCHEMA_DIR = Path(__file__).parent / "schema"

NGINX_PQ = (
    "server {\n"
    "  listen 443 ssl;\n"
    "  ssl_protocols TLSv1.3;\n"
    "  ssl_ecdh_curve X25519MLKEM768:X25519;\n"
    "}\n"
)

NGINX_SUITES = (
    "server {\n"
    "    listen 443 ssl;\n"
    "    # Old settings, kept for reference. Not active.\n"
    "    # ssl_ciphers RC4-SHA:EXP-DES-CBC-SHA;\n"
    "    ssl_protocols TLSv1.2 TLSv1.3;\n"
    "    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:AES256-SHA:!RC4:HIGH:EECDH+aRSA;\n"
    "    ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;\n"
    "}\n"
)


def _validator():
    schema = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "jsf-0.82.schema.json").read_text()),
    }
    return jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store))


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(args: list[str]) -> None:
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True)


def _cboms(root: Path, tmp_path: Path) -> list[dict]:
    """The CBOM from all three ways out, at the default (masked) level."""
    out = tmp_path / "c.json"
    _cli(["cbom", str(root), "--out", str(out)])
    return [build(_at_level(scan_directory(root), "masked")), export_cbom(str(root)),
            json.loads(out.read_text())]


def _refs_resolve(doc: dict) -> None:
    refs = {c["bom-ref"] for c in doc["components"]}
    for c in doc["components"]:
        pp = c.get("cryptoProperties", {}).get("protocolProperties", {})
        for ref in pp.get("cryptoRefArray", []):
            assert ref in refs, ref
        for suite in pp.get("cipherSuites", []):
            for ref in suite.get("algorithms", []):
                assert ref in refs, ref
    for dep in doc.get("dependencies", []):
        assert dep["ref"] in refs
        for ref in dep["dependsOn"]:
            assert ref in refs, ref


def _without_properties(value):
    if isinstance(value, dict):
        return {k: _without_properties(v) for k, v in value.items() if k != "properties"}
    if isinstance(value, list):
        return [_without_properties(v) for v in value]
    return value


def _tls(doc: dict, version: str) -> list[dict]:
    return [c for c in doc["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "protocol"
            and c["cryptoProperties"]["protocolProperties"].get("type") == "tls"
            and c["cryptoProperties"]["protocolProperties"].get("version") == version]


def test_the_reader_resolves_the_key_exchange_without_qrp_properties(tmp_path):
    root = _write(tmp_path / "r", {"web/nginx.conf": NGINX_PQ})
    for doc in _cboms(root, tmp_path):
        assert not list(_validator().iter_errors(doc))
        _refs_resolve(doc)
        plain = _without_properties(doc)
        by_ref = {c["bom-ref"]: c for c in plain["components"]}
        (tls13,) = _tls(plain, "TLSv1.3")
        groups = [by_ref[r] for r in tls13["cryptoProperties"]["protocolProperties"]
                  ["cryptoRefArray"]]
        names = sorted(g["name"] for g in groups)
        assert names == ["X25519 (TLS group offered alone)", "X25519MLKEM768"], names
        for g in groups:
            assert g["cryptoProperties"]["algorithmProperties"]["primitive"] in (
                "key-agree", "kem", "combiner")
        # The hybrid's halves, by the standard dependencies.
        hybrid = next(g for g in groups if g["name"] == "X25519MLKEM768")
        (dep,) = [d for d in plain["dependencies"] if d["ref"] == hybrid["bom-ref"]]
        halves = sorted(by_ref[r]["name"] for r in dep["dependsOn"])
        assert halves[0].startswith("ML-KEM") and halves[1] == "X25519", halves


def test_suites_carry_iana_names_and_their_algorithms(tmp_path):
    root = _write(tmp_path / "r", {"nginx.conf": NGINX_SUITES})
    for doc in _cboms(root, tmp_path):
        assert not list(_validator().iter_errors(doc))
        _refs_resolve(doc)
        plain = _without_properties(doc)
        by_ref = {c["bom-ref"]: c for c in plain["components"]}
        (tls12,) = _tls(plain, "TLSv1.2")
        suites = tls12["cryptoProperties"]["protocolProperties"]["cipherSuites"]
        # Commented lines, `!RC4` and the selectors HIGH / EECDH+aRSA are not suites; the
        # TLS 1.3 suites go to the TLS 1.3 component, not here.
        assert [s["name"] for s in suites] == [
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA"]
        ecdhe = {by_ref[r]["name"] for r in suites[0]["algorithms"]}
        assert {"ECDH", "RSA"} <= ecdhe, ecdhe
        assert "3DES" in {by_ref[r]["name"] for r in suites[1]["algorithms"]}
        (tls13,) = _tls(plain, "TLSv1.3")
        assert [s["name"] for s in tls13["cryptoProperties"]["protocolProperties"]
                ["cipherSuites"]] == ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]


def test_links_stay_in_their_file_and_an_unlinked_pin_keeps_its_ref(tmp_path):
    plain_pin = "server {\n  ssl_protocols TLSv1.3;\n}\n"
    # A group set somewhere in the tree, in a file that pins no version: without it the pin
    # carries `key_exchange: library default` (scan._library_default_key_exchange), which is
    # a different, older fact about the tree and moves the ref on its own.
    alone = build(scan_directory(_write(tmp_path / "a", {
        "b.conf": plain_pin, "c.conf": "ssl_ecdh_curve X25519;\n"})))
    (before,) = _tls(alone, "TLSv1.3")
    both = build(scan_directory(_write(tmp_path / "b", {"a/nginx.conf": NGINX_PQ,
                                                        "b.conf": plain_pin})))
    pins = _tls(both, "TLSv1.3")
    assert len(pins) == 2
    unlinked = [c for c in pins if "cryptoRefArray" not in
                c["cryptoProperties"]["protocolProperties"]]
    (unlinked,) = unlinked
    assert unlinked["bom-ref"] == before["bom-ref"]
    assert [o["location"] for o in unlinked["evidence"]["occurrences"]] == ["b.conf"]


def test_the_scan_result_carries_the_suites_at_the_masked_level(tmp_path):
    root = _write(tmp_path / "r", {"nginx.conf": NGINX_SUITES})
    out = tmp_path / "s.json"
    _cli(["scan", str(root), "--out", str(out)])
    for result in (json.loads(out.read_text()), scan_repo(str(root))):
        assert result["excerpt_level"] == "masked"
        names = [s["name"] for item in result["cipher_suites"] for s in item["suites"]]
        assert names == ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                         "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA",
                         "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
        assert result["cipher_suites"][0]["suites"][1]["written"] == "DES-CBC3-SHA"


def test_a_hybrid_goes_to_tls_1_3_and_a_classical_group_to_both(tmp_path):
    root = _write(tmp_path / "r", {"nginx.conf": (
        "server {\n  ssl_protocols TLSv1.2 TLSv1.3;\n"
        "  ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n")})
    doc = build(scan_directory(root))
    by_ref = {c["bom-ref"]: c["name"] for c in doc["components"]}
    (tls12,) = _tls(doc, "TLSv1.2")
    (tls13,) = _tls(doc, "TLSv1.3")
    assert [by_ref[r] for r in tls12["cryptoProperties"]["protocolProperties"]
            ["cryptoRefArray"]] == ["X25519 (TLS group offered alone)"]
    assert sorted(by_ref[r] for r in tls13["cryptoProperties"]["protocolProperties"]
                  ["cryptoRefArray"]) == ["X25519 (TLS group offered alone)", "X25519MLKEM768"]


def test_a_version_apache_enables_by_all_is_linked_too(tmp_path):
    # certbot's current-options-ssl-apache.conf: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`
    # enables TLS 1.2 and 1.3 by `all` (`included_by`); the suites of the same file go to 1.2.
    root = _write(tmp_path / "r", {"ssl.conf": (
        "SSLProtocol             all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\n"
        "SSLCipherSuite          ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\n")})
    doc = build(scan_directory(root))
    _refs_resolve(doc)
    (tls12,) = _tls(doc, "TLSv1.2")
    assert [s["name"] for s in tls12["cryptoProperties"]["protocolProperties"]["cipherSuites"]] == [
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"]
    assert all("cipherSuites" not in c["cryptoProperties"]["protocolProperties"]
               for c in doc["components"] if "(forbidden)" in c["name"])


def test_go_and_envoy_suite_forms_are_carried():
    from qrp_mcp.detectors import scan_suite_names
    go = "\tCipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},"
    envoy = '      cipher_suites: "[ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-ECDSA-CHACHA20-POLY1305]"'
    assert [s["name"] for s in scan_suite_names(go)] == ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]
    assert [s["name"] for s in scan_suite_names(envoy)] == [
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]



def test_a_commented_out_pin_makes_no_linked_component(tmp_path):
    # Row 465's own input (QCI tier4 nginx.conf, written here): the old settings stay commented.
    root = _write(tmp_path / "r", {"nginx.conf": (
        "server {\n    # Old settings, kept for reference. Not active.\n"
        "    # ssl_protocols SSLv3 TLSv1;\n    # ssl_ciphers RC4-SHA:EXP-DES-CBC-SHA;\n"
        "    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;\n"
        "    ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:AES256-SHA;\n}\n")})
    doc = build(scan_directory(root))
    pins = [c for c in doc["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "protocol"]
    assert {c["cryptoProperties"]["protocolProperties"]["version"] for c in pins} == {
        "TLSv1.0", "TLSv1.1", "TLSv1.2"}
    for c in pins:
        assert [o["line"] for o in c["evidence"]["occurrences"]] == [5]
        assert "RC4" not in json.dumps(c["cryptoProperties"])
