"""A hybrid is one asset that depends on its two halves (release A, M4h).

Measured 25.10.2026 (qrp-pokazateli 01-tablo M4, probe/hybrid): no scanner links a hybrid
to its halves through `dependencies` -- CryptoScan, PostShor and foxguard emit a hybrid
component with `dependsOn` empty, and ours emitted the halves with no hybrid at all. So a
reader could not tell X25519 offered alone from X25519 inside X25519MLKEM768 from the
document's structure. Here the hybrid is its own component and `dependencies` points from
it to each half that is in the inventory.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from qrp_mcp import closure, cyclonedx
from qrp_mcp.scan import scan_directory

jsonschema = pytest.importorskip("jsonschema")
SCHEMA_DIR = Path(__file__).parent / "schema"


@pytest.fixture(scope="module")
def validator():
    schema = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "jsf-0.82.schema.json").read_text()),
    }
    resolver = jsonschema.RefResolver.from_schema(schema, store=store)
    return jsonschema.Draft7Validator(schema, resolver=resolver)


def _cbom(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    return cyclonedx.build(scan_directory(tmp_path))


def _hybrid(doc: dict, name: str) -> tuple[dict, list[str]]:
    component = next(c for c in doc["components"] if c["name"] == name)
    deps = next(d for d in doc.get("dependencies", []) if d["ref"] == component["bom-ref"])
    return component, deps["dependsOn"]


def _refs_resolve(doc: dict) -> bool:
    refs = {c["bom-ref"] for c in doc["components"]}
    return all(d["ref"] in refs and set(d.get("dependsOn", [])) <= refs
               for d in doc.get("dependencies", []))


@pytest.mark.parametrize("name,text,file,halves", [
    ("X25519MLKEM768", "ssl_ecdh_curve X25519MLKEM768:X25519;\n", "nginx.conf",
     ["crypto:ml-kem", "crypto:x25519"]),
    ("mlkem768x25519-sha256", "KexAlgorithms mlkem768x25519-sha256\n", "sshd_config",
     ["crypto:ml-kem", "crypto:x25519"]),
    ("sntrup761x25519-sha512", "KexAlgorithms sntrup761x25519-sha512\n", "sshd_config",
     ["crypto:ntru", "crypto:x25519"]),
    ("X25519MLKEM768",
     "package main\nimport \"crypto/tls\"\n"
     "var c = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}\n",
     "main.go", ["crypto:ml-kem", "crypto:x25519"]),
])
def test_the_hybrid_depends_on_both_halves(tmp_path, validator, name, text, file, halves):
    doc = _cbom(tmp_path, {file: text})
    component, depends_on = _hybrid(doc, name)
    assert depends_on == halves
    algo = component["cryptoProperties"]["algorithmProperties"]
    assert algo["primitive"] == "combiner"
    assert component["evidence"]["occurrences"][0]["location"] == file
    assert _refs_resolve(doc)
    assert list(validator.iter_errors(doc)) == []


def test_the_halves_are_named_with_their_parameter_set(tmp_path):
    doc = _cbom(tmp_path, {"nginx.conf": "ssl_ecdh_curve X25519MLKEM768;\n"})
    component, _ = _hybrid(doc, "X25519MLKEM768")
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert props["qrp:halves"] == "X25519 + ML-KEM-768"


def test_a_hybrid_named_in_a_comment_is_not_an_asset(tmp_path):
    doc = _cbom(tmp_path, {"a.py": "# later: X25519MLKEM768\n"
                                   "from cryptography.hazmat.primitives.asymmetric import x25519\n"
                                   "k = x25519.X25519PrivateKey.generate()\n"})
    assert not any(c["name"] == "X25519MLKEM768" for c in doc["components"])
    assert "dependencies" not in doc


def test_one_component_per_hybrid_however_often_it_is_named(tmp_path):
    doc = _cbom(tmp_path, {"nginx.conf": "ssl_ecdh_curve X25519MLKEM768;\n",
                           "b.conf": "ssl_ecdh_curve x25519mlkem768;\n"})
    hybrids = [c for c in doc["components"] if c["name"] == "X25519MLKEM768"]
    assert len(hybrids) == 1
    assert len(hybrids[0]["evidence"]["occurrences"]) == 2


def test_the_halves_stay_findings_and_the_hybrid_is_not_one(tmp_path):
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519MLKEM768;\n")
    result = scan_directory(tmp_path)
    families = {f["algorithm_family"] for f in result["findings"]}
    assert {"ML-KEM", "X25519"} <= families and "X25519MLKEM768" not in families


def test_a_parameter_set_read_later_does_not_reopen_a_closed_comparison(tmp_path):
    # The set is read off the line already in the identity; a result written before it
    # was tagged must compare equal to one written after.
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519MLKEM768;\n")
    after = scan_directory(tmp_path)
    tagged = [(c, i) for c, items in after["evidence"].items() for i in items
              if isinstance(i, dict) and i.get("parameter_set")]
    assert tagged
    for category, item in tagged:
        untagged = copy.deepcopy(item)
        untagged.pop("parameter_set")
        assert closure._identity(category, item) == closure._identity(category, untagged)
