"""ZA-OPRAVYANE row 488: the implementation and the parameter set were not always recorded.

Probe `linkedin-postove/2026-11-15/impl-proba/` (0.46.0): Rust `use ml_kem::{MlKem768, ...}` and
`MlKem768::generate` read ML-KEM 768 with no `provider` (RustCrypto's ml-kem crate); Go
`mlkem.GenerateKey768()` read ML-KEM, Go standard library, with no `parameter_set`. Python
liboqs, Go and Bouncy Castle had a provider.

RustCrypto's `ml_kem::`, `ml_dsa::` and `slh_dsa::` crate paths now name the provider
`RustCrypto`, and libcrux's `libcrux_ml_kem`/`libcrux_ml_dsa` (Rust paths and the C names
OpenSSH vendors) `libcrux`; Go's `crypto/mlkem` names (GenerateKey768/1024,
NewEncapsulationKey768/1024, NewDecapsulationKey768/1024, EncapsulationKey768/1024,
DecapsulationKey768/1024, from the Go 1.26 source) give the parameter set. The crate path names
the API: a fork that keeps it reads the same; nothing here says anything about validation.
"""

import json
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx, detectors, server
from qrp_mcp.scan import scan_directory

PROBE = Path.home() / "zadachi/linkedin-postove/2026-11-15/impl-proba/r"
FILES = {
    "b.go": ('package k\nimport "crypto/mlkem"\n'
             "func K() { dk, _ := mlkem.GenerateKey768(); _ = dk }\n"),
    "d.rs": ("use ml_kem::{MlKem768, KemCore};\n"
             "fn k(){ let (dk, ek) = MlKem768::generate(&mut rng); }\n"),
}


@pytest.fixture
def tree(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    for name, text in FILES.items():
        probe = PROBE / name
        if probe.is_file():
            assert probe.read_text() == text
        (t / name).write_text(text)
    return t


def _rows(evidence, path):
    return [e for e in evidence["source_code"] if e["path"] == path and e["algorithm"] == "ML-KEM"]


def test_rust_provider_and_go_parameter_set_in_the_scan_json(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    ev = json.loads(out.read_text())["evidence"]
    rust = _rows(ev, "d.rs")
    assert rust and {e.get("provider") for e in rust} == {"RustCrypto"}
    go = _rows(ev, "b.go")
    assert go and {e.get("parameter_set") for e in go} == {"768"}
    assert {e.get("provider") for e in go} == {"Go standard library"}
    # The set now read reaches the CNSA 2.0 parameter-set clause.
    out2 = tmp_path / "c.json"
    server.scan_to_file([str(tree), "--mandate", "cnsa-2.0", "--as-of", "2026-11-15",
                         "--out", str(out2)])
    go = _rows(json.loads(out2.read_text())["evidence"], "b.go")
    assert "ML-KEM-1024 is the only parameter set" in go[0]["mandates"]["cnsa-2.0"]["clause"]


def test_they_reach_the_mcp_tool_and_the_cbom(tree):
    ev = server.scan_repo(str(tree))["evidence"]
    assert {e.get("provider") for e in _rows(ev, "d.rs")} == {"RustCrypto"}
    assert {e.get("parameter_set") for e in _rows(ev, "b.go")} == {"768"}
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        at = {(o["location"], o.get("line")): c for c in doc["components"]
              for o in c.get("evidence", {}).get("occurrences") or []}
        go = at[("b.go", 3)]
        assert go["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] == "768"
        assert "768" in go["name"]


@pytest.mark.parametrize("line, said", [
    ("use ml_kem::{MlKem768, KemCore};", ["RustCrypto"]),
    ("let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed);", ["RustCrypto"]),
    ("use slh_dsa::{Shake128f, SigningKey};", ["RustCrypto"]),
    ("let (sk, pk) = libcrux_ml_kem::mlkem768::generate_key_pair(r);", ["libcrux"]),
    ("libcrux_ml_kem_mlkem768_portable_generate_key_pair(rnd);", ["libcrux"]),
    # liboqs C names are not the Rust crate.
    ("rc = OQS_KEM_ml_kem_768_keypair(pk, sk);", ["liboqs"]),
    ('#include "kem_ml_kem.h"', []),
])
def test_provider_names(line, said):
    assert [n for n, p in detectors.PROVIDER_PATTERNS if p.search(line)] == said


@pytest.mark.parametrize("line, said", [
    ("dk, err := mlkem.GenerateKey768()", "768"),
    ("dk, err := mlkem.GenerateKey1024()", "1024"),
    ("ek, err := mlkem.NewEncapsulationKey768(b)", "768"),
    ("dk, err := mlkem.NewDecapsulationKey1024(seed)", "1024"),
    ("func f(ek *mlkem.EncapsulationKey768) {}", "768"),
    # Two sets on one line: none.
    ("a, _ := mlkem.GenerateKey768(); b, _ := mlkem.GenerateKey1024()", None),
])
def test_go_parameter_sets(line, said):
    item = {"algorithm": "ML-KEM", "excerpt": line}
    detectors._tag_parameter_sets([item])
    assert item.get("parameter_set") == said
