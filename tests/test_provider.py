"""Which module implements the algorithm, where the evidence names it.

Raised on 6 Oct 2026 (Jesone Sam, on CMMC and FIPS 140-3): `@noble/post-quantum` and
Go's `crypto/mlkem` produced identical findings -- `ML-KEM / standardised /
pqc_ready` -- on 0.28.0 (4a59058). For a FIPS reader the module is the question:
validation belongs to a module, not to an algorithm.

What is claimed: the identifier in the file names a provider's API. What is not
claimed: that the build is that provider (a fork keeping the API reads the same),
and anything at all about CMVP validation. An unknown provider is absent, never
guessed.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.server import export_cbom, scan_repo

NOBLE = ("a.js", "import { ml_kem768 } from '@noble/post-quantum/ml-kem';\n"
                 "const keys = ml_kem768.keygen();\n")
GO = ("a.go", 'package main\n\nimport "crypto/mlkem"\n\n'
              "func f() { k, _ := mlkem.GenerateKey768(); _ = k }\n")


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(root: Path, *files: tuple[str, str]) -> Path:
    for name, text in files:
        (root / name).write_text(text)
    return root


def _cli(tree: Path, out: Path, *extra: str) -> dict:
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", *extra, str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def _providers(result: dict, family: str = "ML-KEM"):
    finding = next(f for f in result["findings"] if f["algorithm_family"] == family)
    return finding.get("providers")


@pytest.mark.parametrize("file, expected", [
    (NOBLE, ["@noble/post-quantum"]),
    (GO, ["Go standard library"]),
])
def test_the_two_findings_are_no_longer_identical(tmp_path, file, expected):
    tree = _tree(tmp_path, file)
    for result in (_cli(tree, tmp_path.parent / f"{tmp_path.name}.json", "scan"),
                   *(_tool(scan_repo)(str(tree), level=level)
                     for level in ("full", "masked", "trimmed"))):
        assert _providers(result) == expected
        # The call line survives the import it covers, and carries the import's module.
        lines = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "ML-KEM"]
        assert lines and all(e.get("provider") == expected[0] for e in lines)


def test_two_providers_in_one_tree_are_both_named(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, NOBLE, GO)))
    assert _providers(result) == ["@noble/post-quantum", "Go standard library"]


@pytest.mark.parametrize("name, text, family, provider", [
    ("a.py", "from pqcrypto.kem import kyber768\n", "Kyber", "pqcrypto"),
    ("a.c", "OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);\n", "ML-KEM", "liboqs"),
    ("a.go", 'import "github.com/cloudflare/circl/kem/mlkem/mlkem768"\n', "ML-KEM",
     "Cloudflare CIRCL"),
    ("A.java", "import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;\n",
     "ML-KEM", "Bouncy Castle"),
    ("a.c", "MLKEM768_generate_key(pub, seed, &priv);\n", "ML-KEM", "BoringSSL"),
    ("a.c", 'EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");\n', "ML-KEM",
     "OpenSSL 3"),
])
def test_named_providers(tmp_path, name, text, family, provider):
    result = _tool(scan_repo)(str(_tree(tmp_path, (name, text))))
    assert _providers(result, family) == [provider]


def test_unknown_provider_is_absent_not_guessed(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, ("a.py", "keys = ml_kem_768.keygen()\n"))))
    assert _providers(result) is None
    assert all("provider" not in e for e in result["evidence"]["source_code"])


def test_a_provider_named_only_in_a_comment_is_not_the_finding_s(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, ("a.py",
        "# we used to use pqcrypto.kem.mlkem768 here\nkeys = ml_kem_768.keygen()\n"))))
    assert _providers(result) is None


def test_the_cbom_carries_providers_and_claims_no_validation(tmp_path):
    jsonschema = pytest.importorskip("jsonschema")
    tree = _tree(tmp_path, NOBLE, GO)
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
    for doc in (_tool(export_cbom)(str(tree)),
                _cli(tree, tmp_path.parent / f"{tmp_path.name}.cdx.json", "cbom")):
        validator.validate(doc)
        mlkem = next(c for c in doc["components"] if c["name"] == "ML-KEM")
        props = {p["name"]: p["value"] for p in mlkem["properties"]}
        assert json.loads(props["qrp:providers"]) == ["@noble/post-quantum",
                                                      "Go standard library"]
        assert "not claimed" in props["qrp:provider_validation"]
        assert "certificationLevel" not in json.dumps(doc)


def test_closure_keeps_the_provider_and_does_not_key_on_it(tmp_path):
    """Shown in closure, but not part of an occurrence's identity: changing the
    import must not turn every call line in the file into closed + new."""
    from qrp_mcp import closure
    before = _tool(scan_repo)(str(_tree(tmp_path, ("a.py",
        "from pqcrypto.kem import mlkem768\nk = mlkem768.generate_keypair()\n"))), level="full")
    item = next(e for e in before["evidence"]["source_code"] if e["line"] == 2)
    assert item["provider"] == "pqcrypto"
    other = dict(item, provider="liboqs")
    assert closure._identity("source_code", item) == closure._identity("source_code", other)
    assert closure._brief("source_code", item)["provider"] == "pqcrypto"
