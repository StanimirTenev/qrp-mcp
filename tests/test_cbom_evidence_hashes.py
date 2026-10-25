"""Each file the CBOM cites as evidence carries its SHA-256 (release A, 05-novi-merki T2).

Checked 25.10.2026 three ways on eight tools' certbot CBOMs: no tool hashes the files its
evidence points at. A location and a line say where to look; without the file's digest a
reader cannot tell "the line moved" from "the file is not the one that was read". CycloneDX
1.6 `occurrences` has no hash field (additionalProperties: false), so each cited file is a
`file` component with the schema's own `hashes`, named exactly as the occurrence's
`location`, which is the join.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory

jsonschema = pytest.importorskip("jsonschema")
SCHEMA_DIR = Path(__file__).parent / "schema"

RSA = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
       "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")


@pytest.fixture
def document(tmp_path):
    (tmp_path / "a.py").write_text(RSA)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.conf").write_text("ssl_protocols TLSv1.2;\nssl_ecdh_curve X25519;\n")
    (tmp_path / "plain.py").write_text("x = 1\n")
    return tmp_path, cyclonedx.build(scan_directory(tmp_path))


def _files(doc: dict) -> dict[str, dict]:
    return {c["name"]: c for c in doc["components"] if c["type"] == "file"}


def test_every_cited_file_carries_its_sha256(document):
    root, doc = document
    files = _files(doc)
    cited = {o["location"] for c in doc["components"] if c["type"] != "file"
             for o in c.get("evidence", {}).get("occurrences", [])}
    assert cited == {"a.py", "sub/b.conf"}
    assert set(files) == cited
    for name, component in files.items():
        assert component["hashes"] == [
            {"alg": "SHA-256", "content": hashlib.sha256((root / name).read_bytes()).hexdigest()}]


def test_a_file_with_no_evidence_is_not_listed(document):
    _, doc = document
    assert "plain.py" not in _files(doc)


def test_the_file_components_are_not_claimed_as_inventory(document):
    _, doc = document
    assemblies = set(doc["compositions"][0]["assemblies"])
    assert not any(ref.startswith("file:") for ref in assemblies)


def test_the_document_with_file_hashes_validates(document):
    _, doc = document
    schema = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "jsf-0.82.schema.json").read_text()),
    }
    resolver = jsonschema.RefResolver.from_schema(schema, store=store)
    validator = jsonschema.Draft7Validator(schema, resolver=resolver)
    assert list(validator.iter_errors(doc)) == []


def test_the_scan_result_names_the_digests_of_cited_files_only(document):
    root, _ = document
    result = scan_directory(root)
    assert set(result["evidence_file_sha256"]) == {"a.py", "sub/b.conf"}
