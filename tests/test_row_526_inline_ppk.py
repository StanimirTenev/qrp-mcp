"""ZA-OPRAVYANE row 526 (Daniel Grazioli, QKD; probe linkedin-postove/2026-11-17/grazioli-proba,
0.48.0): a swanctl.conf with `ppk_id` / `ppk_required = yes` and the PPK itself in its `secrets`
block (`ppk-qkd { secret = 0x...(256 bits) }`) gave `embedded_keys: []`, and the PPK finding said
nothing about where its secret comes from.

Now the secret written in the file is committed key material in `embedded_keys` (a shared
secret, not a private key; its bytes are never quoted), and the PPK finding carries `ppk_source`:
the place in the files read, or that the secret is not in them. A client of a QKD key management
entity (ETSI GS QKD 014) is out of scope and said so.
"""

from __future__ import annotations

import json

import pytest

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import main

SECRET = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
CONNECTIONS = """connections {
  site-b {
    version = 2
    proposals = aes256gcm16-prfsha384-ecp384
    ppk_id = qkd-key-1
    ppk_required = yes
    local { auth = pubkey  certs = site-a.pem }
    remote { auth = pubkey }
    children { net { esp_proposals = aes256gcm16 } }
  }
}
"""
INLINE = CONNECTIONS + "secrets {\n  ppk-qkd { secret = 0x" + SECRET + "  id = qkd-key-1 }\n}\n"
SPLIT = (CONNECTIONS + "secrets {\n  ppk-qkd {\n    id = qkd-key-1\n    secret = 0s"
         "ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8=\n  }\n}\n")


def _ppk(result):
    return next(f for f in result["findings"] if f["algorithm_family"] == "PPK (RFC 8784)")


@pytest.mark.parametrize("text, line, size", [(INLINE, 13, 256), (SPLIT, 15, 256)])
def test_the_inline_ppk_is_committed_key_material(tmp_path, text, line, size):
    (tmp_path / "swanctl.conf").write_text(text)
    result = scan_directory(str(tmp_path))
    keys = result["evidence"]["embedded_keys"]
    assert len(keys) == 1, keys
    key = keys[0]
    assert (key["path"], key["line"]) == ("swanctl.conf", line)
    assert key["key_material"] == "shared secret" and key["key_size"] == size
    assert "PPK" in key["type"]
    assert "swanctl.conf:%d" % line in _ppk(result)["ppk_source"]
    # A shared secret's family is known: it does not make readiness "not established".
    assert result["summary"]["pqc_readiness"] == "mechanism_protected"


def test_no_inline_ppk_says_the_secret_is_not_in_the_files(tmp_path):
    (tmp_path / "swanctl.conf").write_text(CONNECTIONS)
    result = scan_directory(str(tmp_path))
    assert result["evidence"]["embedded_keys"] == []
    said = _ppk(result)["ppk_source"]
    assert said.startswith("not in the files read") and "QKD" in said


def test_a_classical_psk_is_not_a_ppk(tmp_path):
    (tmp_path / "swanctl.conf").write_text(
        CONNECTIONS + "secrets {\n  ike-site-b { secret = 0x" + SECRET + " }\n}\n")
    assert scan_directory(str(tmp_path))["evidence"]["embedded_keys"] == []


@pytest.mark.parametrize("level", ["full", "masked", "trimmed"])
def test_the_secret_is_never_quoted(tmp_path, level):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "swanctl.conf").write_text(INLINE)
    out, bom = tmp_path / "r.json", tmp_path / "b.json"
    with pytest.raises(SystemExit):
        main(["scan", str(tree), "--no-config", "--level", level, "--out", str(out)])
    with pytest.raises(SystemExit):
        main(["cbom", str(tree), "--no-config", "--level", level, "--out", str(bom)])
    for written in (out, bom):
        assert SECRET[8:40] not in written.read_text()


def test_the_cbom_holds_a_secret_key_not_a_private_key(tmp_path):
    (tmp_path / "swanctl.conf").write_text(INLINE)
    bom = cyclonedx.build(scan_directory(str(tmp_path)))
    material = [c for c in bom["components"]
                if c.get("cryptoProperties", {}).get("assetType") == "related-crypto-material"]
    assert len(material) == 1
    props = material[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert props["type"] == "secret-key" and props["size"] == 256
    assert "private" not in material[0]["name"]
    assert json.dumps(bom)


def test_the_cbom_with_a_ppk_secret_is_valid_cyclonedx(tmp_path):
    from pathlib import Path
    jsonschema = pytest.importorskip("jsonschema")
    (tmp_path / "swanctl.conf").write_text(INLINE)
    bom = cyclonedx.build(scan_directory(str(tmp_path)))
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
    assert sorted(str(e.message) for e in validator.iter_errors(bom)) == []
