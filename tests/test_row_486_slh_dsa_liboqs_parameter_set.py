"""ZA-OPRAVYANE row 486: an SLH-DSA name in liboqs's spelling gave no parameter set.

Probe `linkedin-postove/2026-11-15/hbs-proba/` (0.45.0): `oqs.Signature("SLH_DSA_PURE_SHA2_128S")`
read SLH-DSA with `parameter_set: None`. liboqs names its SLH-DSA schemes with a `PURE_` or
`<hash>_PREHASH_` part between `SLH_DSA_` and the FIPS 205 set (src/sig/sig.h:
`SLH_DSA_PURE_SHA2_128S`, `SLH_DSA_SHA2_224_PREHASH_SHA2_128S`, `SLH_DSA_SHAKE_256_PREHASH_...`);
the parameter set read only `slh-dsa-sha2-128s` with nothing in between.

Not done: pyspx (`import pyspx.shake_128f`) is round-3 SPHINCS+, not FIPS 205, and its set is on
the import line, not the call; the names leanSPHINCS / leanSig wait for a primary source; pure vs
pre-hash is not recorded.
"""

import json
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx, detectors, server
from qrp_mcp.scan import scan_directory

PROBE = Path.home() / "zadachi/linkedin-postove/2026-11-15/hbs-proba/r/signer.py"
TEXT = ('import oqs\n\n'
        'def sign_oqs(msg: bytes):\n'
        '    with oqs.Signature("SLH_DSA_PURE_SHA2_128S") as s:\n'
        '        s.generate_keypair()\n'
        '        return s.sign(msg)\n')


@pytest.fixture
def tree(tmp_path):
    if PROBE.is_file():
        assert 'oqs.Signature("SLH_DSA_PURE_SHA2_128S")' in PROBE.read_text()
    t = tmp_path / "repo"
    t.mkdir()
    (t / "signer.py").write_text(TEXT)
    return t


def _row(evidence):
    rows = [e for e in evidence["source_code"] if e["algorithm"] == "SLH-DSA" and e["line"] == 4]
    assert len(rows) == 1
    return rows[0]


def test_scan_json_and_mcp_tool(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    assert _row(json.loads(out.read_text())["evidence"]).get("parameter_set") == "SHA2-128s"
    assert _row(server.scan_repo(str(tree))["evidence"]).get("parameter_set") == "SHA2-128s"


def test_cbom(tree):
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        at = {(o["location"], o.get("line")): c for c in doc["components"]
              for o in c.get("evidence", {}).get("occurrences") or []}
        props = at[("signer.py", 4)]["cryptoProperties"]["algorithmProperties"]
        assert props["parameterSetIdentifier"] == "SHA2-128s"


@pytest.mark.parametrize("line, said", [
    ('oqs.Signature("SLH_DSA_PURE_SHA2_128S")', "SHA2-128s"),
    ('oqs.Signature("SLH_DSA_PURE_SHAKE_256F")', "SHAKE-256f"),
    ("OQS_SIG_alg_slh_dsa_pure_shake_192s", "SHAKE-192s"),
    ('"SLH_DSA_SHA2_224_PREHASH_SHA2_128S"', "SHA2-128s"),
    ('"SLH_DSA_SHA2_512_224_PREHASH_SHAKE_128F"', "SHAKE-128f"),
    ('"SLH_DSA_SHAKE_256_PREHASH_SHA2_256S"', "SHA2-256s"),
    ('"SLH_DSA_SHA3_384_PREHASH_SHAKE_192F"', "SHAKE-192f"),
    # The FIPS 205 spelling still reads as before.
    ("alg = 'SLH-DSA-SHA2-192f'", "SHA2-192f"),
    # The pre-hash function alone is not a parameter set.
    ('"SLH_DSA_SHA2_256_PREHASH"', None),
])
def test_parameter_sets(line, said):
    item = {"algorithm": "SLH-DSA", "excerpt": line}
    detectors._tag_parameter_sets([item])
    assert item.get("parameter_set") == said
