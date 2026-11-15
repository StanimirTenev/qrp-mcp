"""ZA-OPRAVYANE row 494: where a KEM key is generated was not said.

Probe `linkedin-postove/2026-11-15/keyber-proba/` (0.46.0), after Keyber (IACR ePrint
2026/2766): a pqm4-style `provision.c` generates the device's ML-KEM-512 key once with
`crypto_kem_keypair` (line 6) and decapsulates with it (`crypto_kem_dec`, line 9). The scan
found ML-KEM-512 from the comment on line 1 and the Makefile, called it `pqc_ready`, and gave
neither call a row: it could not say that this device generates its own long-lived key.

A call to a KEM's key generation, encapsulation or decapsulation (the NIST API
`crypto_kem_keypair/enc/dec` of pqm4, PQClean and SUPERCOP, liboqs `OQS_KEM_keypair/encaps/
decaps` and their per-scheme forms, mlkem-native's `..._MLKEM768_..._keypair/enc/dec`) is now a
row with `operation` -- `keygen` apart from `encapsulate` and `decapsulate` -- in the scan JSON,
the MCP tools, SARIF and the CBOM (`qrp:operation`); the same for `crypto_sign_keypair`,
`crypto_sign_signature`/`crypto_sign`, `crypto_sign_verify`/`crypto_sign_open` and
`OQS_SIG_keypair/sign/verify`. Where the call does not name the scheme, the family is the one
KEM (or signature) family the same file names, and `family_named_at` says on which line.
Not claimed: that the step survives a fault -- code shows where a key is generated, not whether
that survives a glitch; a call in a file that names no scheme, or two, gets no row.
"""

import json
import shutil
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

PROBE = Path.home() / "zadachi/linkedin-postove/2026-11-15/keyber-proba/r"
PROVISION = (
    '#include "api.h"   /* pqm4 crypto_kem/ml-kem-512/m4fspeed */\n'
    '#include "randombytes.h"\n'
    "static uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];\n"
    "int provision_device_key(void) {\n"
    "    /* one-time key ceremony at first boot; key kept for device lifetime */\n"
    "    return crypto_kem_keypair(pk, sk);\n"
    "}\n"
    "int handle_session(const uint8_t *ct, uint8_t *ss) {\n"
    "    return crypto_kem_dec(ss, ct, sk);\n"
    "}\n")


@pytest.fixture
def tree(tmp_path):
    t = tmp_path / "repo"
    if PROBE.is_dir():
        shutil.copytree(PROBE, t)
    else:
        (t / "fw").mkdir(parents=True)
        (t / "fw/Makefile").write_text("SCHEME = crypto_kem/ml-kem-512/m4fspeed\n")
        (t / "fw/provision.c").write_text(PROVISION)
    assert (t / "fw/provision.c").read_text() == PROVISION
    return t


def _ops(evidence):
    return {(e["path"], e["line"]): (e["algorithm"], e.get("operation"))
            for e in evidence["source_code"] if e.get("operation")}


def test_keygen_and_decapsulation_are_rows_in_the_scan_json(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    ops = _ops(r["evidence"])
    assert ops[("fw/provision.c", 6)] == ("ML-KEM", "keygen")
    assert ops[("fw/provision.c", 9)] == ("ML-KEM", "decapsulate")
    row = next(e for e in r["evidence"]["source_code"]
               if e["path"] == "fw/provision.c" and e["line"] == 6)
    assert row["evidence_kind"] == "call"
    assert row["family_named_at"] == "fw/provision.c:1"
    assert row["parameter_set"] == "512"
    # One finding per family, as before: the verdict and the count do not move.
    assert r["summary"]["total_findings"] == 1
    assert r["summary"]["pqc_readiness"] == "pqc_ready"


def test_operations_reach_the_mcp_tool_sarif_and_the_cbom(tree, tmp_path):
    r = server.scan_repo(str(tree))
    assert _ops(r["evidence"])[("fw/provision.c", 6)] == ("ML-KEM", "keygen")
    out = tmp_path / "r.sarif"
    assert server.scan_to_file([str(tree), "--format", "sarif", "--out", str(out)]) == 0
    sarif = json.loads(out.read_text())
    got = {(res["locations"][0]["physicalLocation"]["region"]["startLine"],
            res["properties"].get("operation"))
           for run in sarif["runs"] for res in run["results"]}
    assert (6, "keygen") in got and (9, "decapsulate") in got
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        said = {}
        for c in doc["components"]:
            props = {p["name"]: p["value"] for p in c.get("properties", [])}
            if "qrp:operation" in props:
                ops = json.loads(props["qrp:operation"])
                assert len(ops) == len(c["evidence"]["occurrences"])
                for o, op in zip(c["evidence"]["occurrences"], ops):
                    said[(o["location"], o.get("line"))] = op
        assert said[("fw/provision.c", 6)] == "keygen"
        assert said[("fw/provision.c", 9)] == "decapsulate"


@pytest.mark.parametrize("line, said", [
    ("    return crypto_kem_keypair(pk, sk);", ("ML-KEM", "keygen")),
    ("    if (crypto_kem_enc(ct, ss, pk) != 0) return -1;", ("ML-KEM", "encapsulate")),
    ("    rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);", ("ML-KEM", "decapsulate")),
    ("    OQS_KEM_keypair(kem, pk, sk);", ("ML-KEM", "keygen")),
    ("    OQS_KEM_encaps(kem, ct, ss, pk);", ("ML-KEM", "encapsulate")),
    ("    rc = OQS_KEM_ml_kem_768_decaps(ss, ct, sk);", ("ML-KEM", "decapsulate")),
    ("    PQCP_MLKEM_NATIVE_MLKEM768_C_keypair(pk, sk);", ("ML-KEM", "keygen")),
    ("    return crypto_kem_keypair_derand(pk, sk, seed);", ("ML-KEM", "keygen")),
    # liboqs kem_ml_kem_768.c: the wrapper calls mlkem-native behind a cast.
    ("\treturn (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_keypair(public_key, secret_key);",
     ("ML-KEM", "keygen")),
    # Declarations, definitions and macros are not calls.
    ("int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);", None),
    ("int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk) {", None),
    ("OQS_API OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *pk, uint8_t *sk);", None),
    ("extern int PQCP_MLKEM_NATIVE_MLKEM768_C_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);",
     None),
    ("#define crypto_kem_keypair(pk, sk) other_keypair(pk, sk)", None),
    ("// crypto_kem_keypair(pk, sk) is called once", None),
])
def test_kem_call_forms(tmp_path, line, said):
    t = tmp_path / "k"
    t.mkdir()
    (t / "k.c").write_text('#include <oqs/oqs.h>  /* ML-KEM-768 */\n'
                           'static const char *alg = "ML-KEM-768";\n'
                           f"{line}\n")
    ops = _ops(scan_directory(t)["evidence"])
    assert ops.get(("k.c", 3)) == said


def test_signature_calls_too(tmp_path):
    t = tmp_path / "s"
    t.mkdir()
    (t / "s.c").write_text('#include "api.h"  /* crypto_sign/ml-dsa-65 */\n'
                           "void f(void) {\n"
                           "    crypto_sign_keypair(pk, sk);\n"
                           "    crypto_sign_signature(sig, &siglen, m, mlen, sk);\n"
                           "    if (crypto_sign_verify(sig, siglen, m, mlen, pk)) return;\n"
                           "    crypto_sign(sm, &smlen, m, mlen, sk);\n"
                           "    crypto_sign_open(m, &mlen, sm, smlen, pk);\n"
                           "}\n")
    ops = _ops(scan_directory(t)["evidence"])
    assert ops[("s.c", 3)] == ("ML-DSA", "keygen")
    assert ops[("s.c", 4)] == ("ML-DSA", "sign")
    assert ops[("s.c", 5)] == ("ML-DSA", "verify")
    assert ops[("s.c", 6)] == ("ML-DSA", "sign")
    assert ops[("s.c", 7)] == ("ML-DSA", "verify")


def test_no_scheme_or_two_schemes_in_the_file_gives_no_row(tmp_path):
    t = tmp_path / "n"
    t.mkdir()
    (t / "none.c").write_text('#include "api.h"\nvoid f(void) { crypto_kem_keypair(pk, sk); }\n')
    (t / "two.c").write_text("/* ML-KEM-768 and HQC-128 */\n"
                             "void f(void) { crypto_kem_keypair(pk, sk); }\n")
    r = scan_directory(t)
    assert not [e for e in r["evidence"]["source_code"] if e.get("operation")]
