"""Rows 576-579 (crypto-asset probe, 25.11.2026): post-quantum signature libraries of the chains.

576 (fp): leanSig / hash-sig `generalized_xmss` was XMSS, `standardised`, `pqc_ready`, from the
    import alone. Its README: "a generic framework from this paper (ePrint 2025/055), which builds
    XMSS-like hash-based signatures from a primitive called incomparable encodings", instantiated
    with Poseidon -- not RFC 8391 / SP 800-208 XMSS. Its own family, `Generalized XMSS`, a research
    scheme: pqc_pre_standard, never pqc_ready.
    https://raw.githubusercontent.com/leanEthereum/leanSig/main/README.md
577: pyspx's own spelling, `import pyspx.shake_128f` / `pyspx.shake_128f.generate_keypair(seed)`, gave
    nothing. Its README: bindings "for all parameter sets included as part of the SPHINCS+ submission
    to NIST's Post-Quantum Cryptography Standardization project" -- round-3 SPHINCS+, not FIPS 205.
    https://raw.githubusercontent.com/sphincs/pyspx/master/README.md
578: Algorand's falcon package (`falcon.GenerateKey`, `SignCompressed`, `Verify`) and go-algorand's
    `crypto.GenerateFalconSigner` gave nothing.
    https://raw.githubusercontent.com/algorand/falcon/main/falcon.go,
    https://pkg.go.dev/github.com/algorand/go-algorand/crypto
579: RustCrypto slh-dsa's `SigningKey::<Shake128f>::new`, `try_sign`, `verifying_key` gave nothing
    but the `use`. https://docs.rs/slh-dsa/latest/slh_dsa/
"""

from __future__ import annotations

from qrp_mcp.scan import scan_directory

LEANSIG = """use leansig::signature::SignatureScheme;
use leansig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W4;
type S = SIGWinternitzLifetime18W4;
"""


def _scan(tmp_path, files):
    for name, body in files.items():
        (tmp_path / name).write_text(body)
    return scan_directory(tmp_path)


def test_generalized_xmss_is_not_standardised_xmss(tmp_path):
    result = _scan(tmp_path, {"leansig.rs": LEANSIG})
    fams = {f["algorithm_family"]: f for f in result["findings"]}
    assert "XMSS" not in fams, fams.keys()
    g = fams["Generalized XMSS"]
    assert g["classification"] == "pqc_pre_standard"
    assert result["summary"]["pqc_readiness"] != "pqc_ready"


def test_rfc_8391_xmss_is_still_xmss(tmp_path):
    result = _scan(tmp_path, {"x.c": "#include <oqs/oqs.h>\nOQS_SIG_STFL *s = OQS_SIG_STFL_new(OQS_SIG_STFL_alg_xmss_sha256_h10);\n"})
    fams = {f["algorithm_family"]: f for f in result["findings"]}
    assert "XMSS" in fams and "Generalized XMSS" not in fams


SPX = """import pyspx.shake_128f
public_key, secret_key = pyspx.shake_128f.generate_keypair(seed)
signature = pyspx.shake_128f.sign(message, secret_key)
ok = pyspx.shake_128f.verify(message, signature, public_key)
"""
SPX_ALIAS = """import pyspx.shake_128f as sphincs
pk, sk = sphincs.generate_keypair(seed)
sig = sphincs.sign(m, sk)
"""


def test_pyspx_readme_spelling_is_round_3_sphincs(tmp_path):
    result = _scan(tmp_path, {"spx.py": SPX, "spx2.py": SPX_ALIAS})
    rows = result["evidence"]["source_code"]
    for path, lines in (("spx.py", (2, 3, 4)), ("spx2.py", (2, 3))):
        for n in lines:
            fams = {r["algorithm"] for r in rows if r["path"] == path and r["line"] == n}
            assert "SPHINCS+ round 3" in fams and "SLH-DSA" not in fams, (path, n, fams)
    assert "SLH-DSA" not in result["detected_algorithms"]


FALCON = """package main

import (
\t"github.com/algorand/falcon"
\t"github.com/algorand/go-algorand/crypto"
)

func run(seed []byte, msg []byte, fs crypto.FalconSeed) error {
\tpub, priv, _ := falcon.GenerateKey(seed)
\tsig, _ := priv.SignCompressed(msg)
\terr := pub.Verify(sig, msg)
\tsigner, _ := crypto.GenerateFalconSigner(fs)
\t_ = signer
\treturn err
}
"""


def test_algorand_falcon(tmp_path):
    rows = _scan(tmp_path, {"falcon.go": FALCON})["evidence"]["source_code"]
    lines = {r["line"] for r in rows if r["algorithm"] == "Falcon" and r["evidence_kind"] == "call"}
    assert {9, 10, 11, 12} <= lines, sorted((r["line"], r["algorithm"]) for r in rows)


SLH = """use slh_dsa::*;
use signature::*;
fn main() {
    let sk = SigningKey::<Shake128f>::new(&mut rng);
    let sig = sk.try_sign(message).unwrap();
    let vk = sk.verifying_key();
}
"""


def test_rustcrypto_slh_dsa_calls(tmp_path):
    rows = _scan(tmp_path, {"slh.rs": SLH})["evidence"]["source_code"]
    lines = {r["line"] for r in rows if r["algorithm"] == "SLH-DSA" and r["evidence_kind"] == "call"}
    assert {4, 5, 6} <= lines, sorted((r["line"], r["algorithm"], r["evidence_kind"]) for r in rows)


def test_hashsig_and_leansig_as_plain_words_are_not_a_scheme(tmp_path):
    result = _scan(tmp_path, {"b.c": "int f(void) { return hashsig; }\n",
                              "c.py": "hashsig = h(sig)\nleansig = 1\n"})
    assert "Generalized XMSS" not in {r["algorithm"] for r in result["evidence"]["source_code"]}


def test_go_algorand_crypto_import_alone_is_not_falcon(tmp_path):
    result = _scan(tmp_path, {"a.go": 'package main\n\nimport "github.com/algorand/go-algorand/crypto"\n\n'
                                      "func h(b []byte) crypto.Digest { return crypto.Hash(b) }\n"})
    assert "Falcon" not in {r["algorithm"] for r in result["evidence"]["source_code"]}
