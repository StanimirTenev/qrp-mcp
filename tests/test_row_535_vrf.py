"""ZA-OPRAVYANE row 535 (LinkedIn, 19.11.2026): a VRF is its own role, not a signature.

The reproduction (`linkedin-postove/2026-11-19/chernovi/raw/proba/fx/ecvrf`, qrp-mcp 0.50.0): a
Go file that elects its leader with `vrf.Prove(seed, sk)` over an Ed25519 key and signs blocks with
ML-DSA-65. 0.50.0 read the Ed25519 import and type and the ML-DSA ones, and summed the file up as
`by_role.signature` = Ed25519 + ML-DSA, `hybrid_partial`; the VRF call had no row. Read so, the
output says "replace Ed25519 with ML-DSA and you are done", and the leader election stays classical.

ECVRF (RFC 9381) rests on elliptic-curve groups; its pseudorandomness on the decisional
Diffie-Hellman problem there (RFC 9381, 7.2, 7.3), which Shor's algorithm breaks. Its own family,
`ECVRF`, with its own role, `vrf`: a part of `by_role` beside key establishment and signatures,
present where a VRF is found. The documented spellings are in data/operations/vrf.toml.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

VRF_GO = """package consensus

import (
\t"crypto/ed25519"
\t"github.com/cloudflare/circl/sign/mldsa/mldsa65"
\tvrf "github.com/yahoo/coname/vrf"
)

func Propose(sk ed25519.PrivateKey, seed []byte) ([]byte, []byte) {
\t// ECVRF-EDWARDS25519-SHA512-ELL2 (RFC 9381) for leader election
\tproof, out := vrf.Prove(seed, sk)
\treturn proof, out
}

func SignBlock(sk *mldsa65.PrivateKey, b []byte) []byte {
\tsig, _ := sk.Sign(nil, b, nil)
\treturn sig
}
"""
GO_MOD = """module example.com/chain
go 1.22
require (
\tgithub.com/cloudflare/circl v1.4.0
\tgithub.com/yahoo/coname v0.0.0-20170609175141-84592ddf8673
)
"""


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return root


def _rows(result: dict, family: str) -> list[dict]:
    return [r for r in result["evidence"]["source_code"]
            if isinstance(r, dict) and r.get("algorithm") == family]


def test_the_vrf_call_is_a_row_of_its_own_family(tmp_path):
    result = scan_directory(str(_tree(tmp_path, {"vrf.go": VRF_GO, "go.mod": GO_MOD})))
    rows = {(r["path"], r["line"]): r for r in _rows(result, "ECVRF")}
    assert ("vrf.go", 11) in rows, rows
    assert rows[("vrf.go", 11)]["evidence_kind"] == "call"
    # The import of the VRF package names it too.
    assert ("vrf.go", 6) in rows
    # The comment names a suite; a comment is never a use.
    assert rows.get(("vrf.go", 10), {}).get("evidence_kind", "comment") == "comment"
    finding = next(f for f in result["findings"] if f["algorithm_family"] == "ECVRF")
    assert finding["classification"] == "classical_vulnerable"


def test_the_summary_names_the_vrf_apart_from_the_signatures(tmp_path):
    result = scan_directory(str(_tree(tmp_path, {"vrf.go": VRF_GO, "go.mod": GO_MOD})))
    by_role = result["summary"]["by_role"]
    assert by_role["vrf"] == {"families": ["ECVRF"], "pqc_readiness": "classical_only"}
    assert "ECVRF" not in by_role["signature"]["families"]
    assert "ECVRF" not in by_role["key_establishment"]["families"]
    said = result["summary"]["readiness_by_role"]
    assert said["vrf"] == "classical_only"
    assert said["roles_differ"] is True
    # The headline is not ready: a classical VRF is beside the post-quantum signature.
    assert result["summary"]["pqc_readiness"] != "pqc_ready"


def test_no_signature_scheme_is_offered_for_the_vrf(tmp_path):
    result = scan_directory(str(_tree(tmp_path, {"vrf.go": VRF_GO, "go.mod": GO_MOD})))
    finding = next(f for f in result["findings"] if f["algorithm_family"] == "ECVRF")
    text = json.dumps(finding.get("replacement") or finding.get("remediation") or {})
    for scheme in ("ML-DSA", "SLH-DSA", "ML-KEM", "FIPS 204", "FIPS 205"):
        assert scheme not in text, (scheme, text)
    # Said, not left blank: no option, and why (mutation round of 0.51.0: without the entry the
    # finding had no replacement at all, and the line above still passed).
    replacement = finding["replacement"]
    assert replacement["options"] == []
    assert "verifiable random function" in replacement["note"]


def test_a_scan_without_a_vrf_keeps_its_shape(tmp_path):
    result = scan_directory(str(_tree(tmp_path, {"a.go": 'package a\nimport "crypto/ed25519"\n'
                                                         "var k ed25519.PrivateKey\n"})))
    assert set(result["summary"]["by_role"]) == {"key_establishment", "signature",
                                                 "role_not_determined"}
    assert set(result["summary"]["readiness_by_role"]) == {"key_establishment", "signature",
                                                           "roles_differ"}


def test_vrf_in_a_network_config_is_not_a_vrf(tmp_path):
    # Virtual routing and forwarding: the same three letters, nothing cryptographic.
    files = {"router.cfg": "vrf definition MGMT\n rd 65000:1\nip vrf forwarding MGMT\n",
             "r.go": 'package r\nfunc f(vrf Table) { vrf.Prove(x, y); vrf.Verify(a, b, c, d) }\n',
             "junos.conf": "routing-instances { CUST { instance-type vrf; vrf-target target:1:1; } }\n"}
    result = scan_directory(str(_tree(tmp_path, files)))
    assert _rows(result, "ECVRF") == []
    assert "vrf" not in result["summary"]["by_role"]


def _cli(root: Path, out: Path, command: str) -> dict:
    run = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                          command, str(root), "--out", str(out)],
                         capture_output=True, text=True, timeout=300)
    assert out.exists(), run.stderr
    return json.loads(out.read_text())


def test_the_three_exits_carry_it(tmp_path):
    root = _tree(tmp_path / "t", {"vrf.go": VRF_GO, "go.mod": GO_MOD})
    scanned = _cli(root, tmp_path / "scan.json", "scan")
    assert scanned["summary"]["by_role"]["vrf"]["families"] == ["ECVRF"]
    tool = scan_repo(path=str(root))
    assert tool["summary"]["by_role"]["vrf"]["families"] == ["ECVRF"]
    cbom = _cli(root, tmp_path / "cbom.json", "cbom")
    names = {c.get("name") for c in cbom.get("components", [])}
    assert "ECVRF" in names, names
    component = next(c for c in cbom["components"] if c.get("name") == "ECVRF")
    props = component["cryptoProperties"]["algorithmProperties"]
    assert props["primitive"] == "other"
    assert props.get("nistQuantumSecurityLevel") == 0


def test_a_package_call_beside_go_ecvrf_is_not_a_vrf(tmp_path):
    # Independent review before the release (19.11): in a file importing go-ecvrf, any `.Verify(`
    # was read as the VRF's -- `ed25519.Verify(pub, msg, sig)` too.
    body = ('package v\n\nimport (\n\t"crypto/ed25519"\n\t"github.com/ProtonMail/go-ecvrf/ecvrf"\n)\n\n'
            "func F(sk *ecvrf.PrivateKey, pub ed25519.PublicKey, msg, sig []byte) bool {\n"
            "\tsk.Prove(msg)\n\treturn ed25519.Verify(pub, msg, sig)\n}\n")
    result = scan_directory(str(_tree(tmp_path, {"v.go": body})))
    lines = {r["line"] for r in _rows(result, "ECVRF")}
    assert 9 in lines and 10 not in lines, lines


# Second independent review (19.11): an import with a trailing comment, calls on any receiver, and
# the keytransparency import that gave no row.
REVIEW_A = """package a

import (
\t"crypto/ed25519" // signatures
\t"crypto/x509"

\t"github.com/ProtonMail/go-ecvrf/ecvrf"
)

func A(pub ed25519.PublicKey, m, s []byte, cert *x509.Certificate, sk *ecvrf.PrivateKey) bool {
\t_, _ = ecvrf.GenerateKey(nil)
\tok := ed25519.Verify(pub, m, s)
\t_, err := cert.Verify(x509.VerifyOptions{})
\t_, _, _ = sk.Prove(m)
\treturn ok && err == nil
}
"""
REVIEW_B = """package b

import (
\t"github.com/google/keytransparency/core/crypto/vrf/p256"
)

func B(policy Policy, k *p256.PrivateKey) {
\tpolicy.Evaluate(nil)
\tk.Evaluate(nil)
}
"""


def test_only_calls_on_a_vrf_key_are_the_vrfs(tmp_path):
    result = scan_directory(str(_tree(tmp_path, {"a.go": REVIEW_A, "b.go": REVIEW_B})))
    rows = {(r["path"], r["line"]): r["evidence_kind"] for r in _rows(result, "ECVRF")}
    assert ("a.go", 12) not in rows      # ed25519.Verify, the import with a comment
    assert ("a.go", 13) not in rows      # cert.Verify
    assert rows.get(("a.go", 14)) == "call" and rows.get(("a.go", 11)) == "call"
    assert ("b.go", 8) not in rows       # policy.Evaluate
    assert rows.get(("b.go", 9)) == "call"


def test_the_keytransparency_import_is_a_row(tmp_path):
    body = 'package b\n\nimport (\n\t"github.com/google/keytransparency/core/crypto/vrf/p256"\n)\n\nfunc B(k *p256.PrivateKey) {}\n'
    result = scan_directory(str(_tree(tmp_path, {"b.go": body})))
    assert [(r["line"], r["evidence_kind"]) for r in _rows(result, "ECVRF")] == [(4, "import")]


def test_a_blank_identifier_is_not_a_key(tmp_path):
    # `_, _ = ecvrf.GenerateKey(nil)` names no key: no `.Verify(` in the file is the VRF's.
    body = REVIEW_A.replace(", sk *ecvrf.PrivateKey", "").replace("\t_, _, _ = sk.Prove(m)\n", "")
    result = scan_directory(str(_tree(tmp_path, {"a.go": body})))
    # The import row is dropped once the file has a call of the family, as for every family.
    assert sorted(r["line"] for r in _rows(result, "ECVRF")) == [11]


def test_an_ed25519_key_seen_only_beside_a_vrf_call_is_not_counted_as_a_signature(tmp_path):
    # Second independent review (19.11): the reproduction still read `signature` = Ed25519 + ML-DSA.
    # Its Ed25519 rows are the import and the type of the key handed to vrf.Prove; no Ed25519 call.
    result = scan_directory(str(_tree(tmp_path, {"vrf.go": VRF_GO, "go.mod": GO_MOD})))
    by_role = result["summary"]["by_role"]
    assert by_role["signature"]["families"] == ["ML-DSA"]
    assert "Ed25519" in by_role["role_not_determined"]
    assert by_role["vrf"]["families"] == ["ECVRF"]


def test_an_ed25519_call_keeps_it_a_signature(tmp_path):
    body = VRF_GO.replace("\treturn proof, out\n", "\t_ = ed25519.Sign(sk, seed)\n\treturn proof, out\n")
    result = scan_directory(str(_tree(tmp_path, {"vrf.go": body, "go.mod": GO_MOD})))
    assert "Ed25519" in result["summary"]["by_role"]["signature"]["families"]
    assert "Ed25519" not in result["summary"]["by_role"]["role_not_determined"]
