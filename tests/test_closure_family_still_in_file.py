"""A family that stays in the same file is changed, not closed (fix list row 218).

Measured on 0.40.1 with a crypto-agility change: a verifier that keeps a branch for old
Ed25519 proofs beside the new ML-DSA one. The statement said "2 occurrence(s) closed", while
`per_family_before_after` gave Ed25519 [2, 2]: the old lines of verifier.py were "closed" and
the Ed25519 lines written in the same file were "new". The sentence and the counts disagreed.

Now an occurrence that left a file in which the second run finds the same family again is
paired with that occurrence and listed under `changed`, neither closed nor new; and the
statement names the families that did not fall to 0.
"""

import json

from qrp_mcp import closure
from qrp_mcp.server import prove_closure



def _result(items, commit="aaa"):
    """A comparable scan result (the shape tests/test_closure.py builds)."""
    return {
        "excerpt_level": "full",
        "coverage": {
            "instrument": {"version": "0.19.0",
                           "source_commit": {"pinned": True, "commit": "tool1", "dirty": False},
                           "ruleset": {"algorithm_patterns": 48},
                           "claimed_types": {"source": [".py"]}, "excluded_dirs": [".git"]},
            "corpus": {"target": "/repo", "pinned_at": {"pinned": True, "kind": "git",
                                                        "commit": commit, "dirty": False}},
        },
        "evidence": {"source_code": items},
        "unreadable_files": [], "files_left_out": [], "unreadable_directories": [],
        "symlinks_not_followed": [],
        "files_read": sorted({"a.py"} | {i["path"] for i in items}),
    }


def _ed(path, line, kind, excerpt):
    return {"path": path, "line": line, "algorithm": "Ed25519", "description": "Ed25519",
            "excerpt": excerpt, "evidence_kind": kind, "in_test_code": False}


def _mldsa(path, line, excerpt):
    return {"path": path, "line": line, "algorithm": "ML-DSA", "description": "ML-DSA",
            "excerpt": excerpt, "evidence_kind": "call", "in_test_code": False}


BEFORE = [_ed("signer.py", 3, "call", "def sign_proof(key: Ed25519PrivateKey, proof):"),
          _ed("verifier.py", 3, "call", "def verify_proof(pub: Ed25519PublicKey, sig, proof):")]
AFTER = [_mldsa("signer.py", 4, 'with oqs.Signature("ML-DSA-65", secret_key) as signer:'),
         _ed("verifier.py", 2, "import", "from ...ed25519 import Ed25519PublicKey"),
         _ed("verifier.py", 5, "declaration", 'if alg == "ed25519":'),
         _mldsa("verifier.py", 8, 'with oqs.Signature("ML-DSA-65") as v:')]


def test_the_verifier_that_keeps_ed25519_is_changed_not_closed(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(_result(BEFORE)))
    b.write_text(json.dumps(_result(AFTER, commit="bbb")))
    out = prove_closure(str(a), str(b))
    c = out["closure"]
    # signer.py has no Ed25519 left: that one is closed.
    assert [(i["path"], i["line"]) for i in c["closed"]] == [("signer.py", 3)]
    assert [(i["path"], i["line"], i["now_line"]) for i in c["changed"]] == [
        ("verifier.py", 3, 2)]
    assert sorted((i["path"], i["line"], i["algorithm"]) for i in c["new"]) == [
        ("signer.py", 4, "ML-DSA"), ("verifier.py", 5, "Ed25519"), ("verifier.py", 8, "ML-DSA")]
    assert c["per_family_before_after"]["Ed25519"] == [2, 2]
    assert out["statement"].startswith("1 occurrence(s) closed, 1 changed in place")
    assert "Not down to 0 in the second tree: Ed25519 (2 -> 2)." in out["statement"]


def test_a_family_gone_from_every_file_is_named_nowhere():
    after = _result([], commit="bbb")
    after["files_read"] = ["signer.py"]
    out = closure.prove_closure(_result(BEFORE[:1]), after)
    assert len(out["closure"]["closed"]) == 1 and out["closure"]["changed"] == []
    assert "Not down to 0" not in out["statement"]
