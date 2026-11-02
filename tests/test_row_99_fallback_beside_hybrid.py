"""ZA-OPRAVYANE row 99 (LinkedIn 23.10.2026, Addie #4, Cherukuri #47; decided by Stanimir on
2 Nov 2026): nginx `X25519MLKEM768:X25519` and `X25519MLKEM768` both read `hybrid_partial`
with the same families and counts; only the evidence told them apart (SSH the same). The
classical group offered alone beside a hybrid stays a classical finding, and now carries
`fallback_beside_hybrid` with its places -- on the finding, in
`summary.by_role.key_establishment.fallback_beside_hybrid`, and on the CBOM component. A pure
hybrid carries none of it (the key is absent)."""

import json
import subprocess
import sys

import pytest


def _run(tmp_path, command, name, text):
    tree = tmp_path / command
    tree.mkdir()
    (tree / name).write_text(text, encoding="utf-8")
    out = tmp_path / f"{command}.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", command, str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


CASES = [
    ("nginx.conf", "ssl_ecdh_curve X25519MLKEM768:X25519;\n", "ssl_ecdh_curve X25519MLKEM768;\n",
     "X25519", "nginx.conf:1"),
    ("sshd_config", "KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n",
     "KexAlgorithms mlkem768x25519-sha256\n", "X25519", "sshd_config:1"),
]


@pytest.mark.parametrize("name, fallback, pure, family, place", CASES)
def test_a_fallback_is_marked_and_a_pure_hybrid_is_not(tmp_path, name, fallback, pure,
                                                       family, place):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    with_fallback = _run(tmp_path / "a", "scan", name, fallback)
    without = _run(tmp_path / "b", "scan", name, pure)
    finding = next(f for f in with_fallback["findings"] if f["algorithm_family"] == family)
    assert finding["classification"] == "classical_vulnerable"
    assert finding["fallback_beside_hybrid"] == [place]
    role = with_fallback["summary"]["by_role"]["key_establishment"]
    assert role["fallback_beside_hybrid"] == {family: [place]}
    assert "fallback_beside_hybrid" not in without["summary"]["by_role"]["key_establishment"]
    assert not any("fallback_beside_hybrid" in f for f in without["findings"])


@pytest.mark.parametrize("name, fallback, pure, family, place", CASES)
def test_the_cbom_marks_the_fallback(tmp_path, name, fallback, pure, family, place):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()

    def marked(doc):
        return [c["name"] for c in doc["components"]
                for p in c.get("properties", []) if p["name"] == "qrp:fallback_beside_hybrid"]

    assert marked(_run(tmp_path / "a", "cbom", name, fallback)) == [family]
    assert marked(_run(tmp_path / "b", "cbom", name, pure)) == []
