"""ZA-OPRAVYANE row 527 (probe qrp-kachestvo/obhvat-simetrichno-2026-11-17, 0.48.0): AES-128 and
SHA-256 in code, and `--mandate cnsa-2.0` said `pass` with `in_scope: 0`, though CNSA 2.0 requires
AES-256 and SHA-384/512 (profiles.py says so) -- a silent pass.

The scan does not read symmetric ciphers or hashes (out of scope by design, row 525), so it cannot
count their sizes against a document. Four of the mandates it ships date symmetric or hash
algorithms (qrp-kachestvo/obhvat-razuznavane/01-grover-simetrichno.md, quotes checked against the
local copies): CNSA 2.0 (AES-256, SHA-384/512, already required), the ISM (AES-128/192,
SHA-224/256 and HMAC-SHA256 not approved beyond 2030, "for interoperability and maintainability
reasons"), ITSP.40.111 and NIST IR 8547 (the 112-bit tail by 2030). Each of their blocks now says
`symmetric.status: not_established` with the document's own words, and a gate that would pass
reads `not_established` (the exit code stays that of a pass), as row 204 does for unread files.
The ten other documents date public-key cryptography only and keep `pass`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SYM_JAVA = """import javax.crypto.KeyGenerator;
import java.security.MessageDigest;
public class Sym { public static void main(String[] a) throws Exception {
  KeyGenerator kg = KeyGenerator.getInstance("AES"); kg.init(128);
  MessageDigest md = MessageDigest.getInstance("SHA-256"); } }
"""
SYM_PY = """from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os
key = os.urandom(16)
c = Cipher(algorithms.AES(key), modes.GCM(os.urandom(12)))
h = hashes.Hash(hashes.SHA256())
"""

DATING = ("cnsa-2.0", "au-ism", "ca-cccs", "nist-ir-8547")


def _tree(tmp_path: Path) -> Path:
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "Sym.java").write_text(SYM_JAVA)
    (tree / "sym.py").write_text(SYM_PY)
    return tree


def _run(tmp_path: Path, *names: str, extra: tuple[str, ...] = ()):
    out = tmp_path / "r.json"
    args = [a for n in names for a in ("--mandate", n)]
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(_tree(tmp_path)),
                        "--no-config", *args, "--as-of", "2026-11-17", *extra,
                        "--out", str(out)], capture_output=True, text=True)
    return r.returncode, json.loads(out.read_text())


@pytest.mark.parametrize("name", DATING)
def test_no_silent_pass_on_aes_128_and_sha_256(tmp_path, name):
    code, result = _run(tmp_path, name)
    block = result["mandates"][name]
    assert result["findings"] == []
    assert block["gate"] == "not_established", block
    assert "symmetric" in block["gate_not_established_because"]
    sym = block["symmetric"]
    assert sym["status"] == "not_established" and sym["evaluated"] is False
    assert sym["document_says"] and all(q["quote"] and q["source"] for q in sym["document_says"])
    assert code == 0


def test_the_quotes_are_the_documents_words(tmp_path):
    _, result = _run(tmp_path, *DATING)
    said = {n: " ".join(q["quote"] for q in result["mandates"][n]["symmetric"]["document_says"])
            for n in DATING}
    assert "Use 256-bit keys for all classification levels" in said["cnsa-2.0"]
    assert "Use SHA-384 or SHA-512 for all classification levels" in said["cnsa-2.0"]
    assert ("For interoperability and maintainability reasons, AES-128 and AES-192 will not be "
            "approved beyond 2030.") in said["au-ism"]
    assert ("For interoperability and maintainability reasons, SHA-224 and SHA-256 will not be "
            "approved beyond 2030.") in said["au-ism"]
    assert "HMAC-SHA256 will not be approved beyond 2030" in said["au-ism"]
    assert "SHA-224 should be phased out by the end of 2030." in said["ca-cccs"]
    assert "at the 112-bit security level, which will be disallowed in 2030" in said["nist-ir-8547"]


@pytest.mark.parametrize("name", ["eu-pqc-roadmap", "uk-ncsc", "de-bsi"])
def test_a_document_that_dates_public_key_only_still_passes(tmp_path, name):
    code, result = _run(tmp_path, name)
    block = result["mandates"][name]
    assert block["gate"] == "pass" and code == 0
    assert "symmetric" not in block


def test_a_failing_gate_is_not_softened(tmp_path):
    tree = tmp_path / "f"
    tree.mkdir()
    (tree / "k.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                               "k = rsa.generate_private_key(public_exponent=65537, "
                               "key_size=2048)\n")
    out = tmp_path / "f.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree), "--no-config",
                        "--mandate", "au-ism", "--as-of", "2026-11-17", "--lead-months", "60",
                        "--out", str(out)], capture_output=True, text=True)
    block = json.loads(out.read_text())["mandates"]["au-ism"]
    assert block["gate"] == "fail" and r.returncode == 1
    assert block["symmetric"]["status"] == "not_established"


def test_the_fingerprint_does_not_move_with_a_mandate(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _, without = _run(a)
    _, with_ = _run(b, *DATING, "il-boi")
    assert without["findings_fingerprint"]["sha256"] == with_["findings_fingerprint"]["sha256"]
