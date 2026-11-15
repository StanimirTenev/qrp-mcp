"""Row 463 (15.11.2026, QCI CBOM-Benchmark 2.6.6 cross-run): PQC-washing believed from names.

`self.mlkem_key = ec.generate_private_key(ec.SECP256R1())`, `def kyber_exchange(...)` and
`class MlkemSession` gave ML-KEM and Kyber as `call` at high, and a file doing ECDH on P-256
alone read `pqc_readiness: hybrid_partial` with ML-KEM `pqc_ready`. The same in Java with a
`KeyPair mlKemKeyPair` field. A post-quantum name that is only a piece of a name the file
itself defines is now an identifier row: low, and the family is not counted (identifier_only)
on any of the three exits -- `scan --out`, the MCP tools, the CBOM.

The fixtures are written here, after the shape of QCI's `corpus/pqc/python/pq_washing.py` and
`corpus/pqc/java/PqWashing.java` (CBOM-Benchmark, Apache-2.0, v2.6.6 2c18af2); no file is copied.
The other side is pinned too: a string literal, a library's own name and a config value stay uses.
"""

import json
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

PY_WASHING = (
    '"""Quantum-safe channel (ML-KEM-768). Approved for post-quantum workloads."""\n'
    "from cryptography.hazmat.primitives.asymmetric import ec\n"
    "\n"
    "class MlkemSession:\n"
    "    def __init__(self):\n"
    "        self.mlkem_key = ec.generate_private_key(ec.SECP256R1())\n"
    "\n"
    "    def kyber_exchange(self, peer_public) -> bytes:\n"
    "        return self.mlkem_key.exchange(ec.ECDH(), peer_public)\n"
    "\n"
    "a, b = MlkemSession(), MlkemSession()\n"
    "print(a.kyber_exchange(b.mlkem_key.public_key()))\n"
)

JAVA_WASHING = (
    "import java.security.KeyPair;\n"
    "import java.security.KeyPairGenerator;\n"
    "import java.security.spec.ECGenParameterSpec;\n"
    "import javax.crypto.KeyAgreement;\n"
    "\n"
    "/** QuantumSafeVault: ML-KEM-1024 key establishment. */\n"
    "public class Vault {\n"
    "    private final KeyPair mlKemKeyPair;\n"
    "    Vault() throws Exception {\n"
    '        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");\n'
    '        kpg.initialize(new ECGenParameterSpec("secp384r1"));\n'
    "        this.mlKemKeyPair = kpg.generateKeyPair();\n"
    "    }\n"
    "    byte[] kyberAgree(Vault peer) throws Exception {\n"
    '        KeyAgreement ka = KeyAgreement.getInstance("ECDH");\n'
    "        ka.init(mlKemKeyPair.getPrivate());\n"
    "        ka.doPhase(peer.mlKemKeyPair.getPublic(), true);\n"
    "        return ka.generateSecret();\n"
    "    }\n"
    "}\n"
)

PQ = {"ML-KEM", "Kyber"}


def cli(*args):
    """The command line as a user runs it: a separate process through the entry point."""
    done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                           *args], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def _pq_uses(result):
    return [o for o in result["evidence"]["source_code"]
            if o["algorithm"] in PQ and o["evidence_kind"] not in ("comment", "identifier")]


def _assert_washing_not_believed(result):
    assert _pq_uses(result) == [], _pq_uses(result)
    summary = result["summary"]
    assert summary["pqc_readiness"] == "classical_only", summary["pqc_readiness"]
    assert summary["pqc_ready_count"] == 0 and summary["pqc_pre_standard_count"] == 0
    assert summary["by_role"]["key_establishment"]["pqc_readiness"] != "hybrid_partial"
    for f in result["findings"]:
        if f["algorithm_family"] in PQ:
            assert f.get("identifier_only") is True, f


def test_python_washing_names_are_identifiers(tmp_path):
    (tmp_path / "pq_washing.py").write_text(PY_WASHING)
    result = scan_directory(tmp_path)
    _assert_washing_not_believed(result)
    rows = {(o["line"], o["algorithm"]): o["evidence_kind"] for o in result["evidence"]["source_code"]}
    # The class line, the assignment, the def, the receiver and the uses of the class all flip.
    for line, family in ((4, "ML-KEM"), (6, "ML-KEM"), (8, "Kyber"), (9, "ML-KEM"),
                         (11, "ML-KEM"), (12, "ML-KEM")):
        assert rows[(line, family)] == "identifier", (line, family, rows)
    # The classical code is still read as what it is.
    assert rows[(6, "EC")] == "call" and rows[(9, "ECDH")] == "call"


def test_java_washing_names_are_identifiers(tmp_path):
    (tmp_path / "Vault.java").write_text(JAVA_WASHING)
    result = scan_directory(tmp_path)
    _assert_washing_not_believed(result)
    families = {f["algorithm_family"] for f in result["findings"] if not f.get("identifier_only")}
    assert {"EC", "ECDH"} <= families


def test_washing_leaves_by_the_cli(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "pq_washing.py").write_text(PY_WASHING)
    out = tmp_path / "scan.json"
    cli("scan", str(src), "--out", str(out), "--no-config")
    _assert_washing_not_believed(json.loads(out.read_text()))


def test_washing_leaves_by_the_mcp_tool(tmp_path):
    (tmp_path / "pq_washing.py").write_text(PY_WASHING)
    result = getattr(scan_repo, "fn", scan_repo)(str(tmp_path))
    _assert_washing_not_believed(result)


def _ml_kem_component(bom):
    return [c for c in bom["components"] if c.get("type") == "cryptographic-asset"
            and c["name"].startswith(("ML-KEM", "Kyber"))]


def test_washing_in_the_cbom_is_marked_identifier_only(tmp_path):
    (tmp_path / "pq_washing.py").write_text(PY_WASHING)
    for bom in (build(scan_directory(tmp_path)),
                getattr(export_cbom, "fn", export_cbom)(str(tmp_path))):
        bom = bom if isinstance(bom, dict) else json.loads(bom)
        pq = _ml_kem_component(bom)
        assert pq
        for c in pq:
            props = {p["name"]: p["value"] for p in c.get("properties", [])}
            assert props.get("qrp:identifier_only") == "true", (c["name"], props)
            kinds = json.loads(props["qrp:evidence_kind"])
            assert set(kinds) <= {"comment", "identifier"}, kinds


def test_cbom_cli_marks_identifier_only(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "pq_washing.py").write_text(PY_WASHING)
    out = tmp_path / "bom.json"
    cli("cbom", str(src), "--out", str(out), "--no-config")
    pq = _ml_kem_component(json.loads(out.read_text()))
    assert pq and all({"name": "qrp:identifier_only", "value": "true"} in c["properties"]
                      for c in pq)


# -- the other side: real post-quantum use stays a use ---------------------------------------

REAL = {
    "oqs_kem.py": ('import oqs\n'
                   'kem = oqs.KeyEncapsulation("ML-KEM-768")\n'
                   'pk = kem.generate_keypair()\n'),
    "pqcrypto_kem.py": ("from pqcrypto.kem import ml_kem_768\n"
                        "pk, sk = ml_kem_768.generate_keypair()\n"),
    "kem.go": ('package main\n\nimport "crypto/mlkem"\n\n'
               "func main() {\n\tdk, _ := mlkem.GenerateKey768()\n\t_ = dk\n}\n"),
    "Bc.java": ("import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;\n"
                "class Bc {\n"
                '    void k() throws Exception { var g = java.security.KeyPairGenerator.getInstance("ML-KEM"); }\n'
                "}\n"),
    "node_kem.js": ("const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');\n"
                    "const keys = ml_kem768.keygen();\n"),
    "var_named_like_the_lib.js": ("const mlkem = require('mlkem');\n"
                                  "const k = mlkem.encapsulate(pub);\n"),
}


def test_real_ml_kem_use_is_still_a_use_and_counted(tmp_path):
    for name, text in REAL.items():
        d = tmp_path / name.replace(".", "_")
        d.mkdir()
        (d / name).write_text(text)
        result = scan_directory(d)
        uses = [o for o in result["evidence"]["source_code"] if o["algorithm"] == "ML-KEM"
                and o["evidence_kind"] not in ("comment", "identifier", "ban")]
        assert uses, (name, result["evidence"]["source_code"])
        ml_kem = [f for f in result["findings"] if f["algorithm_family"] == "ML-KEM"]
        assert ml_kem and not ml_kem[0].get("identifier_only"), name
        assert result["summary"]["pqc_ready_count"] >= 1, name


def test_a_defined_name_beside_a_real_call_keeps_the_call(tmp_path):
    (tmp_path / "w.py").write_text(
        "from pqcrypto.kem import ml_kem_768\n"
        "mlkem_keys = ml_kem_768.generate_keypair()\n"
        "def mlkem_encaps(pk):\n"
        "    return ml_kem_768.encrypt(pk)\n")
    result = scan_directory(tmp_path)
    rows = {o["line"]: o["evidence_kind"] for o in result["evidence"]["source_code"]
            if o["algorithm"] == "ML-KEM"}
    assert rows[2] == "call" and rows[4] == "call", rows
    assert rows[3] == "identifier", rows
    assert result["summary"]["pqc_ready_count"] == 1


def test_a_config_value_is_not_an_identifier(tmp_path):
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519MLKEM768:X25519;\n")
    result = scan_directory(tmp_path)
    assert result["summary"]["pqc_ready_count"] >= 1
    assert not any(f.get("identifier_only") for f in result["findings"]
                   if f["algorithm_family"] == "ML-KEM")
