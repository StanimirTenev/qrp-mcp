"""The summary does not reassure from test code (ZA-OPRAVYANE row 62, the first half;
the summary probe of 22.10.2026).

The only ML-KEM was in tests/; production code was EC only. The JSON summary said
`hybrid_partial` with `pqc_ready_count` 1, the finding said nothing about test code, and
the CBOM marked the same component `scope: excluded`. Two outputs of one scan disagreed on
whether post-quantum is deployed. A family found only in test code now carries
`in_test_code: true`, and a post-quantum one is set aside from what reassures. Deliberately
one-sided: test-only RSA is still counted as vulnerable, as before.
"""

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

PQ_TEST = "from pqcrypto.kem.ml_kem_768 import generate_keypair\npk, sk = generate_keypair()\n"
EC_APP = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
          "k = ec.generate_private_key(ec.SECP256R1())\n")


def _scan(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)


def _finding(result, family):
    return next(f for f in result["findings"] if f["algorithm_family"] == family)


def test_test_only_pq_is_named_and_not_counted(tmp_path):
    result = _scan(tmp_path, {"tests/test_pq.py": PQ_TEST, "src/app.py": EC_APP})
    assert _finding(result, "ML-KEM")["in_test_code"] is True
    assert "in_test_code" not in _finding(result, "EC")
    assert result["summary"]["pqc_ready_count"] == 0
    assert result["summary"]["pqc_readiness"] == "classical_only"
    mlkem = next(c for c in build(result)["components"] if c["name"] == "ML-KEM")
    assert mlkem["scope"] == "excluded"


def test_pq_in_production_as_well_still_counts(tmp_path):
    result = _scan(tmp_path, {"tests/test_pq.py": PQ_TEST, "src/kem.py": PQ_TEST,
                              "src/app.py": EC_APP})
    assert "in_test_code" not in _finding(result, "ML-KEM")
    assert result["summary"]["pqc_readiness"] == "hybrid_partial"


def test_test_only_classical_still_warns(tmp_path):
    result = _scan(tmp_path, {"tests/test_ec.py": EC_APP})
    assert _finding(result, "EC")["in_test_code"] is True
    assert result["summary"]["pqc_readiness"] == "classical_only"
