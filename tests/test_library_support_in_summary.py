"""A hybrid group the pinned image cannot negotiate is not counted as ready
(ZA-OPRAVYANE row 55, the summary probe of 22.10.2026).

`evidence.library_support` already said it: nginx:1.24.0 carries OpenSSL 1.1.1 and cannot
negotiate X25519MLKEM768, which the nginx configuration asks for. The ML-KEM finding still
said `pqc_ready`, `pqc_ready_count` counted it, the summary said `hybrid_partial`, and the
CBOM's ML-KEM component said `pqc_ready` with nothing joining it to the image. The finding
now names the image (`not_negotiable_by`), the summary leaves it out of what reassures, and
the CBOM component carries the same property. The classification is not changed: ML-KEM is
standardised, the image is what cannot speak it.
"""

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

NGINX = "server {\n  listen 443 ssl;\n  ssl_ecdh_curve X25519MLKEM768;\n  ssl_protocols TLSv1.3;\n}\n"
COMPOSE = "services:\n  web:\n    image: nginx:1.24.0\n"
KEM = "from pqcrypto.kem.ml_kem_768 import generate_keypair\npk, sk = generate_keypair()\n"


def _scan(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)


def _mlkem(result):
    return next(f for f in result["findings"] if f["algorithm_family"] == "ML-KEM")


def test_unnegotiable_hybrid_is_named_and_not_counted(tmp_path):
    result = _scan(tmp_path, {"nginx.conf": NGINX, "docker-compose.yml": COMPOSE})
    finding = _mlkem(result)
    assert finding["not_negotiable_by"] == ["nginx:1.24.0 (docker-compose.yml:3)"]
    assert result["summary"]["pqc_ready_count"] == 0
    assert result["summary"]["pqc_readiness"] == "classical_only"
    mlkem = next(c for c in build(result)["components"] if c["name"] == "ML-KEM")
    props = {p["name"]: p["value"] for p in mlkem["properties"]}
    assert props["qrp:not_negotiable_by"] == '["nginx:1.24.0 (docker-compose.yml:3)"]'


def test_mlkem_used_in_code_as_well_still_counts(tmp_path):
    """The image limits the TLS place, not ML-KEM used by the code beside it."""
    result = _scan(tmp_path, {"nginx.conf": NGINX, "docker-compose.yml": COMPOSE,
                              "kem.py": KEM})
    assert "not_negotiable_by" not in _mlkem(result)
    assert result["summary"]["pqc_ready_count"] == 1
    assert result["summary"]["pqc_readiness"] == "hybrid_partial"


def test_without_a_pinned_image_nothing_changes(tmp_path):
    result = _scan(tmp_path, {"nginx.conf": NGINX})
    assert "not_negotiable_by" not in _mlkem(result)
    assert result["summary"]["pqc_ready_count"] == 1
