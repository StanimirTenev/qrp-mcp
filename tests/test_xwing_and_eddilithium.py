"""Two shipped hybrids that were invisible (ZA-OPRAVYANE row 77, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_r13`).

X-Wing is ML-KEM-768 with X25519 (CIRCL kem/xwing/xwing.go; libsodium crypto_kem_xwing.h).
CIRCL's eddilithium2 is Ed25519-Dilithium2 and eddilithium3 is Ed448-Dilithium3 (their
package comments). Read 23.10.2026.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("name, line", [
    ("p.go", 'import "github.com/cloudflare/circl/kem/xwing"'),
    ("p.c", "crypto_kem_xwing_keypair(pk, sk);"),
])
def test_xwing_names_both_halves(tmp_path, name, line):
    (tmp_path / name).write_text(line + "\n", encoding="utf-8")
    assert {"ML-KEM", "X25519"} <= set(scan_directory(tmp_path)["detected_algorithms"])


@pytest.mark.parametrize("line, classical", [
    ('import "github.com/cloudflare/circl/sign/eddilithium2"', "Ed25519"),
    ('import "github.com/cloudflare/circl/sign/eddilithium3"', "Ed448"),
])
def test_eddilithium_names_both_halves(tmp_path, line, classical):
    (tmp_path / "p.go").write_text(line + "\n", encoding="utf-8")
    assert {"ML-DSA", classical} <= set(scan_directory(tmp_path)["detected_algorithms"])


def test_a_starfighter_is_not_a_kem(tmp_path):
    (tmp_path / "game.py").write_text('ship = Ship("X-Wing", speed=12)\n', encoding="utf-8")
    assert "ML-KEM" not in scan_directory(tmp_path)["detected_algorithms"]
