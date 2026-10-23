"""Falcon's padded variant (ZA-OPRAVYANE row 76, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_r12`). Names from liboqs src/sig/sig.h, oqs-provider
ALGORITHMS.md (read 23.10.2026) and PQClean crypto_sign/falcon-padded-512/clean/api.h as the
swarm fetched it. wolfSSL's wc_falcon_* and Bouncy Castle's FalconSigner are pinned in
test_wolfcrypt_names.py and test_bouncycastle_classes.py."""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("line", [
    "OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_falcon_padded_512);",
    "PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);",
    'EVP_PKEY_Q_keygen(NULL, NULL, "falconpadded1024");',
])
def test_falcon_padded(tmp_path, line):
    (tmp_path / "p.c").write_text(line + "\n", encoding="utf-8")
    assert "Falcon" in scan_directory(tmp_path)["detected_algorithms"]
