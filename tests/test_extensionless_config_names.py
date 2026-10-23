"""Configuration files with a well-known name and no extension (ZA-OPRAVYANE row 79, swarm C
of 22.10.2026, `roy-2026-10-22/c-korpus` test_c1; and row 103a, FreeRADIUS).

oqs-demos keeps 17 Dockerfile* with `SIG_ALG=mldsa65`/`DEFAULT_GROUPS=...mlkem768`, mcuboot's
boot/zephyr/Kconfig selects the signature type, and FreeRADIUS keeps EAP-TLS in
raddb/mods-available/eap: all were "no extension", unread.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("rel, text, family", [
    ("Dockerfile", 'FROM debian:stable-slim\nARG SIG_ALG="mldsa65"\n', "ML-DSA"),
    ("curl/Dockerfile-QUIC", 'ARG DEFAULT_GROUPS="x25519:mlkem768"\n', "ML-KEM"),
    ("app.Dockerfile", 'ARG SIG_ALG="mldsa65"\n', "ML-DSA"),
    ("Containerfile", 'ARG KEM_ALG="mlkem768"\n', "ML-KEM"),
    ("boot/zephyr/Kconfig", "config BOOT_SIGNATURE_TYPE_ECDSA_P256\n"
                            '\tbool "ECDSA signatures over P-256"\n', "ECDSA"),
    ("Caddyfile", "example.com {\n  tls {\n    curves x25519mlkem768\n  }\n}\n", "ML-KEM"),
    ("raddb/mods-available/eap", 'tls-config tls-common {\n  ecdh_curve = "prime256v1"\n}\n',
     "EC"),
    ("nginx/sites-available/default", "ssl_ecdh_curve X25519MLKEM768;\n", "ML-KEM"),
])
def test_read_and_named(tmp_path, rel, text, family):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    result = scan_directory(tmp_path)
    assert rel in result["files_read"], result["files_skipped_by_type"]
    assert family in result["detected_algorithms"]


def test_an_unrelated_extensionless_file_is_still_not_claimed(tmp_path):
    (tmp_path / "NOTES").write_text("ARG SIG_ALG=mldsa65\n", encoding="utf-8")
    assert "NOTES" not in scan_directory(tmp_path)["files_read"]
