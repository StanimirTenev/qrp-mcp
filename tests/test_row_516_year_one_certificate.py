"""ZA-OPRAVYANE row 516: `scan certbot --as-of 2026-11-17` stopped with a ValueError.

certbot's acme tests carry the ARI draft's example certificate (draft-ietf-acme-ari-08,
appendix A), whose validity is GeneralizedTime 00010101000000Z: the year 1. The row's dates were
written with `strftime("%Y")`, which glibc does not pad, so `not_after` read `1-01-01T00:00:00Z`,
and `--as-of` (certificates.pin_expiry) parsed it back with `%Y-%m-%d` and failed. Without
`--as-of` the scan passed, which is why the crash came back only with it.

The date is the certificate's own, so the row keeps it, written as ISO 8601 with four digits,
and `--as-of` reads it: `expired` is true, as it is without `--as-of`.
"""

from __future__ import annotations

import json

import pytest

from qrp_mcp.server import main

ARI_EXAMPLE = """\
-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
-----END CERTIFICATE-----
"""


def _scan(tmp_path, *extra):
    tree = tmp_path / "t"
    tree.mkdir(exist_ok=True)
    (tree / "ari.pem").write_text(ARI_EXAMPLE)
    out = tmp_path / f"s{len(extra)}.json"
    with pytest.raises(SystemExit) as done:
        main(["scan", str(tree), "--no-config", "--level", "full", "--out", str(out), *extra])
    assert done.value.code == 0
    result = json.loads(out.read_text())
    return [r["certificate"] for rows in result["evidence"].values() for r in rows
            if isinstance(r, dict) and r.get("certificate")]


def test_as_of_reads_a_certificate_of_the_year_one(tmp_path):
    certs = _scan(tmp_path, "--as-of", "2026-11-17")
    assert certs
    for c in certs:
        assert c["not_after"] == c["not_before"] == "0001-01-01T00:00:00Z"
        assert c["expired"] is True and c["expired_basis"] == "--as-of"


def test_the_date_is_written_with_four_digits_without_as_of(tmp_path):
    certs = _scan(tmp_path)
    assert certs and {c["not_after"] for c in certs} == {"0001-01-01T00:00:00Z"}
    assert {c["expired"] for c in certs} == {True}
