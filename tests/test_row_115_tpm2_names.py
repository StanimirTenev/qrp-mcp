"""ZA-OPRAVYANE row 115 (LinkedIn 23.10.2026, Ivezic/MITRE probe t1-mitre): TPM 2.0 names
were invisible. `TPM2_ALG_RSA` with keyBits 2048 and `tpm2_createek -G rsa` gave no RSA;
only TPM 1.2's `TPM_ALG_RSA` was read. The names are tpm2-tss's
(include/tss2/tss2_tpm2_types.h), tpm2-pytss's (`TPM2_ALG.RSA`, `TPM2_ECC.NIST_P256`,
src/tpm2_pytss/constants.py) and tpm2-tools' algorithm specifiers (man/common/alg.md:
`rsa`, `rsa2048`, `ecc`, `ecc256`, `ecc_nist_p256` after `-G`/`--key-algorithm`), all
read on 2 Nov 2026 into ~/zadachi/qrp-mcp/izvori/tpm2/."""

import json
import subprocess
import sys

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("rel, text, family", [
    ("a.c", "inPublic.publicArea.type = TPM2_ALG_RSA;\n", "RSA"),
    ("a.c", "scheme.scheme = TPM2_ALG_RSASSA;\n", "RSA"),
    ("a.c", "scheme.scheme = TPM2_ALG_RSAPSS;\n", "RSA"),
    ("a.c", "inPublic.publicArea.type = TPM2_ALG_ECC;\n", "EC"),
    ("a.c", "eccDetail.curveID = TPM2_ECC_NIST_P256;\n", "EC"),
    ("a.c", "scheme.scheme = TPM2_ALG_ECDSA;\n", "ECDSA"),
    ("a.c", "scheme.scheme = TPM2_ALG_ECDH;\n", "ECDH"),
    ("k.py", "pub.publicArea.type = TPM2_ALG.RSA\n", "RSA"),
    ("k.py", "curve = TPM2_ECC.NIST_P384\n", "EC"),
    ("mk.sh", "tpm2_createek -c ek.ctx -G rsa -u ek.pub\n", "RSA"),
    ("mk.sh", "tpm2_create -C p.ctx -G rsa2048:rsaes -u k.pub -r k.priv\n", "RSA"),
    ("mk.sh", "tpm2_createprimary -C o -G ecc256 -c p.ctx\n", "EC"),
    ("mk.sh", "tpm2_createprimary -C o --key-algorithm=ecc_nist_p384 -c p.ctx\n", "EC"),
])
def test_tpm2_names_give_their_family(tmp_path, rel, text, family):
    (tmp_path / rel).write_text(text, encoding="utf-8")
    assert family in scan_directory(str(tmp_path))["detected_algorithms"]


@pytest.mark.parametrize("rel, text", [
    ("mk.sh", "tpm2_createprimary -C o -G aes128cfb -c p.ctx\n"),
    ("mk.sh", "gpg -G rsa\n"),
    ("a.c", "x = TPM2_ALG_SHA256;\n"),
])
def test_not_an_asymmetric_tpm2_name(tmp_path, rel, text):
    (tmp_path / rel).write_text(text, encoding="utf-8")
    assert not {"RSA", "EC", "ECDSA", "ECDH"} & set(
        scan_directory(str(tmp_path))["detected_algorithms"])


def test_through_the_cli(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "ek.c").write_text(
        "TPM2B_PUBLIC in = { .publicArea = { .type = TPM2_ALG_RSA,\n"
        "  .parameters.rsaDetail = { .keyBits = 2048 } } };\n", encoding="utf-8")
    out = tmp_path / "scan.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    rows = json.loads(out.read_text())["evidence"]["source_code"]
    # Line 2 is RSA too, read from `rsaDetail` as a component (before this row as well).
    assert (1, "RSA") in [(e["line"], e["algorithm"]) for e in rows]
