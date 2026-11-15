"""Row 489 (15.11.2026, Peter Davis, ZeroVaultID; probe `linkedin-postove/2026-11-15/kms-oid-proba/`).

A signer configuration that declares a composite ML-DSA signature (RFC 10073) beside the two KMS
key aliases it signs with was found as a composite, but nothing tied the declaration to the keys
declared in Terraform. Now a composite `hybrid_names` entry carries `kms_keys`: each alias written
in the same file, resolved through a Terraform `aws_kms_alias` (`name`, `target_key_id`) to an
`aws_kms_key`, and matched to a half by the key's spec. Only that chain links; an alias whose name
merely contains "mldsa87" does not. The output gives places, never the alias text, so it is the same
at every `--level`.

Not changed: the findings and `readiness_by_role.signature` (`hybrid_partial`, as a TLS hybrid
reads). What a linked composite should read is a decision left open in 0.47.0.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

# The probe's files (kms-oid-proba/r), as written there.
SIGNER = ("signer:\n"
          "  algorithm: id-MLDSA87-ECDSA-P384-SHA512\n"
          "  algorithm_oid: 1.3.6.1.5.5.7.6.49\n"
          "  components:\n"
          "    mldsa_key: alias/zv-mldsa87\n"
          "    ecdsa_key: alias/zv-ecdsa-p384\n")
KEYS = ('resource "aws_kms_key" "pq" {\n'
        '  key_usage                = "SIGN_VERIFY"\n'
        '  customer_master_key_spec = "ML_DSA_87"\n'
        '}\n'
        'resource "aws_kms_key" "trad" {\n'
        '  key_usage                = "SIGN_VERIFY"\n'
        '  customer_master_key_spec = "ECC_NIST_P384"\n'
        '}\n')
SIGN_PY = ('import boto3\nkms = boto3.client("kms")\n\n'
           'def composite_sign(mu: bytes, digest384: bytes):\n'
           '    pq = kms.sign(KeyId="alias/pq-mldsa87", Message=mu, MessageType="EXTERNAL_MU",\n'
           '                  SigningAlgorithm="ML_DSA_SHAKE_256")\n'
           '    ec = kms.sign(KeyId="alias/trad-p384", Message=digest384, MessageType="DIGEST",\n'
           '                  SigningAlgorithm="ECDSA_SHA_384")\n'
           '    return pq["Signature"], ec["Signature"]\n')
ALIASES = ('resource "aws_kms_alias" "pq" {\n'
           '  name          = "alias/zv-mldsa87"\n'
           '  target_key_id = aws_kms_key.pq.key_id\n'
           '}\n'
           'resource "aws_kms_alias" "trad" {\n'
           '  name          = "alias/zv-ecdsa-p384"\n'
           '  target_key_id = aws_kms_key.trad.key_id\n'
           '}\n')


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(args: list[str], **env) -> None:
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True, env={**os.environ, **env})


def _scans(root: Path, tmp_path: Path) -> list[dict]:
    out, plain = tmp_path / "s.json", tmp_path / "s0.json"
    _cli(["scan", str(root), "--out", str(out)])
    # The same with the line gate's core off: the alias rule reads the whole file either way.
    _cli(["scan", str(root), "--out", str(plain)], QRP_MCP_CORE="0")
    return [json.loads(out.read_text()), json.loads(plain.read_text()), scan_repo(str(root)),
            scan_directory(root)]


def _cboms(root: Path, tmp_path: Path) -> list[dict]:
    out = tmp_path / "c.json"
    _cli(["cbom", str(root), "--out", str(out)])
    return [json.loads(out.read_text()), export_cbom(str(root)), build(scan_directory(root))]


def _composites(result: dict) -> list[dict]:
    return [h for h in result["hybrid_names"] if h["path"] == "signer/signer.yaml"]


def test_aliases_resolved_through_terraform_link_the_composite_to_both_keys(tmp_path):
    root = _write(tmp_path / "r", {"signer/signer.yaml": SIGNER, "keys.tf": KEYS,
                                   "aliases.tf": ALIASES, "composite_sign.py": SIGN_PY})
    for result in _scans(root, tmp_path):
        entries = _composites(result)
        assert [h["line"] for h in entries] == [2, 3]
        for h in entries:
            keys = h["kms_keys"]
            assert keys["linked"] is True
            assert keys["not_linked"] == []
            assert keys["halves"] == [
                {"half": "ML-DSA-87", "alias_at": "signer/signer.yaml:5",
                 "alias_resolved_at": "aliases.tf:2", "key_at": "keys.tf:3",
                 "key_spec": "ML_DSA_87"},
                {"half": "ECDSA P-384", "alias_at": "signer/signer.yaml:6",
                 "alias_resolved_at": "aliases.tf:6", "key_at": "keys.tf:7",
                 "key_spec": "ECC_NIST_P384"}]
            # Places only: the alias text does not leave at any level.
            assert "zv-" not in json.dumps(keys)
        # Not claimed: the label and the findings stay as they were.
        assert result["summary"]["readiness_by_role"]["signature"] == "hybrid_partial"


def test_the_probe_as_written_is_not_linked_and_says_why(tmp_path):
    # kms-oid-proba/r: the yaml names alias/zv-*, the code alias/pq-* and alias/trad-*, and the
    # Terraform declares no alias. Nothing links them, and the result says so per alias.
    root = _write(tmp_path / "r", {"signer/signer.yaml": SIGNER, "keys.tf": KEYS,
                                   "composite_sign.py": SIGN_PY})
    for result in _scans(root, tmp_path):
        for h in _composites(result):
            keys = h["kms_keys"]
            assert keys["linked"] is False and keys["halves"] == []
            assert [n["alias_at"] for n in keys["not_linked"]] == [
                "signer/signer.yaml:5", "signer/signer.yaml:6"]
            assert {n["reason"] for n in keys["not_linked"]} == {
                "no aws_kms_alias with this name in the files read"}


def test_a_key_of_another_spec_or_one_half_alone_does_not_link(tmp_path):
    root = _write(tmp_path / "m", {"signer/signer.yaml": SIGNER, "aliases.tf": ALIASES,
                                   "keys.tf": KEYS.replace("ML_DSA_87", "ML_DSA_65")})
    for result in _scans(root, tmp_path):
        for h in _composites(result):
            keys = h["kms_keys"]
            assert keys["linked"] is False
            assert [x["half"] for x in keys["halves"]] == ["ECDSA P-384"]
            assert keys["not_linked"] == [{
                "alias_at": "signer/signer.yaml:5",
                "reason": "resolves to an aws_kms_key of spec ML_DSA_65 (keys.tf:3), "
                          "which is neither half"}]


def test_a_key_of_the_same_name_in_another_module_does_not_link(tmp_path):
    # Terraform resolves aws_kms_key.pq inside the alias's own module (directory). A key of the
    # same name in another directory is another key; the alias's module holds none.
    root = _write(tmp_path / "d", {"signer/signer.yaml": SIGNER, "envs/a/aliases.tf": ALIASES,
                                   "envs/b/keys.tf": KEYS})
    for result in _scans(root, tmp_path):
        for h in _composites(result):
            keys = h["kms_keys"]
            assert keys["linked"] is False and keys["halves"] == []
            assert {n["reason"] for n in keys["not_linked"]} == {
                "its aws_kms_alias does not name exactly one aws_kms_key of its own directory "
                "in the files read"}


def test_no_alias_beside_the_composite_adds_nothing(tmp_path):
    # kms-oid-proba/r2: the composite from a label table, no alias in that file.
    root = _write(tmp_path / "r2", {
        "labels.py": 'COMPOSITE_LABELS = {\n    "1.3.6.1.5.5.7.6.49": '
                     'b"COMPSIG-MLDSA87-ECDSA-P384-SHA512",\n}\n',
        "keys.tf": KEYS, "composite_sign.py": SIGN_PY})
    for result in _scans(root, tmp_path):
        (h,) = result["hybrid_names"]
        assert "kms_keys" not in h


def test_the_cbom_combiner_carries_the_link(tmp_path):
    root = _write(tmp_path / "r", {"signer/signer.yaml": SIGNER, "keys.tf": KEYS,
                                   "aliases.tf": ALIASES})
    for doc in _cboms(root, tmp_path):
        (composite,) = [c for c in doc["components"]
                        if c["name"] == "id-MLDSA87-ECDSA-P384-SHA512"]
        props = {p["name"]: p["value"] for p in composite["properties"]}
        assert props["qrp:kms_keys"] == (
            "linked: ML-DSA-87 -> keys.tf:3 (ML_DSA_87, alias at signer/signer.yaml:5, "
            "resolved at aliases.tf:2); ECDSA P-384 -> keys.tf:7 (ECC_NIST_P384, alias at "
            "signer/signer.yaml:6, resolved at aliases.tf:6)")
