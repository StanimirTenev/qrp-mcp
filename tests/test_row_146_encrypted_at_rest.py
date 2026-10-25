"""Secrets encrypted at rest with sops / age / OpenPGP (ZA-OPRAVYANE row 146).

A sops file committed to the tree is ciphertext whose key was agreed with the recipient's
public key. An `age1...` recipient is an X25519 key: whoever records the file today opens
it once X25519 falls (harvest now, decrypt later). The tree read `secrets.enc.yaml` and gave
0 rows; qScan reports the recipient as X25519 with HNDL. An OpenPGP recipient's family is
not in the tree -- a fingerprint does not say it -- so no family is invented: the file is
named as encrypted at rest to OpenPGP.
"""

from qrp_mcp.scan import scan_directory

AGE = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
FP = "FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4"

SECRETS = f"""password: ENC[AES256_GCM,data:abc=,iv:def=,tag:ghi=,type:str]
sops:
    age:
        - recipient: {AGE}
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB4eHh4
            -----END AGE ENCRYPTED FILE-----
    pgp:
        - created_at: "2026-01-01T00:00:00Z"
          enc: |
            -----BEGIN PGP MESSAGE-----
            hQEMA1234567890ABCDEFGH
            -----END PGP MESSAGE-----
          fp: {FP}
"""

SOPS_CONFIG = f"""creation_rules:
  - path_regex: secrets/.*\\.yaml$
    age: {AGE},{AGE[:-1]}q
    pgp: {FP}
"""


def _scan(tmp_path):
    (tmp_path / "secrets.enc.yaml").write_text(SECRETS)
    (tmp_path / ".sops.yaml").write_text(SOPS_CONFIG)
    return scan_directory(str(tmp_path))


def test_age_recipients_are_x25519_with_hndl(tmp_path):
    result = _scan(tmp_path)
    rows = [(e["path"], e["line"]) for e in result["evidence"]["source_code"]
            if e["algorithm"] == "X25519" and e.get("hndl") is True]
    assert ("secrets.enc.yaml", 4) in rows
    assert (".sops.yaml", 3) in rows
    assert "X25519" in result["detected_algorithms"]


def test_encrypted_files_are_named_as_protocol_assets_without_an_invented_family(tmp_path):
    result = _scan(tmp_path)
    at_rest = [(p["path"], p["line"], p["protocol"], p.get("recipient_family"))
               for p in result["evidence"]["protocols"] if p.get("basis") == "encrypted_at_rest"]
    assert ("secrets.enc.yaml", 6, "age", None) in at_rest
    assert ("secrets.enc.yaml", 12, "openpgp", None) in at_rest
    assert ("secrets.enc.yaml", 15, "openpgp", None) in at_rest
    assert (".sops.yaml", 4, "openpgp", None) in at_rest
    assert all(p["hndl"] for p in result["evidence"]["protocols"]
               if p.get("basis") == "encrypted_at_rest")


def test_the_cbom_names_the_encryption_at_rest(tmp_path):
    from qrp_mcp import cyclonedx
    bom = cyclonedx.build(_scan(tmp_path))
    names = {c["name"] for c in bom["components"]}
    assert "age encryption at rest (X25519 recipient)" in names
    assert "OpenPGP encryption at rest" in names
    pgp = next(c for c in bom["components"] if c["name"] == "OpenPGP encryption at rest")
    assert {"name": "qrp:hndl", "value": "true"} in pgp["properties"]


def test_age_lookalikes_are_not_recipients(tmp_path):
    (tmp_path / "a.yaml").write_text("image: page1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p\n"
                                     "short: age1abc\n"
                                     "plugin: age1yubikey1qwt50d05nh5vutpdzmlg5wn80xq5negm4uj9ghv0snvdd3yysf5yw3rhl3t\n")
    result = scan_directory(str(tmp_path))
    assert not [e for e in result["evidence"]["source_code"] if e["algorithm"] == "X25519"]
