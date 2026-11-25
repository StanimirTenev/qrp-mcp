"""Row 557 (25.11.2026, Dr. Gilberto Crespo; probe `linkedin-postove/2026-11-25/stai/proba/gilberto2`).

`gpg --batch --quick-gen-key ops@bank.example rsa3072 encrypt never` gave nothing, while
`openssl genrsa 3072` and `ssh-keygen -t rsa -b 3072` on the same file gave RSA 3072. The class is
the algorithm a GnuPG key generation names, in every form the GnuPG manual documents:

* `--quick-generate-key user-id [algo [usage [expire]]]`, also `--quick-gen-key`, and
  `--quick-add-key fpr [algo [usage [expire]]]` (OpenPGP-Key-Management.html): "Supported algorithms
  are “rsa”, “dsa”, “elg”, “ed25519”, “cv25519”, and other ECC curves. For example the string “rsa”
  adds an RSA key with the default key length; a string “rsa4096” requests that the key length is
  4096 bits"; the curve names "as used by key listings" (nistp256, named in the same page);
* `--default-new-key-algo string`, e.g. "rsa2048/cert,sign+rsa2048/encr" and
  "ed25519/cert,sign+cv25519/encr" (GPG-Esoteric-Options.html);
* the parameter file of `--generate-key --batch` (Unattended-GPG-key-generation.html): `Key-Type:`
  and `Subkey-Type:` an algorithm name or number ("RSA=1, DSA=17"), `Key-Length:` / `Subkey-Length:`
  in bits, `Key-Curve:` / `Subkey-Curve:` the curve.

Not a family: "default", "future-default", "-" and "pqc" name what the gpg that runs chooses, which
the file does not say. An interactive `--full-generate-key` names no algorithm on its line.
"""

from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory


def _rows(tmp_path: Path, text: str, name: str = "keys.sh") -> list[tuple]:
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    return sorted((i["line"], i["algorithm"], i.get("key_size"), i.get("curve"))
                  for i in result["evidence"]["source_code"])


@pytest.mark.parametrize("command,family,size,curve", [
    ("gpg --batch --quick-gen-key ops@bank.example rsa3072 encrypt never", "RSA", 3072, None),
    ("gpg --batch --quick-generate-key ops@bank.example rsa4096 sign never", "RSA", 4096, None),
    ('gpg --batch --quick-generate-key "Ops <ops@bank.example>" rsa2048', "RSA", 2048, None),
    ("gpg --quick-generate-key ops@bank.example rsa", "RSA", "undetermined", None),
    ("gpg2 --batch --passphrase '' --quick-gen-key ops@bank.example dsa2048", "DSA", 2048, None),
    ("gpg --quick-add-key 0123ABCD rsa3072 encr", "RSA", 3072, None),
    ("gpg --quick-add-key 0123ABCD elg", "ElGamal", None, None),
    ("gpg --quick-add-key 0123ABCD cv25519 encr", "X25519", None, None),
    ("gpg --quick-add-key 0123ABCD cv448 encr", "X448", None, None),
    ("gpg --quick-generate-key ops@bank.example ed25519 sign never", "Ed25519", None, None),
    ("gpg --quick-generate-key ops@bank.example ed448", "Ed448", None, None),
    ("gpg --quick-generate-key ops@bank.example nistp256", "EC", 256, "P-256"),
    ("gpg --quick-generate-key ops@bank.example nistp384", "EC", 384, "P-384"),
    ("gpg --quick-generate-key ops@bank.example brainpoolP256r1", "EC", 256, "brainpoolP256r1"),
])
def test_quick_generate_and_add_key(tmp_path, command, family, size, curve):
    rows = _rows(tmp_path, f"#!/bin/sh\n{command}\n")
    assert [r for r in rows if r[0] == 2] == [(2, family, size, curve)]


@pytest.mark.parametrize("algo", ["default", "future-default", "-", "pqc"])
def test_a_default_names_no_family(tmp_path, algo):
    assert _rows(tmp_path, f"#!/bin/sh\ngpg --batch --quick-gen-key ops@bank.example {algo}\n") == []


def test_interactive_full_generate_key_names_none(tmp_path):
    assert _rows(tmp_path, "#!/bin/sh\ngpg --full-generate-key\ngpg --full-gen-key\n") == []


def test_default_new_key_algo(tmp_path):
    rows = _rows(tmp_path, '#!/bin/sh\ngpg --default-new-key-algo "rsa2048/cert,sign+rsa2048/encr" '
                           "--quick-gen-key ops@bank.example default\n"
                           'gpg --default-new-key-algo "ed25519/cert,sign+cv25519/encr" --gen-key\n')
    assert rows == [(2, "RSA", 2048, None), (3, "Ed25519", None, None), (3, "X25519", None, None)]


def test_default_new_key_algo_in_gpg_conf(tmp_path):
    rows = _rows(tmp_path, "default-new-key-algo rsa4096/cert,sign+rsa4096/encr\n",
                 name="gnupg/gpg.conf")
    assert rows == [(1, "RSA", 4096, None)]


def test_batch_parameter_file_from_the_manual(tmp_path):
    # The manual's own example, written by a script and handed to --generate-key.
    text = ("#!/bin/sh\ncat >foo <<EOF\n%echo Generating a basic OpenPGP key\nKey-Type: DSA\n"
            "Key-Length: 1024\nSubkey-Type: ELG-E\nSubkey-Length: 1024\nName-Real: Joe Tester\n"
            "Expire-Date: 0\n%commit\n%echo done\nEOF\ngpg --batch --generate-key foo\n")
    assert _rows(tmp_path, text) == [(4, "DSA", 1024, None), (6, "ElGamal", None, None)]


@pytest.mark.parametrize("key_type,extra,family,size,curve", [
    ("RSA", "Key-Length: 3072", "RSA", 3072, None),
    ("1", "Key-Length: 4096", "RSA", 4096, None),
    ("17", "Key-Length: 2048", "DSA", 2048, None),
    ("EDDSA", "Key-Curve: ed25519", "Ed25519", None, None),
    ("ECDSA", "Key-Curve: nistp256", "ECDSA", 256, "P-256"),
])
def test_batch_key_type(tmp_path, key_type, extra, family, size, curve):
    text = (f"#!/bin/sh\ngpg --batch --generate-key <<EOF\nKey-Type: {key_type}\n{extra}\n"
            "Name-Real: Ops\n%commit\nEOF\n")
    assert _rows(tmp_path, text) == [(3, family, size, curve)]


def test_batch_subkey_curve(tmp_path):
    text = ("#!/bin/sh\ngpg --batch --generate-key <<EOF\nKey-Type: EDDSA\nKey-Curve: ed25519\n"
            "Subkey-Type: ECDH\nSubkey-Curve: cv25519\nName-Real: Ops\n%commit\nEOF\n")
    assert _rows(tmp_path, text) == [(3, "Ed25519", None, None), (5, "X25519", None, None)]


def test_batch_default_names_no_family(tmp_path):
    text = ("#!/bin/sh\ngpg --batch --generate-key <<EOF\nKey-Type: default\n"
            "Subkey-Type: default\nName-Real: Ops\n%commit\nEOF\n")
    assert _rows(tmp_path, text) == []


def test_in_a_workflow(tmp_path):
    text = ("name: k\non: push\njobs:\n  k:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: gpg --batch --quick-gen-key ci@bank.example rsa3072 sign never\n")
    rows = _rows(tmp_path, text, name=".github/workflows/k.yml")
    assert rows == [(7, "RSA", 3072, None)]


def test_the_probe_file(tmp_path):
    rows = _rows(tmp_path, "#!/bin/sh\nopenssl genrsa -out backup.key 3072\n"
                           'ssh-keygen -t rsa -b 3072 -f backup_ssh -N ""\n'
                           "gpg --batch --quick-gen-key ops@bank.example rsa3072 encrypt never\n"
                           "gpg --batch --quick-generate-key archive@bank.example ed25519 sign never\n")
    assert rows == [(2, "RSA", 3072, None), (3, "RSA", 3072, None), (4, "RSA", 3072, None),
                    (5, "Ed25519", None, None)]


def test_gpg_named_in_prose_is_not_a_generation(tmp_path):
    assert _rows(tmp_path, "# use gpg to make keys, rsa3072 is fine\necho done\n") == []
