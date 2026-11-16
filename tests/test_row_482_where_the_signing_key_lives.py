"""ZA-OPRAVYANE row 482: where the signing key lives was not said.

Probe `linkedin-postove/2026-11-15/hw-sign-proba/r/release_sign.sh` (0.45.0): `tpm2_sign -c
...ctx` and `pkcs11-tool --sign --mechanism ECDSA-SHA256` gave only `source_code` ECDSA rows, no
signing step; `openssl dgst -sign key.pem` was a `ci_pipeline` openssl_sign step with
`signing_key.path`. A key URI was cut or rewritten: cosign `--key "pkcs11:token=a;object=b"` gave
`pkcs11:token=a` (the value stopped at `;`), `--key awskms:///alias/x` gave `awskms:/alias/x`
(normpath).

Now `tpm2_sign` (tpm2-tools man/tpm2_sign.1.md) and `pkcs11-tool --sign`/`-s` (OpenSC
pkcs11-tool(1)) are signing steps, as is `openssl pkeyutl -sign` (openssl-pkeyutl(1)); every
signing step carries `key_location`: `file`, `tpm`, `pkcs11_token`, `kms`, or "not determined
from the line". A key URI is kept as written, without its query (an RFC 7512 `pin-value` is never
copied out). The family the line names -- tpm2_sign `-s/--scheme` (man/common/alg.md: rsassa,
rsapss, ecdsa, ecdaa, ecschnorr, sm2), pkcs11-tool `-m/--mechanism` -- is `key_algorithm`.

Not claimed: a Kubernetes secret (`k8s://`) or `env://` key is not a location of these four; an
Android StrongBox or Apple Secure Enclave key in code is not read.
"""

import json
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

PROBE = Path.home() / "zadachi/linkedin-postove/2026-11-15/hw-sign-proba/r/release_sign.sh"
PROBE_TEXT = """#!/bin/sh
tpm2_sign -c /etc/keys/release.ctx -g sha256 -s ecdsa -o payload.sig payload.bin
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --sign --mechanism ECDSA-SHA256 --id 01 -i payload.bin -o payload.p11sig
openssl dgst -sha256 -sign /etc/keys/release.pem -out payload.ossl.sig payload.bin
"""
MORE = """#!/bin/sh
cosign sign --key "pkcs11:token=a;object=b?pin-value=Qx7PinWv" img
cosign sign --key awskms:///alias/release img
openssl dgst -sha256 -sign "pkcs11:object=rel;type=private" -engine pkcs11 -keyform engine -out s p
openssl pkeyutl -sign -provider pkcs11 -inkey "pkcs11:object=rel" -in d -out s
cosign sign --key k8s://ns/key img
gpg --detach-sign release.tar
pkcs11-tool --verify -m ECDSA-SHA256 --id 01 -i p --signature-file x
openssl dgst -sha256 -sign rel -engine pkcs11 -keyform engine -out s p
openssl pkeyutl -sign -provider tpm2 -inkey handle:0x81000000 -in d -out s
cosign sign --key "pkcs11:token=a;object=b;pin-value=Zq9PinXy" img
"""


@pytest.fixture
def tree(tmp_path):
    if PROBE.is_file():
        assert PROBE.read_text() == PROBE_TEXT
    t = tmp_path / "repo"
    t.mkdir()
    (t / "release_sign.sh").write_text(PROBE_TEXT)
    (t / "more.sh").write_text(MORE)
    return t


def _steps(ci):
    return {(c["path"], c["line"]): c for c in ci if c.get("operation") != "public_key_encryption"}


def _check(ci):
    s = _steps(ci)
    tpm = s[("release_sign.sh", 2)]
    assert tpm["command_type"] == "tpm2_sign" and tpm["key_location"] == "tpm"
    assert tpm["key_algorithm"].startswith("ECDSA, named on the line")
    p11 = s[("release_sign.sh", 3)]
    assert p11["command_type"] == "pkcs11_tool_sign" and p11["key_location"] == "pkcs11_token"
    assert p11["key_algorithm"].startswith("ECDSA, named on the line")
    assert s[("release_sign.sh", 4)]["key_location"] == "file"
    cos = s[("more.sh", 2)]
    assert cos["key_location"] == "pkcs11_token"
    assert cos["signing_key"]["path"] == "pkcs11:token=a;object=b"
    kms = s[("more.sh", 3)]
    assert kms["key_location"] == "kms" and kms["signing_key"]["path"] == "awskms:///alias/release"
    assert s[("more.sh", 4)]["key_location"] == "pkcs11_token"
    assert s[("more.sh", 5)]["command_type"] == "openssl_sign"
    assert s[("more.sh", 5)]["key_location"] == "pkcs11_token"
    assert s[("more.sh", 6)]["key_location"] == "not determined from the line"
    assert s[("more.sh", 7)]["key_location"] == "not determined from the line"
    # A verify is not a signing step.
    assert ("more.sh", 8) not in s
    # The engine or provider, where the key is not a URI of its own.
    assert s[("more.sh", 9)]["key_location"] == "pkcs11_token"
    assert s[("more.sh", 10)]["key_location"] == "tpm"
    # A PIN in the URI's path is dropped too.
    assert s[("more.sh", 11)]["signing_key"]["path"] == "pkcs11:token=a;object=b"


def test_scan_json(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out), "--level", "full"]) == 0
    text = out.read_text()
    _check(json.loads(text)["evidence"]["ci_pipeline"])
    out2 = tmp_path / "m.json"
    server.scan_to_file([str(tree), "--out", str(out2)])
    assert "Qx7PinWv" not in out2.read_text() and "Zq9PinXy" not in out2.read_text()


def test_mcp_tool(tree):
    _check(server.scan_repo(str(tree))["evidence"]["ci_pipeline"])


def test_cbom(tree):
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        assert "Qx7PinWv" not in json.dumps(doc) and "Zq9PinXy" not in json.dumps(doc)
        props = {p["name"]: p["value"] for p in doc["properties"]}
        steps = {(c["location"], c["line"]): c
                 for c in json.loads(props["qrp:evidence:signing_commands"])}
        assert steps[("release_sign.sh", 2)]["key_location"] == "tpm"
        assert steps[("more.sh", 3)]["key_location"] == "kms"
