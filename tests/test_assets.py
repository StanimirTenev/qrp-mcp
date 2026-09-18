"""Assets present without an algorithm written down: protocols and dependencies.

Counted from this release on, because a TLS version pin and an installed RSA
library are both real cryptographic facts about a repository. Counted in their
own buckets, with `basis` saying how they were learned, because a configured
protocol is not an observed call and a declared dependency is neither.

The cases come from QuantaKrypto's published recall corpus (Apache-2.0), which
labels 11 TLS, 14 SSH and 25 dependency findings this scanner reported as
nothing.
"""
from __future__ import annotations

import json

import pytest

from qrp_mcp.scan import scan_directory


def assets(tmp_path, name: str, body: str, kind: str) -> list:
    (tmp_path / name).write_text(body)
    return scan_directory(tmp_path)["evidence"][kind]


# --- protocols ---------------------------------------------------------------

@pytest.mark.parametrize("name,line,version", [
    ("server.ts", '  const opts = { minVersion: "TLSv1.2", maxVersion: "TLSv1.3" };', "TLSv1.2"),
    ("gateway.go", "  cfg := &tls.Config{MinVersion: tls.VersionTLS12}", "TLSv1.2"),
    ("tls-server.properties", "server.ssl.enabled-protocols=TLSv1.2", "TLSv1.2"),
    ("Creds.cs", "  SslProtocols = SslProtocols.Tls12;", "TLSv1.2"),
    ("hardening.py", "  ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)", "TLSv1.2"),
    ("nginx.conf", "  ssl_protocols TLSv1.1 TLSv1.2;", "TLSv1.1"),
])
def test_tls_version_is_an_asset(tmp_path, name, line, version):
    found = assets(tmp_path, name, line + "\n", "protocols")
    assert any(a["protocol"] == "tls" and a["version"] == version for a in found), found
    assert all(a["basis"] == "configured_protocol" for a in found)


def test_a_deprecated_version_is_named_deprecated_not_quantum_vulnerable(tmp_path):
    found = assets(tmp_path, "nginx.conf", "ssl_protocols TLSv1.1;\n", "protocols")
    assert found[0]["deprecated"] is True
    # A version says nothing about the key exchange: TLS 1.3 is vulnerable over
    # X25519 and is not over X25519MLKEM768. The verdict is not the version's.
    assert "quantum_vulnerable" not in found[0]


def test_tls_in_prose_is_not_an_asset(tmp_path):
    assert assets(tmp_path, "a.py", "# we still allow TLSv1.2 here\n", "protocols") == []


@pytest.mark.parametrize("line", [
    "HostKeyAlgorithms ssh-rsa,rsa-sha2-512",
    "KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256",
    "Protocol 2",
])
def test_ssh_transport_configuration_is_an_asset(tmp_path, line):
    found = assets(tmp_path, "sshd_config", line + "\n", "protocols")
    assert any(a["protocol"] == "ssh" for a in found), found


# --- dependencies ------------------------------------------------------------

def test_npm_dependencies(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps(
        {"dependencies": {"express": "^4", "node-forge": "^1.3.1",
                          "elliptic": "^6.5.5", "jsonwebtoken": "^9"}}, indent=1))
    found = scan_directory(tmp_path)["evidence"]["dependencies"]
    names = {d["package"] for d in found}
    assert names == {"node-forge", "elliptic", "jsonwebtoken"}   # not express
    assert all(d["basis"] == "declared_dependency" for d in found)
    assert "RSA" in next(d for d in found if d["package"] == "node-forge")["families"]


def test_go_module_requirements(tmp_path):
    (tmp_path / "go.mod").write_text(
        "module github.com/acme/edge-crypto\n\ngo 1.22\n\nrequire (\n"
        "\tgithub.com/cloudflare/circl v1.3.9\n"
        "\tgithub.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0\n"
        "\tgithub.com/golang-jwt/jwt/v5 v5.2.1\n"
        "\tgolang.org/x/crypto v0.24.0\n)\n")
    found = scan_directory(tmp_path)["evidence"]["dependencies"]
    assert len(found) == 4


def test_a_comment_in_a_manifest_is_not_a_dependency(tmp_path):
    """qscan reports RSA for a comment line in a go.mod. That is the whole
    reason these are read structurally instead of by substring."""
    (tmp_path / "go.mod").write_text(
        "module x\n\n// we should drop golang.org/x/crypto and node-forge\n"
        "require github.com/spf13/cobra v1.8.0\n")
    assert scan_directory(tmp_path)["evidence"]["dependencies"] == []


def test_python_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# Runtime dependencies\nfastapi==0.110.1\ncryptography==42.0.5\n"
        "pyOpenSSL==24.1.0\npycryptodome==3.20.0\nPyJWT[crypto]==2.8.0\nparamiko==3.4.0\n")
    found = scan_directory(tmp_path)["evidence"]["dependencies"]
    assert {d["package"] for d in found} == {
        "cryptography", "pyOpenSSL", "pycryptodome", "PyJWT", "paramiko"}


def test_no_dependency_is_given_an_algorithm_finding(tmp_path):
    """A library that is installed is not a line of code that calls it.

    Nothing in the algorithm findings, and nothing in detected_algorithms, may
    come from a manifest: that is the difference between what is there and what
    is used, and it is the whole point of the separate bucket.
    """
    (tmp_path / "package.json").write_text('{"dependencies": {"node-forge": "^1.3.1"}}')
    result = scan_directory(tmp_path)
    assert result["evidence"]["dependencies"]
    assert result["detected_algorithms"] == []
    assert result["evidence"]["source_code"] == []


# --- the CBOM ----------------------------------------------------------------

def test_the_cbom_carries_protocols_and_dependencies(tmp_path):
    import json as _json
    import os
    import jsonschema
    from qrp_mcp import cyclonedx

    (tmp_path / "nginx.conf").write_text("ssl_protocols TLSv1.1 TLSv1.2;\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"node-forge": "^1.3.1"}}')
    bom = cyclonedx.build(scan_directory(tmp_path))

    base = os.path.join(os.path.dirname(__file__), "schema")
    schema = _json.load(open(os.path.join(base, "bom-1.6.schema.json")))
    store = {}
    for f in os.listdir(base):
        s = _json.load(open(os.path.join(base, f)))
        store[f] = s
        if "$id" in s:
            store[s["$id"]] = s
    validator = jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store))
    assert list(validator.iter_errors(bom)) == []

    kinds = {c["name"]: c for c in bom["components"]}
    assert kinds["TLSv1.1"]["cryptoProperties"]["assetType"] == "protocol"
    assert kinds["TLSv1.1"]["cryptoProperties"]["protocolProperties"]["type"] == "tls"
    assert kinds["node-forge"]["type"] == "library"
    # Neither may masquerade as an observed algorithm.
    algorithms = [c for c in bom["components"]
                  if c.get("cryptoProperties", {}).get("assetType") == "algorithm"]
    assert [c["name"] for c in algorithms] == []


def test_an_ssh_public_key_entry_is_also_an_ssh_asset(tmp_path):
    """An authorized_keys line names the algorithm and the protocol both.

    The algorithm finding was already there; the protocol was not, so a report
    could say RSA is in use and not that SSH is how.
    """
    (tmp_path / "authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ deploy@host\n"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI ops@host\n")
    result = scan_directory(tmp_path)
    assert {"RSA", "Ed25519"} <= set(result["detected_algorithms"])
    assert any(a["protocol"] == "ssh" for a in result["evidence"]["protocols"])


def test_the_word_ciphers_alone_is_not_an_ssh_configuration(tmp_path):
    """`Ciphers` and `MACs` are directives at the start of a line in sshd_config.

    Anywhere else they are ordinary words, and a scanner that reads them as SSH
    configuration will find SSH in every cryptography library in the world.
    """
    (tmp_path / "a.c").write_text(
        "/* the Ciphers and MACs supported by this build */\n"
        "static const char *all_ciphers[] = { NULL };\n")
    assert scan_directory(tmp_path)["evidence"]["protocols"] == []


def test_one_component_per_library_however_many_manifests(tmp_path):
    """Vault declares golang.org/x/crypto in several go.mod files.

    One component with several occurrences; a repeated bom-ref breaks the
    uniqueness the schema requires of compositions.assemblies, which is how this
    was found -- a CBOM that no longer validated.
    """
    for sub in ("a", "b"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "go.mod").write_text(
            "module x\n\nrequire golang.org/x/crypto v0.24.0\n")
    from qrp_mcp import cyclonedx
    bom = cyclonedx.build(scan_directory(tmp_path))
    libraries = [c for c in bom["components"] if c["type"] == "library"]
    assert len(libraries) == 1
    assert len(libraries[0]["evidence"]["occurrences"]) == 2
    refs = bom["compositions"][0]["assemblies"]
    assert len(refs) == len(set(refs))


@pytest.mark.parametrize("line,used,banned", [
    ("SSLProtocol all -SSLv2 -SSLv3", [], ["SSLv2", "SSLv3"]),
    ("SSLProtocol             all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1", [], ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]),
    ("ssl_protocols TLSv1.2 TLSv1.3;", ["TLSv1.2", "TLSv1.3"], []),
    ("ssl_protocols SSLv2 SSLv3 TLSv1;", ["SSLv2", "SSLv3", "TLSv1.0"], []),
])
def test_a_banned_protocol_version_is_not_a_used_one(tmp_path, line, used, banned):
    """`-SSLv3` in an SSLProtocol line forbids SSL 3; it does not configure it.

    The same rule this scanner already applies to `!MD5` in a cipher list, and
    the same defect it criticises in others when they get it wrong. certbot
    carries 27 such lines, every one of them a ban read as a use.
    """
    (tmp_path / "ssl.conf").write_text(line + "\n")
    found = scan_directory(tmp_path)["evidence"]["protocols"]
    assert sorted(a["version"] for a in found if not a.get("banned")) == sorted(used)
    assert sorted(a["version"] for a in found if a.get("banned")) == sorted(banned)
