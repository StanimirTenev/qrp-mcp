"""Row 12 (Ogochukwu Friday Ikwuogu, 6 Oct 2026): OPC UA was invisible.

Reproduced on 0.28.0 + 178dcf2: a .NET `*.Config.xml` naming
`http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256` gave 0 findings -- `.xml`
was not read at all -- and no rule knew a SecurityPolicy URI or a stack identifier.

The mapping is the OPC Foundation profile database (export/xml/171, read 7 Oct 2026):
30 SecurityPolicy URIs, the algorithms of each from its conformance units, and
`ReleaseStatus="Deprecated"` on ten of them. No post-quantum SecurityPolicy exists.
`.xml` and `.json5` are read only when they name a SecurityPolicy URI, so the
coverage of every other tree does not move.
"""

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp.server import export_cbom, scan_repo


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(tree: Path, out: Path) -> dict:
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def _both(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    tree = _tree(tmp_path / "tree", files)
    return [_cli(tree, tmp_path / "out.json"), _tool(scan_repo)(str(tree))]


def _families(result: dict) -> dict[str, str]:
    return {f["algorithm_family"]: f["classification"] for f in result["findings"]}


def _policies(result: dict) -> dict[str, dict]:
    return {p["security_policy"]: p for p in result["evidence"]["protocols"]
            if p.get("protocol") == "opcua"}


URI = "http://opcfoundation.org/UA/SecurityPolicy#"

DOTNET_CONFIG = f"""<?xml version="1.0" encoding="utf-8"?>
<ApplicationConfiguration>
  <ServerConfiguration>
    <SecurityPolicies>
      <ServerSecurityPolicy>
        <SecurityMode>SignAndEncrypt_3</SecurityMode>
        <SecurityPolicyUri>{URI}Basic256Sha256</SecurityPolicyUri>
      </ServerSecurityPolicy>
      <ServerSecurityPolicy>
        <SecurityMode>Sign_2</SecurityMode>
        <SecurityPolicyUri>{URI}Basic128Rsa15</SecurityPolicyUri>
      </ServerSecurityPolicy>
      <ServerSecurityPolicy>
        <SecurityPolicyUri>{URI}ECC_nistP256</SecurityPolicyUri>
      </ServerSecurityPolicy>
    </SecurityPolicies>
  </ServerConfiguration>
</ApplicationConfiguration>
"""


def test_a_dotnet_config_xml_is_read_and_its_policies_named(tmp_path):
    for result in _both(tmp_path, {"Quickstarts.ReferenceServer.Config.xml": DOTNET_CONFIG}):
        assert result["files_scanned"]["config"] == 1
        found = _families(result)
        assert found["RSA"] == "classical_vulnerable"
        assert found["ECDSA"] == "classical_vulnerable"
        assert found["ECDH"] == "classical_vulnerable"
        assert found["SHA1"] == "deprecated_weak"          # Basic128Rsa15: RSA-PKCS15-SHA1
        policies = _policies(result)
        assert policies["Basic128Rsa15"]["deprecated"] is True
        assert policies["Basic256Sha256"]["deprecated"] is False
        assert policies["ECC_nistP256"]["deprecated"] is True
        # The .NET stack disagrees on the six un-suffixed ECC policies; said, not hidden.
        assert "IsDeprecated = false" in policies["ECC_nistP256"]["description"]
        assert result["summary"]["pqc_readiness"] == "classical_only"


def test_an_xml_without_a_security_policy_stays_unclaimed(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "layout.xml": "<LinearLayout android:id=\"@+id/rsa\"/>\n",
        "settings.json5": "{ cipher: 'RSA' }\n"})))
    assert result["files_scanned"]["config"] == 0
    assert result["files_skipped_by_type"] == {".xml": 1, ".json5": 1}


def test_the_claimed_types_say_when_xml_is_read(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {"a.py": "x = 1\n"})))
    claimed = result["coverage"]["instrument"]["claimed_types"]
    assert claimed["config_when_naming_opcua_security_policy"] == [".json5", ".xml"]


def test_open62541_json5_is_read(tmp_path):
    text = ("// server\n{\n  securityPolicies: [\n"
            f"    {{ policy: \"{URI}Aes256_Sha256_RsaPss\" }},\n"
            f"    {{ policy: \"{URI}ECC_curve25519_AesGcm\" }},\n  ]\n}}\n")
    for result in _both(tmp_path, {"server_json_config.json5": text}):
        found = _families(result)
        assert {"RSA", "Ed25519", "X25519"} <= set(found)
        assert _policies(result)["ECC_curve25519_AesGcm"]["deprecated"] is False


def test_the_boundary_keeps_basic256_out_of_basic256sha256(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {"a.cs": (
        "options.SecurityPolicyUri = SecurityPolicies.Basic256Sha256;\n")})))
    assert list(_policies(result)) == ["Basic256Sha256"]
    assert "SHA1" not in _families(result)


def test_stack_identifiers(tmp_path):
    files = {
        "server.c": "UA_ServerConfig_addSecurityPolicyBasic128Rsa15(config, &cert, &key);\n"
                    "UA_SecurityPolicy_EccNistP256AesGcm(policy, cert, key, logger);\n",
        "server.py": "server.set_security_policy("
                     "[ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt])\n"
                     "await client.set_security_string(\"Basic256,Sign,c.der,k.pem\")\n",
        "client.go": "opts := []opcua.Option{opcua.SecurityPolicy(\"Aes256Sha256RsaPss\")}\n"
                     "u := ua.SecurityPolicyURIBasic256Sha256\n",
        "Server.java": ".setSecurityPolicy(SecurityPolicy.Basic256Sha256)\n",
        "flows.json": '[{"type":"OpcUa-Endpoint","secpol":"Basic256","secmode":"Sign"}]\n',
    }
    policies = _policies(_tool(scan_repo)(str(_tree(tmp_path, files))))
    assert set(policies) == {"Basic128Rsa15", "ECC_nistP256_AesGcm",
                             "Aes128_Sha256_RsaOaep", "Basic256", "Aes256_Sha256_RsaPss",
                             "Basic256Sha256"}


def test_a_stack_only_uri_is_named_with_no_algorithm_claimed(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "policy.ts": f'Basic192 = "{URI}Basic192",\n'})))
    assert _policies(result)["Basic192"]["policy_status"] == "not in the OPC Foundation profile database"
    assert _families(result) == {}


def test_a_bare_word_never_matches(tmp_path):
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "a.py": "auth = 'Basic256Sha256'\nif x is None: pass\npolicy = SecurityPolicy.None\n"})))
    assert _policies(result) == {}


def test_the_cbom_carries_the_policy_and_its_status(tmp_path):
    doc = _tool(export_cbom)(str(_tree(tmp_path, {"Server.Config.xml": DOTNET_CONFIG})))
    comp = next(c for c in doc["components"] if c["name"] == "OPC UA SecurityPolicy Basic128Rsa15")
    assert comp["cryptoProperties"]["protocolProperties"]["type"] == "other"
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qrp:deprecated"] == "true"
    assert props["qrp:security_policy"] == "Basic128Rsa15"
    assert props["qrp:policy_status"] == "deprecated"


def test_a_longer_unknown_fragment_is_not_its_prefix(tmp_path):
    """`#Basic256Sha384` is no policy; read without the end guard it was Basic256,
    deprecated, with SHA-1 -- a finding invented out of a typo or a test value."""
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "Bad.Config.xml": f"<SecurityPolicyUri>{URI}Basic256Sha384</SecurityPolicyUri>\n"})))
    assert _policies(result) == {}
    assert _families(result) == {}
