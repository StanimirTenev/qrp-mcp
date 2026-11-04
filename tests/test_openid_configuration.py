"""An OpenID provider's discovery document is read (ZA-OPRAVYANE row 352, second half; fixture
L2/17-jwks/.well-known/openid-configuration). It has no extension and was skipped. OpenID
Connect Discovery 1.0, https://openid.net/specs/openid-connect-discovery-1_0.html, 4: providers
"MUST make a JSON document available at the path formed by concatenating the string
/.well-known/openid-configuration"; id_token_signing_alg_values_supported is a "JSON array
containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID
Token".
"""

import json

from qrp_mcp.scan import scan_directory


def test_discovery_document_algorithms(tmp_path):
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "openid-configuration").write_text(json.dumps({
        "issuer": "https://id.example.com",
        "id_token_signing_alg_values_supported": ["RS256", "ES256"]}, indent=2))
    result = scan_directory(tmp_path)
    assert result["files_read"] == [".well-known/openid-configuration"]
    assert {"RSA", "ECDSA"} <= {f["algorithm"] for f in result["evidence"]["source_code"]}
