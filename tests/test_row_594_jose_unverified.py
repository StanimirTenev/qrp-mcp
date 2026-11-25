"""Row 594 (25.11.2026; probe `scratchpad/algnone/`).

`jwt.decode(token, options={"verify_signature": False})` gave nothing; `algorithms=["none", "RS256"]`
named only RSA; jsonwebtoken's `algorithms: ['none', ...]` and `jwt.sign(..., {algorithm: 'none'})`
and YAML `algorithm: none` gave nothing. A token accepted or made with no verified signature is worse
than a classical one, and the inventory was silent.

Now each documented way a JOSE library accepts or makes an Unsecured JWS ("An Unsecured JWS uses the
"alg" value "none"", RFC 7518 section 3.6) or reads a token without verifying its signature is a row
of the family `JWT-unverified`: a finding classified `deprecated_weak` (severity high, not quantum
vulnerable -- there is no signature for a quantum computer to break). Spellings and their pages:
* PyJWT: `options={"verify_signature": False}` ("you can set the verify_signature option to False",
  pyjwt.readthedocs.io usage), `algorithms=[..."none"...]`, `jwt.encode(..., algorithm="none")`;
  python-jose takes the same options; its `get_unverified_claims` (no page read);
* jsonwebtoken: `algorithms: ['none']` and `algorithm: 'none'` ("none | No digital signature or MAC
  value included"), `jwt.decode(token)` ("Returns the decoded payload without verifying if the
  signature is valid"), in a file that requires jsonwebtoken;
* jose (panva): `UnsecuredJWT` ("Encodes and decodes { "alg": "none" } Unsecured JWTs"), `decodeJwt`
  ("without validating its JWS Signature");
* Nimbus JOSE+JWT: `Algorithm.NONE` / `JWSAlgorithm.NONE` ("No algorithm (unsecured JOSE object
  without signature / encryption)"), `PlainJWT` ("Unsecured (plain) JSON Web Token");
* jjwt: `.unsecured()` ("Enables parsing of Unsecured JWTs"), `parseUnsecuredClaims`,
  `parseUnsecuredContent` and their deprecated `parseClaimsJwt` / `parseContentJwt`, `Jwts.SIG.NONE`;
* golang-jwt: `jwt.SigningMethodNone`, `jwt.UnsafeAllowNoneSignatureType`, `ParseUnverified`;
* configuration: a JWT/JWS algorithm setting whose value is `none`.

"none" counts only in an algorithm setting or argument of a JOSE library, never as any string.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo


def _scan(tmp_path: Path, name: str, text: str) -> dict:
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)


def _rows(result: dict) -> list[int]:
    return sorted(i["line"] for i in result["evidence"]["source_code"]
                  if i["algorithm"] == "JWT-unverified")


@pytest.mark.parametrize("name,text,line", [
    ("a.py", 'import jwt\nc = jwt.decode(token, options={"verify_signature": False})\n', 2),
    ("a.py", "import jwt\nc = jwt.decode(t, key, algorithms=['none', 'RS256'])\n", 2),
    ("a.py", 'import jwt\nt = jwt.encode({"a": 1}, None, algorithm="none")\n', 2),
    ("a.py", "from jose import jwt\nc = jwt.get_unverified_claims(token)\n", 2),
    ("b.js", "const jwt = require('jsonwebtoken');\nconst p = jwt.verify(t, k, { algorithms: ['none', 'HS256'] });\n", 2),
    ("b.js", "const jwt = require('jsonwebtoken');\nconst u = jwt.sign(payload, null, { algorithm: 'none' });\n", 2),
    ("b.js", "const jwt = require('jsonwebtoken');\nconst c = jwt.decode(token);\n", 2),
    ("b.ts", "import { UnsecuredJWT } from 'jose';\nconst t = new UnsecuredJWT({ a: 1 }).encode();\n", 2),
    ("b.ts", "import * as jose from 'jose';\nconst c = jose.decodeJwt(token);\n", 2),
    ("A.java", "import com.nimbusds.jose.*;\nclass A { Algorithm a = Algorithm.NONE; }\n", 2),
    ("A.java", "import com.nimbusds.jwt.*;\nclass A { JWT j = new PlainJWT(claims); }\n", 2),
    ("A.java", "class A { Object p = Jwts.parser().unsecured().build(); }\n", 1),
    ("A.java", "import io.jsonwebtoken.*;\nclass A { Object c = parser.parseUnsecuredClaims(jwt); }\n", 2),
    ("A.java", "class A { Object c = Jwts.parser().setSigningKey(k).parseClaimsJwt(jwt); }\n", 1),
    ("A.java", "class A { Object s = Jwts.SIG.NONE; }\n", 1),
    ("m.go", 'package m\nimport "github.com/golang-jwt/jwt/v5"\nvar t = jwt.NewWithClaims(jwt.SigningMethodNone, c)\n', 3),
    ("m.go", 'package m\nimport "github.com/golang-jwt/jwt/v5"\nvar k = jwt.UnsafeAllowNoneSignatureType\n', 3),
    ("m.go", 'package m\nfunc f() { t, _, _ := jwt.NewParser().ParseUnverified(s, c); _ = t }\n', 2),
    ("app.yml", "jwt:\n  algorithm: none\n", 2),
    ("application.properties", "security.jwt.signature-algorithm=none\n", 1),
])
def test_each_spelling_is_a_row(tmp_path, name, text, line):
    assert _rows(_scan(tmp_path, name, text)) == [line]


@pytest.mark.parametrize("name,text", [
    ("a.py", 'x = "none"\nmode = "none"\n'),
    ("a.py", "import jwt\nc = jwt.decode(t, key, algorithms=['RS256'])\n"),
    ("a.py", 'import jwt\nc = jwt.decode(t, key, options={"verify_signature": True})\n'),
    ("b.js", "const c = something.decode(token);\n"),
    ("b.js", "const z = zlib.compress(b, { algorithm: 'none' });\n"),
    ("app.yml", "compression:\n  algorithm: none\n"),
    ("A.java", "class A { Padding p = Padding.NONE; }\n"),
    ("A.java", "class A { Object a = Algorithm.NONE; Object p = cfg.unsecured(); }\n"),
])
def test_none_elsewhere_is_not_a_row(tmp_path, name, text):
    assert _rows(_scan(tmp_path, name, text)) == []


def test_the_finding_is_weak_not_quantum(tmp_path):
    result = _scan(tmp_path, "a.py", 'import jwt\nc = jwt.decode(token, options={"verify_signature": False})\n')
    finding = next(f for f in result["findings"] if f["algorithm_family"] == "JWT-unverified")
    assert finding["classification"] == "deprecated_weak"
    assert finding["quantum_vulnerable"] is False and finding["severity"] == "high"
    assert "forge" in finding["reason"]


def test_the_probe_tree(tmp_path):
    files = {"a.py": ('import jwt\nclaims = jwt.decode(token, options={"verify_signature": False})\n'
                      'claims2 = jwt.decode(token, key, algorithms=["none", "RS256"])\n'),
             "b.js": ("const jwt = require('jsonwebtoken');\n"
                      "const p = jwt.verify(token, key, { algorithms: ['none', 'HS256'] });\n"
                      "const unsigned = jwt.sign(payload, null, { algorithm: 'none' });\n"),
             "app.yml": "jwt:\n  algorithm: none\n"}
    for n, t in files.items():
        (tmp_path / n).write_text(t)
    result = scan_directory(tmp_path)
    rows = sorted((i["path"], i["line"]) for i in result["evidence"]["source_code"]
                  if i["algorithm"] == "JWT-unverified")
    assert rows == [("a.py", 2), ("a.py", 3), ("app.yml", 2), ("b.js", 2), ("b.js", 3)]
    assert any(i["algorithm"] == "RSA" and i["line"] == 3 and i["path"] == "a.py"
               for i in result["evidence"]["source_code"])


def test_cli_and_mcp_carry_it(tmp_path):
    root = tmp_path / "tree"
    _scan(root, "a.py", 'import jwt\nc = jwt.decode(token, options={"verify_signature": False})\n')
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out)], check=True, capture_output=True,
                   env=dict(os.environ))
    for result in (json.loads(out.read_text()), scan_repo(str(root))):
        assert "JWT-unverified" in [f["algorithm_family"] for f in result["findings"]]
