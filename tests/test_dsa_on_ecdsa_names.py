"""DSA read from ECDSA and EdDSA code (corpus regression, release gate §4b, kragg-3/07, 26.10.2026).

The regression v0.36.0 -> 0adb299 gave 23 new disagreements; 17 were DSA on code that is not DSA,
inherited from round 3's identifier rule. Three causes, one test each:

- `components()` glued DSA to EC/Ed only when it stood alone: `testEcDsa256` and `EdDSA25519`
  carry a size, and lowerCamelCase splits .NET's `eCDsa` into E + C + Dsa (sshj, AspNetCoreCertificates).
- DSS beside a signature is FIPS 186's (r, s) encoding, which DSA and ECDSA share: pyca's
  `encode_dss_signature` / `decode_dss_signature`, cryptography-kotlin's `DssRawSignatureVerifier`
  (letsseal, cuhepy, cryptography-kotlin).
- .NET's `DSASignatureFormat` is the encoding enum `ECDsa.SignData` takes too; it was read as a
  DSA type at call/high (fido2-net-lib). `DSASignatureFormatter` is DSA's own and stays.
"""

import pytest

from qrp_mcp.scan import scan_directory


def _rows(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return scan_directory(tmp_path)["evidence"]["source_code"]


def _lines(rows, family):
    return sorted(e["line"] for e in rows if e["algorithm"] == family)


CS_ECDSA = """using System.Security.Cryptography;

public class C
{
    public X509Certificate2 NewECDsaCertificate(ECDsaConfiguration eCDsaConfiguration)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.KeySize = eCDsaConfiguration.KeySize;
        var eCDsa = cert.GetECDsaPrivateKey();
        return ecdsa.VerifyData(data, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }
    public byte[] Sign(ECDsa leafKey) =>
        leafKey.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
}
"""

JAVA_ECDSA = """import java.security.KeyPair;
import net.schmizz.sshj.common.KeyAlgorithms;

public class T {
    static Object ED25519 = KeyAlgorithms.EdDSA25519();
    public void testEcDsa256() throws Exception { }
    public void testEcDsa521() throws Exception { }
    public void testSlhDsa128() throws Exception { }
}
"""

PY_ECDSA = """from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

def verify(pub, r, s, data):
    pub.verify(encode_dss_signature(r, s), data, ec.ECDSA(hash_alg))

def split(signature):
    r, s = decode_dss_signature(signature)
    return r, s
"""

KT_ECDSA = """package algorithms

import java.security.Signature

internal class JdkEcdsa {
    fun verifier(format: ECDSA.SignatureFormat) = when (format) {
        ECDSA.SignatureFormat.RAW -> DssRawSignatureVerifier(verifier, curveOrderSize)
        ECDSA.SignatureFormat.DER -> DssRawSignatureGenerator(generator, curveOrderSize)
    }
    fun raw(sig: ByteArray) = convertDssDerSignatureToRaw(curveOrderSize, sig)
}
"""

def test_ecdsa_names_in_dotnet_are_not_dsa(tmp_path):
    rows = _rows(tmp_path, "CreateCertificates.cs", CS_ECDSA)
    assert _lines(rows, "DSA") == [], [(e["line"], e["description"]) for e in rows if e["algorithm"] == "DSA"]
    assert {5, 8, 9} <= set(_lines(rows, "ECDSA")), _lines(rows, "ECDSA")


def test_sized_ecdsa_and_eddsa_names_are_not_dsa(tmp_path):
    rows = _rows(tmp_path, "T.java", JAVA_ECDSA)
    assert _lines(rows, "DSA") == [], [(e["line"], e["description"]) for e in rows if e["algorithm"] == "DSA"]
    assert {6, 7} <= set(_lines(rows, "ECDSA")), _lines(rows, "ECDSA")


def test_dss_signature_encoding_is_not_dsa(tmp_path):
    rows = _rows(tmp_path, "oidc.py", PY_ECDSA)
    assert _lines(rows, "DSA") == [], [(e["line"], e["description"]) for e in rows if e["algorithm"] == "DSA"]
    rows = _rows(tmp_path, "JdkEcdsa.kt", KT_ECDSA)
    assert _lines(rows, "DSA") == [], [(e["line"], e["description"]) for e in rows if e["algorithm"] == "DSA"]


@pytest.mark.parametrize("line", [
    "var f = new DSASignatureFormatter(dsa);",
    "DSA dsa = DSA.Create(); var key = dsa.ExportParameters(true); DsaSignature sig = null;",
    "key = paramiko.DSSKey.generate(1024)",
    "if (DSA_verify(0, dgst, len, sig, siglen, dsa) != 1) return -1;",
])
def test_real_dsa_stays(tmp_path, line):
    ext = ".py" if "paramiko" in line else ".c" if "DSA_verify" in line else ".cs"
    rows = _rows(tmp_path, "a" + ext, line + "\n")
    assert _lines(rows, "DSA") == [1], [(e["algorithm"], e["description"]) for e in rows]
