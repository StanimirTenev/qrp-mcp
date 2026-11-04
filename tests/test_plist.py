"""Apple property lists (ZA-OPRAVYANE row 306; fixtures L1/f07-plist). `.plist` was type not
claimed on 0.41.0. Apple's documentation (the JSON its pages load, read 04.11.2026):

* https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads
  -- "A Boolean value indicating whether App Transport Security restrictions are disabled for
  all network connections." "Disabling ATS means that unsecured HTTP connections are allowed."
* https://developer.apple.com/documentation/bundleresources/information-property-list/nsexceptionminimumtlsversion
  -- "The minimum Transport Layer Security (TLS) version for network connections." "The value
  is a string, with a default value of TLSv1.2."

Not done (the minimum): the plist's other strings are not run through the text rules.
"""

import plistlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from qrp_mcp.scan import scan_directory

INFO = {"NSAppTransportSecurity": {
    "NSAllowsArbitraryLoads": True,
    "NSExceptionDomains": {"legacy.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0"}}}}


def _keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    public = ec.generate_private_key(ec.SECP256R1()).public_key()
    return {"rsaPrivate": private.private_bytes(serialization.Encoding.DER,
                                                serialization.PrivateFormat.TraditionalOpenSSL,
                                                serialization.NoEncryption()),
            "ecPublic": public.public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)}


def test_ats_in_xml_plist(tmp_path):
    (tmp_path / "Info.plist").write_bytes(plistlib.dumps(INFO))
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["Info.plist"]
    protocols = result["evidence"]["protocols"]
    assert [p["setting"] for p in protocols if p.get("tls_disabled")] == ["NSAllowsArbitraryLoads"]
    assert [p["version"] for p in protocols if p.get("version")] == ["TLSv1.0"]
    assert result["summary"]["deprecated_protocols"] == ["TLSv1.0"]


def test_keys_as_base64_strings_and_data(tmp_path):
    keys = _keys()
    import base64
    (tmp_path / "TestKeys.plist").write_bytes(plistlib.dumps(
        {"rsaPrivate": base64.b64encode(keys["rsaPrivate"]).decode(), "ecPublic": keys["ecPublic"]}))
    (tmp_path / "Binary.plist").write_bytes(plistlib.dumps({"k": keys["rsaPrivate"]},
                                                           fmt=plistlib.FMT_BINARY))
    result = scan_directory(tmp_path)
    rows = sorted((f["path"], f["algorithm"], f.get("key_size")) for f in result["evidence"]["source_code"])
    assert rows == [("Binary.plist", "RSA", 1024), ("TestKeys.plist", "EC", 256),
                    ("TestKeys.plist", "RSA", 1024)]
    assert len(result["evidence"]["embedded_keys"]) == 2


def test_a_broken_plist_is_named_not_decoded(tmp_path):
    (tmp_path / "Bad.plist").write_text("<plist><dict><key>x</key>")
    result = scan_directory(tmp_path)
    assert result["claimed_but_not_decoded"] == ["Bad.plist"]
