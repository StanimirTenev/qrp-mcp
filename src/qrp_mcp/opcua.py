"""OPC UA SecurityPolicies: what each one rests on, and where a configuration names it.

Until this release OPC UA was invisible: `.xml` was not read, and no rule knew a
SecurityPolicy URI (Ogochukwu Friday Ikwuogu, 6 Oct 2026).

The table is the OPC Foundation profile database, the one primary source for the 1.05
SecurityPolicy facets -- Part 7 v1.05.02: "The actual Profiles are maintained in an
online database". Read 7 Oct 2026 from
https://profiles.opcfoundation.org/api/profilegroup/export/xml/171 (UACore 1.05): 30
SecurityPolicy URIs, the algorithms of each from its conformance units, and
`ReleaseStatus="Deprecated"` on ten. It is a live database. Every asymmetric side is
RSA, ECDSA+ECDH, EdDSA+X25519/X448 or finite-field DH with RSA, all broken by a quantum
computer. No post-quantum SecurityPolicy exists, in the released export or in the draft one.

A policy without the attribute is reported as "not marked deprecated", not as released:
reading an absent attribute as Released is an inference the source does not make.
"""

from __future__ import annotations

import re

URI_PREFIX = "opcfoundation.org/UA/SecurityPolicy#"

# `.xml` and `.json5` are read only when they carry the prefix: a .NET `*.Config.xml`
# and an open62541 `*.json5` are where those stacks declare their policies, and every
# other XML in a tree stays the declared boundary it was.
SNIFF_EXTENSIONS = (".json5", ".xml")
SNIFF_MARKER = URI_PREFIX.encode()

_DEPRECATED = "deprecated"
_NOT_MARKED = "not marked deprecated"
_NON_STANDARD = "not in the OPC Foundation profile database"

# The six un-suffixed ECC policies: the database deprecates them, the .NET reference
# stack does not (SecurityPolicies.cs, IsDeprecated = false; docs list them as
# "Traditional ECC curves"). Unresolved; said where it applies.
_DOTNET_DISAGREES = (" The OPC Foundation .NET stack does not mark it deprecated "
                     "(IsDeprecated = false); the profile database does.")

# fragment -> (families, status, what to say). Families are the names this scanner
# already classifies; SHA1 only where the policy signs with RSA-PKCS15-SHA1.
POLICIES: dict[str, tuple[tuple[str, ...], str, str]] = {
    "None": ((), _NOT_MARKED, "no asymmetric or symmetric algorithm (AsymmetricSignatureAlgorithm_None)"),
    "Basic128Rsa15": (("RSA", "SHA1"), _DEPRECATED,
                      "RSA-PKCS15-SHA1 signatures, RSA-PKCS15 encryption, RSA 1024-2048; "
                      "deprecated since 1.04 for SHA-1"),
    "Basic256": (("RSA", "SHA1"), _DEPRECATED,
                 "RSA-PKCS15-SHA1 signatures, RSA-OAEP-SHA1 encryption, RSA 1024-2048; "
                 "deprecated since 1.04 for SHA-1"),
    "Basic256Sha256": (("RSA",), _NOT_MARKED,
                       "RSA-PKCS15-SHA2-256 signatures, RSA-OAEP-SHA1 encryption, RSA 2048-4096"),
    "Aes128_Sha256_RsaOaep": (("RSA",), _NOT_MARKED,
                              "RSA-PKCS15-SHA2-256 signatures, RSA-OAEP-SHA1 encryption, RSA 2048-4096"),
    "Aes256_Sha256_RsaPss": (("RSA",), _NOT_MARKED,
                             "RSA-PSS-SHA2-256 signatures, RSA-OAEP-SHA2-256 encryption, RSA 2048-4096"),
    "RSA_DH_AesGcm": (("RSA", "DH"), _NOT_MARKED,
                      "RSA-PKCS15-SHA2-256 signatures, finite-field DH (ffdhe2048-4096)"),
    "RSA_DH_ChaChaPoly": (("RSA", "DH"), _NOT_MARKED,
                          "RSA-PKCS15-SHA2-256 signatures, finite-field DH (ffdhe2048-4096)"),
    "PubSub-Aes128-CTR": ((), _NOT_MARKED, "symmetric only (AES128-CTR, HMAC-SHA2-256)"),
    "PubSub-Aes256-CTR": ((), _NOT_MARKED, "symmetric only (AES256-CTR, HMAC-SHA2-256)"),
}
for _curve, _families, _what in (
        ("nistP256", ("ECDSA", "ECDH"), "ECDSA-SHA2-256 signatures, ECDH P-256"),
        ("nistP384", ("ECDSA", "ECDH"), "ECDSA-SHA2-384 signatures, ECDH P-384"),
        ("brainpoolP256r1", ("ECDSA", "ECDH"), "ECDSA-SHA2-256 signatures, ECDH brainpoolP256r1"),
        ("brainpoolP384r1", ("ECDSA", "ECDH"), "ECDSA-SHA2-384 signatures, ECDH brainpoolP384r1"),
        ("curve25519", ("Ed25519", "X25519"), "Ed25519 signatures, X25519"),
        ("curve448", ("Ed448", "X448"), "Ed448 signatures, X448")):
    POLICIES[f"ECC_{_curve}"] = (_families, _DEPRECATED,
                                 _what + "; replaced by the _AesGcm and _ChaChaPoly facets")
    POLICIES[f"ECC_{_curve}_AesGcm"] = (_families, _NOT_MARKED, _what)
    POLICIES[f"ECC_{_curve}_ChaChaPoly"] = (_families, _NOT_MARKED, _what)
# Two interim names, deprecated.
POLICIES["ECC_curve25519_ChaCha20Poly1305"] = (("Ed25519", "X25519"), _DEPRECATED,
                                               "Ed25519 signatures, X25519 (interim name)")
POLICIES["ECC_curve448_ChaCha20Poly1305"] = (("Ed448", "X448"), _DEPRECATED,
                                             "Ed448 signatures, X448 (interim name)")

# Spellings the stacks use that the database does not. Mapped to a policy only where
# the stack's source shows which one: open62541's JSON parser maps `EccNistP256` to
# ECC_nistP256, and node-opcua's `PubSub_Aes128_CTR` is the PubSub policy with
# underscores. The rest (.NET `Https`, node-opcua `Basic128`/`Basic192`/
# `Basic192Rsa15`/`Basic256Rsa15`, Node-RED `Aes128_Sha256`) have no primary source
# for their algorithms, so they are named and nothing is claimed about them.
_ALIASES = {
    "EccNistP256": "ECC_nistP256",
    "PubSub_Aes128_CTR": "PubSub-Aes128-CTR",
    "PubSub_Aes256_CTR": "PubSub-Aes256-CTR",
}

# open62541, asyncua and gopcua write the names without underscores.
_SQUASHED = {
    "Aes128Sha256RsaOaep": "Aes128_Sha256_RsaOaep",
    "Aes256Sha256RsaPss": "Aes256_Sha256_RsaPss",
    "EccNistP256AesGcm": "ECC_nistP256_AesGcm",
    "EccNistP256ChaChaPoly": "ECC_nistP256_ChaChaPoly",
    "EccNistP256": "ECC_nistP256",
    "EccNistP384": "ECC_nistP384",
    "EccBrainpoolP256r1": "ECC_brainpoolP256r1",
    "EccBrainpoolP384r1": "ECC_brainpoolP384r1",
    "EccCurve25519": "ECC_curve25519",
    "EccCurve448": "ECC_curve448",
    "Aes128CtrTPM": "PubSub-Aes128-CTR",
    "Aes256CtrTPM": "PubSub-Aes256-CTR",
    "Aes128Ctr": "PubSub-Aes128-CTR",
    "Aes256Ctr": "PubSub-Aes256-CTR",
    "NoSecurity": "None",
}

_RSA5 = r"Basic128Rsa15|Basic256Sha256|Basic256"
# Longest first, and a guard after: without it Basic256 matches inside Basic256Sha256
# and ECC_nistP256 inside ECC_nistP256_AesGcm.
_END = r"(?![A-Za-z0-9_])"
_URI_FRAGMENT = (
    r"None|Basic128Rsa15|Basic256Sha256|Basic256Rsa15|Basic256|Aes128_Sha256_RsaOaep|"
    r"Aes256_Sha256_RsaPss|RSA_DH_(?:AesGcm|ChaChaPoly)|"
    r"ECC_(?:nistP256|nistP384|brainpoolP256r1|brainpoolP384r1|curve25519|curve448)"
    r"(?:_AesGcm|_ChaChaPoly|_ChaCha20Poly1305)?|PubSub[-_]Aes(?:128|256)[-_]CTR|"
    r"EccNistP256|Https|Basic128|Basic192Rsa15|Basic192")

# A bare word -- `Basic256Sha256`, `None` -- is never matched: only inside the URI or a
# stack's own identifier. The singular `SecurityPolicy.` form (Milo, node-opcua) leaves
# out `None`, which is too common an enum member to stand for OPC UA on its own.
_PATTERNS: list[re.Pattern] = [
    re.compile(r"opcfoundation\.org/UA/SecurityPolicy#(?P<p>" + _URI_FRAGMENT + r")" + _END),
    # .NET: the URI is concatenated in source, so only the identifier can be matched.
    re.compile(r"\bSecurityPolicies\.(?P<p>None|" + _RSA5 + r"|Aes128_Sha256_RsaOaep|"
               r"Aes256_Sha256_RsaPss|RSA_DH_(?:AesGcm|ChaChaPoly)|"
               r"ECC_(?:nistP256|nistP384|brainpoolP256r1|brainpoolP384r1|curve25519|curve448)"
               r"(?:_AesGcm|_ChaChaPoly|_ChaCha20Poly1305)?|Https)" + _END),
    # open62541
    re.compile(r"\bUA_(?:SecurityPolicy_|ServerConfig_addSecurityPolicy_?|PubSubSecurityPolicy_)"
               r"(?P<p>None|" + _RSA5 + r"|Aes128Sha256RsaOaep|Aes256Sha256RsaPss|"
               r"EccNistP256AesGcm|EccNistP256ChaChaPoly|EccNistP256|EccNistP384|"
               r"EccBrainpoolP256r1|EccBrainpoolP384r1|EccCurve25519|EccCurve448|"
               r"Aes128CtrTPM|Aes256CtrTPM|Aes128Ctr|Aes256Ctr)\s*\("),
    # asyncua
    re.compile(r"\bSecurityPolicyType\.(?:(?P<p>NoSecurity)|(?P<q>" + _RSA5 +
               r"|Aes128Sha256RsaOaep|Aes256Sha256RsaPss)_(?:Sign|SignAndEncrypt))\b"),
    re.compile(r"\bSecurityPolicy(?P<p>" + _RSA5 + r"|Aes128Sha256RsaOaep|Aes256Sha256RsaPss)\b"),
    re.compile(r"set_security_string\(\s*[\"'](?P<p>" + _RSA5 +
               r"|Aes128Sha256RsaOaep|Aes256Sha256RsaPss),"),
    # Milo, node-opcua
    re.compile(r"\bSecurityPolicy\.(?P<p>" + _RSA5 + r"|Aes128_Sha256_RsaOaep|"
               r"Aes256_Sha256_RsaPss|PubSub_Aes(?:128|256)_CTR|Basic128|Basic192Rsa15|"
               r"Basic192|Basic256Rsa15)" + _END),
    # gopcua
    re.compile(r"\bSecurityPolicyURI(?P<p>None|" + _RSA5 +
               r"|Aes128Sha256RsaOaep|Aes256Sha256RsaPss)\b"),
    re.compile(r"\b(?:opcua\.SecurityPolicy|EnableSecurity)\(\s*\"(?P<p>None|" + _RSA5 +
               r"|Aes128Sha256RsaOaep|Aes256Sha256RsaPss)\""),
    # Node-RED flows
    re.compile(r"\"secpol\"\s*:\s*\"(?P<p>Basic128Rsa15|Basic256Sha256|Basic256Rsa15|Basic256|"
               r"Basic192Rsa15|Basic192|Basic128|Aes128_Sha256_RsaOaep|Aes128_Sha256|"
               r"PubSub_Aes(?:128|256)_CTR|None)\""),
]

# Every pattern above contains one of these; a line with none of them is skipped unread.
_CHEAP = ("ecurityPolic", "UA_", "secpol", "set_security_string", "EnableSecurity")


def canonical(written: str) -> str:
    """The database's name for a spelling, or the spelling when it has none."""
    name = _SQUASHED.get(written, written)
    return _ALIASES.get(name, name)


def scan(line: str) -> list[tuple[str, int]]:
    """(policy as the database names it, position) for each policy this line names."""
    if not any(word in line for word in _CHEAP):
        return []
    out: list[tuple[str, int]] = []
    seen: set[int] = set()
    for pattern in _PATTERNS:
        for match in pattern.finditer(line):
            name, start = next((value, match.start(key))
                               for key, value in match.groupdict().items() if value)
            if start in seen:
                continue
            seen.add(start)
            out.append((canonical(name), start))
    return sorted(out, key=lambda item: item[1])


def describe(policy: str) -> tuple[tuple[str, ...], str, str]:
    """(families, status, sentence) for a policy as `scan` returns it."""
    if policy in POLICIES:
        families, status, what = POLICIES[policy]
        note = _DOTNET_DISAGREES if (status == _DEPRECATED and policy.startswith("ECC_")
                                     and policy.count("_") == 1) else ""
        word = ("deprecated in the OPC Foundation profile database" if status == _DEPRECATED
                else "not marked deprecated in the OPC Foundation profile database")
        return families, status, f"OPC UA SecurityPolicy {policy}: {what}; {word}.{note}"
    return (), _NON_STANDARD, (f"OPC UA SecurityPolicy {policy}: {_NON_STANDARD}; a stack's "
                               f"own name, and what it uses is not established here.")
