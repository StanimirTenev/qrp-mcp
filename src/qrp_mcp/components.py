"""Algorithm names as components of library identifiers (ZA-OPRAVYANE rows 132, 133, 135).

A C library names the algorithm inside a longer name -- GNUTLS_SIGN_DSA_SHA256,
d2i_DSAPublicKey, wc_curve448_make_key, CKK_RSA -- and the family patterns in detectors.py
did not reach them: over the public headers of ten libraries (qrp-kachestvo/imena-2026-10-23,
measured 23.10.2026) 35 % of the classical names were found, GnuTLS's 0 of 91. One rule
over one vocabulary instead: a name is split into its components, at `_` and where the case
changes but never inside a run of capitals, and a component that IS an algorithm name
names its family. A component, never a substring: DESCRIPTION is one component and not
DES, ECCSET is not ECC, NID_description is `description`.

The short names (DH, EC, DES, DSA, RSA) are ordinary letters elsewhere -- DHCP_*, ECHO,
rsa_logo_draw, the Linux DSA switch layer -- so a component counts only behind a prefix the
library owns. Without one, only OpenSSL's module API is read: the name first, then a
lower-case function part (DSA_free, DH_get0_pqg, SHA224_Init) or an error code (RSA_R_*,
DH_F_*). DSA_COUNTY_CODE and DH_STATUS_OK have neither and stay silent; so do
OpenSSL's upper-case constants such as DH_CHECK_P_NOT_PRIME, which cannot be told from them.
TLS1_/SSL3_ cipher-suite constants are not read here: a suite is read as a suite.
"""

from __future__ import annotations

import re

# Component (upper-cased) -> family. Only families detectors.py already reports.
FAMILY = {
    "RSA": "RSA", "RSASSA": "RSA", "RSAES": "RSA",
    "DSA": "DSA", "DSS": "DSA",
    "DH": "DH", "DHE": "DH", "DHM": "DH", "DHX": "DH", "FFDH": "DH",
    "EC": "EC", "ECC": "EC", "ECP": "EC", "ECPK": "EC",
    "ECDSA": "ECDSA", "ECDH": "ECDH", "ECDHE": "ECDH", "ECDH1": "ECDH", "ECDHX": "ECDH",
    "FFDHE": "DH",
    "MD5": "MD5", "SHA1": "SHA1", "SHA224": "SHA224", "SHA3_224": "SHA3-224",
    "DES": "DES", "DES2": "3DES", "DES3": "3DES", "3DES": "3DES", "TDES": "3DES",
    "RC4": "RC4", "ARC4": "RC4", "ARCFOUR": "RC4",
    "X25519": "X25519", "CURVE25519": "X25519", "X448": "X448", "CURVE448": "X448",
    "ED25519": "Ed25519", "ED448": "Ed448", "EDDSA": "EdDSA",
}
_SIZED = re.compile(r"(FFDHE|RSA|DSA|DHE|DH)\d{3,5}")

# Prefixes a library owns: after one, every component is an algorithm slot. GnuTLS,
# libgcrypt, libssh2, Mbed TLS / PSA, OpenSSL (feature macros, OIDs, EVP, PEM, DER,
# providers, engines), NSS, wolfSSL and PKCS#11 (CKK_ key types, CKM_ mechanisms, CKA_
# attributes). SSL_ only before a lower-case function part: SSL_RSA_WITH_* is a suite.
_PREFIXES = (
    "GNUTLS_", "gnutls_", "GCRY_", "gcry_", "LIBSSH2_", "libssh2_",
    "MBEDTLS_", "mbedtls_", "PSA_WANT_", "PSA_ALG_", "PSA_KEY_TYPE_", "psa_",
    "OPENSSL_NO_", "NID_", "SN_", "LN_", "OBJ_", "EVP_", "PEM_", "d2i_", "i2d_",
    "OSSL_", "PROV_NAMES_", "ENGINE_", "ERR_R_", "BN_",
    "SEC_OID_", "CKK_", "CKM_", "CKA_", "WC_", "wc_", "WOLFSSL_", "wolfSSL_", "CTC_",
    "PKCS5_", "PKCS12_",
    # curl's own crypto API (ZA-OPRAVYANE row 120): Curl_MD5_update, curl_md5.h,
    # Curl_ed25519_sign, curl_des_set_odd_parity. Over curl's lib/ every Curl_/curl_ name
    # with an algorithm component is one (read 25.10.2026).
    "Curl_", "curl_",
)
# Also OpenSSL's: SSL_ calls, and every library's reason and function codes (X509_R_*,
# SSL_R_*); RSA_R_* and the like are the module API below.
_VENDOR_SHAPE = re.compile(r"SSL_(?:CTX_)?[a-z]|[A-Z][A-Z0-9]{1,7}_[RF]_[A-Z]")
# The same, as one search, plus OpenSSL's module API.
_GATE = re.compile(
    r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(p) for p in _PREFIXES) + r"|"
    + _VENDOR_SHAPE.pattern + r"|"
    r"(?:RSA|DSA|DH|DES|EC|SHA1|SHA224|MD5|RC4|DHparams|DSAparams)_)")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# OpenSSL's module API: DSA_free(, DH_get0_pqg(, RSA_OAEP_PARAMS_free(, EC_KEY_dup(,
# SHA224_Init(, and the error codes RSA_R_* / DH_F_*. A function only where it is called or
# declared: the Linux kernel has a struct field `DH_length` and a comment `EC_FP_FLAG_xxx`.
# Triple DES spells itself DES_ede3_* and DES_ecb3_*.
_MODULE_API = re.compile(
    r"(RSA|DSA|DH|DES|EC|SHA1|SHA224|MD5|RC4|DHparams|DSAparams)(?:"
    r"(?:_(?:SIG|GROUP|KEY|POINT|METHOD|OAEP_PARAMS|PSS_PARAMS))?_(?:[a-z]|[A-Z][a-z])\w*\s*\(|"
    r"_[RF]_[A-Z])")
_MODULE_FAMILY = {"DHparams": "DH", "DSAparams": "DSA"}
# A run of capitals before a capitalised word, a capitalised word, a run of capitals or
# digits, a lower-case word. `RSAPrivateKey` is RSA + Private + Key; `Arc4Process` is
# Arc4 + Process; `sha1WithRSAEncryption` is sha1 + With + RSA + Encryption.
_PART = re.compile(r"[A-Z0-9]+(?=[A-Z][a-z])|[A-Z][a-z]+[0-9]*|[A-Z0-9]+|[a-z]+[0-9]*")
# A hash or cipher beside one of these is a MAC or a key derivation (row 131).
_MAC = {"HMAC", "MAC", "CMAC", "PRF"}
_KDF = {"KDF", "PBKDF", "PBKDF1", "PBKDF2", "PBE", "PBES1", "PBES2"}
MAC_OR_KDF_NOTE = "a quantum computer does not break it"


def components(name: str) -> list[str]:
    """The upper-cased components of a name, with the ones a name spells in two parts put
    back together: CKM_SHA_1_HMAC is CKM + SHA1 + HMAC, DES_EDE3 is triple DES, EC_DHE is
    ECDH. ML_DSA, SLH_DSA, FN_DSA and Ed_DSA are not DSA: naming the post-quantum
    replacement DSA is the worst way to be wrong (see "DSA usage" in detectors.py)."""
    # OpenSSL glues `params` to the name: DHparams, DSAparams, ECparameters.
    name = re.sub(r"([A-Z]{2,})(param)", r"\1_\2", name)
    parts = [p.upper() for piece in re.split(r"[_\-]", name) for p in _PART.findall(piece)]
    out: list[str] = []
    for p in parts:
        last = out[-1] if out else ""
        if last == "SHA" and p in {"1", "224"}:
            out[-1] = "SHA" + p
        elif last == "SHA3" and p == "224":
            out[-1] = "SHA3_224"
        elif last == "DES" and p in {"EDE", "EDE2", "EDE3"}:
            out[-1] = "DES3"
        elif last == "EC" and p in {"DH", "DHE", "DSA"}:
            out[-1] = "EC" + p
        elif last in {"ML", "SLH", "FN", "ED"} and p == "DSA":
            out[-1] = last + p
        else:
            out.append(p)
    return out


def families(parts: list[str]) -> list[tuple[str, str | None]]:
    """(family, use) for each algorithm component, in order; use is "MAC", "KDF" or None."""
    out: list[tuple[str, str | None]] = []
    for i, p in enumerate(parts):
        # A size glued on: FFDHE6144, RSA2048, DSA1024.
        sized = _SIZED.fullmatch(p)
        family = FAMILY.get(sized.group(1) if sized else p)
        # dhSinglePass-stdDH-* and -cofactorDH-* are the X9.63 ECDH schemes (RFC 5753).
        if family == "DH" and "SINGLE" in parts and "PASS" in parts:
            family = "ECDH"
        if not family or any(f == family for f, _ in out):
            continue
        near = set(parts[max(0, i - 2):i + 3])
        use = None
        if family in {"MD5", "SHA1", "SHA224", "SHA3-224"}:
            use = "MAC" if near & _MAC else "KDF" if near & _KDF else None
        elif family in {"DES", "3DES"} and near & _MAC:     # CBC-MAC; PBE's cipher encrypts
            use = "MAC"
        out.append((family, use))
    return out


def _describe(family: str, use: str | None, name: str) -> str:
    if use:
        return f"{family} used in a {use} ({name}); {MAC_OR_KDF_NOTE}"
    return f"{family} named as a component of {name}"


def scan(line: str) -> list[tuple[str, int, str]]:
    """(family, position, description) for each algorithm named inside a library name."""
    out: list[tuple[str, int, str]] = []
    for gate in _GATE.finditer(line):
        start = gate.start()
        name = _IDENT.match(line, start).group(0)
        if not (name.startswith(_PREFIXES) or _VENDOR_SHAPE.match(name)):
            module = _MODULE_API.match(line, start)
            if not module:
                continue
            family = _MODULE_FAMILY.get(module.group(1)) or FAMILY[module.group(1)]
            if family == "DES" and re.match(r"DES_(?:ede|ecb3)", name):
                continue
            out.append((family, start, _describe(family, None, name)))
            continue
        for family, use in families(components(name)):
            out.append((family, start, _describe(family, use, name)))
    if "'" in line or '"' in line:
        out += _names(line)
    return out


# X.509 / PKIX algorithm names as a whole string, as OpenSSL's objects.txt, node-forge's
# oids.js and pyca's OID names write them: "sha1WithRSAEncryption", "id-ecPublicKey",
# "ecdsa-with-SHA224", "RSA-SHA1" (row 134). A compound only: a bare 'rsa' value is row 126.
# One algorithm name alone needs the shape of an object name around it -- Encryption, With,
# Agreement, an `id-` start or PublicKey -- because "rsa-logo", "ec-window", the SSH key
# file 'id_rsa' and the measurement's negative control "md5_checksum_column_name" are
# strings too.
_NAME_STRING = re.compile(r"(?<![A-Za-z0-9_])[\"']([A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*)[\"']")
_OBJECT_WORDS = {"ENCRYPTION", "WITH", "AGREEMENT"}
_PUBLIC_KEY = {"RSA", "DSA", "DH", "EC", "ECDSA", "ECDH", "X25519", "X448", "Ed25519", "Ed448",
               "EdDSA"}
_SUITE_PARTS = ("AES", "CBC", "GCM", "CCM", "CAMELLIA", "ARIA", "CHACHA", "POLY1305", "SEED",
                "IDEA", "NULL", "EXP", "ADH", "AECDH", "PSK", "SRP", "KRB5")


def _names(line: str) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for m in _NAME_STRING.finditer(line):
        name = m.group(1)
        parts = components(name)
        if len(parts) < 2:
            continue
        found = families(parts)
        shaped = bool(_OBJECT_WORDS & set(parts)) or name.startswith("id-") or "PUBLIC" in parts
        public_key = _PUBLIC_KEY & {f for f, _ in found}
        if not found or not shaped and (len(found) == 1 or not public_key):
            continue
        # A cipher suite is read as a suite (scan_cipher_suites), not as a name.
        if parts[0] in {"TLS", "SSL", "TLS1", "SSL3"} or any(p.startswith(_SUITE_PARTS)
                                                              for p in parts):
            continue
        for family, use in found:
            out.append((family, m.start(1), (_describe(family, use, name) if use else
                                             f"{family} named by the algorithm name {name}")))
    return out
