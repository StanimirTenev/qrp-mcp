"""Detection patterns for classical crypto usage and CI signing commands."""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
from pathlib import Path
from typing import Any

from . import aws_tls, components, dnssec, ike, oids, opcua
from .classifier import _PQC_SCHEMES
from .assets import _LOCKFILES as LOCKFILES
from .assets import (_COMMENT_START, _cipher_setting, _group_setting, image_pins, is_manifest,
                     library_support, pinned_versions,
                     scan_hybrid_groups, scan_manifest, scan_openssl_fips,
                     scan_protocols, scan_ssh_kex, scan_static_rsa_kex, scan_tls_groups,
                     scan_tls_listeners, static_rsa_positions)
from .certificates import (is_certificate_file, is_undecoded, looks_like_key_file,
                           scan_certificate_file, small_scalar_keys)

SOURCE_EXTENSIONS = {
    ".py", ".go", ".js", ".ts", ".java", ".rb", ".php", ".c", ".cpp", ".cs", ".sh",
    # C and C++ headers. Declarations live here, and in a C codebase they are
    # roughly half the tree -- reading .c but not .h reports a fraction of the
    # file count as if it were the whole language.
    ".h", ".hpp", ".hh", ".cc", ".cxx",
    # Measured on five real trees: these carried 1,600 findings the scan never saw.
    # `.inc` holds the assembly and C fragments of implementations (OpenSSL's ML-DSA
    # among them), `.t` is a Perl test recipe -- tests are code, and skipping them
    # silently is the practice this scanner argues against -- and `.in`/`.cmake`
    # are build files that enumerate which algorithms the tree implements at all.
    ".inc", ".t", ".in", ".cmake",
    # PowerShell and Perl. .sh was already here, so leaving these out was an
    # oversight rather than a scope decision: a Windows estate keeps its
    # certificate handling in .ps1, and OpenSSL's build is Perl.
    ".ps1", ".psm1", ".pl", ".pm",
    # Smart contracts and chain tooling
    ".sol", ".rs", ".move", ".cairo",
    # JVM languages other than Java, and the ES-module spellings of JavaScript.
    # Measured on a rival's labelled corpus: eight of its 176 labels sit in .kt and
    # .mjs files, and this scanner opened none of them -- the single largest hole in
    # its recall, and a reading gap rather than a detection one. Its own
    # files_skipped_by_type named them all along.
    ".kt", ".kts", ".scala", ".sc", ".groovy",
    ".mjs", ".cjs", ".mts", ".cts",
    # React's JSX and TSX: a WebCrypto call in a component was "type not claimed"
    # (ZA-OPRAVYANE row 96), though the comment rules already knew both.
    ".jsx", ".tsx",
}

EXCLUDED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "vendor", "dist", "build", ".tox", "target",
    # Test caches are generated, like the rest of this set. Counting them pads the
    # denominator with files no reader cares about, which weakens the one number
    # this scanner exists to state honestly.
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

CI_CONFIG_FILENAMES = {".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml"}

IAC_EXTENSIONS = {".tf", ".tfvars"}

# Where cryptographic choices are configured rather than written. A TLS or SSH
# hybrid group -- X25519MLKEM768, mlkem768x25519-sha256 -- is almost never a
# string in code; it is a line in nginx.conf or sshd_config. Scanning only source
# meant the whole RFC 10024 vocabulary could be deployed and stay invisible.
CONFIG_EXTENSIONS = {".conf", ".cnf", ".ini", ".toml", ".properties", ".cfg",
                     # HCL configures Vault and Terraform; JSON carries cipher-suite
                     # lists and algorithm names in service configuration.
                     ".hcl", ".json",
                     # A DNS zone file: its DNSKEY, DS and RRSIG records name the
                     # algorithm the zone is signed with by number (see dnssec.py).
                     ".zone"}

# The same files that carry no extension at all.
CONFIG_FILENAMES = {"sshd_config", "ssh_config", "ssl.conf", "krb5.conf",
                    # The JDK's own policy file: it names algorithms, and
                    # jdk.tls.disabledAlgorithms is where a Java estate records
                    # what it has switched off.
                    "java.security", "java.policy",
                    # Build files list the algorithm sources a tree compiles.
                    "Makefile", "makefile", "GNUmakefile", "CMakeLists.txt",
                    # SSH key inventories: the key type is named on every line.
                    "known_hosts", "authorized_keys",
                    # Container builds pass the algorithms as build arguments
                    # (`ARG SIG_ALG="mldsa65"`; oqs-demos keeps 17 such files), Kconfig
                    # selects a bootloader's signature type, and a Caddyfile is a TLS
                    # server's whole configuration (ZA-OPRAVYANE rows 79 and 52).
                    "Dockerfile", "Containerfile", "Kconfig", "Caddyfile"}

# The same names with a variant after them (Dockerfile-QUIC, Dockerfile.alpine,
# Kconfig.defconfig) or before them (nginx.Dockerfile).
CONFIG_FILENAME_PATTERN = re.compile(
    r"^(?:Dockerfile|Containerfile|Kconfig)[-.][\w.-]+$|^[\w.-]+\.(?:Dockerfile|Containerfile)$")

# Directories whose files are configuration without an extension: FreeRADIUS keeps its
# EAP-TLS settings in raddb/mods-available/eap (ZA-OPRAVYANE row 103), and Debian's nginx
# and Apache keep their sites as sites-available/default.
CONFIG_DIRECTORIES = {"mods-available", "mods-enabled", "sites-available", "sites-enabled"}

# (algorithm, description, compiled regex matched against a single source line)
# Test code, named rather than judged. Measured 2026-09-26: comparing this scanner
# against a calibrated classifier on certbot gave 42 disagreements and **33 sat in test
# code**. Neither reference corpus can settle whether a fixture is an asset -- qscan's
# recall benchmark and the cryben corpus of Näther & Hirsch are both 100% synthetic
# fixtures with no test/production distinction -- so there is no convention to follow
# and the scanner does not invent one.
#
# A fixture's RSA key is real RSA and stays in the inventory. Whether it belongs in a
# particular migration plan is the reader's call, and they can only make it if the
# document says which is which. Same answer as coverage: name it, do not drop it.
#
# ⚠️ The rule is path shape, which is a convention and not a fact. It is reported with
# the counts, so a number can be read together with what produced it.
TEST_PATH_RULE = ("a path component named test/tests/testing/spec/specs/fixtures/"
                  "testdata, or a file named test_*, conftest, *_test, *.test.*, "
                  "*Test, *Tests, *_spec, *.spec")
_TEST_DIRS = {"test", "tests", "testing", "spec", "specs", "fixtures", "testdata"}
_TEST_FILE = re.compile(r"^(?:test_|conftest$)|(?:_test|\.test|Test|Tests|_spec|\.spec)$")


def in_test_code(rel_path: str) -> bool:
    """Whether a path is test code by `TEST_PATH_RULE`. Declared, not guessed silently."""
    parts = rel_path.replace("\\", "/").split("/")
    # A directory is judged by the same shape as a file, so .NET's `App.Tests/` and
    # Go's `pkg/testdata/` both land, and `src/latest/` does not.
    if any(part.lower() in _TEST_DIRS or _TEST_FILE.search(part) for part in parts[:-1]):
        return True
    name = parts[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return bool(_TEST_FILE.search(stem))


# Description of the rule for "kyber" with no identifier around it.
EXPERIMENTAL_SSH_MLDSA = ("OpenSSH 10.4 experimental ML-DSA-44-Ed25519 key type "
                          "(@openssh.com), not the one 10.6 enabled")
KYBER_BY_NAME_ONLY = "Kyber named without an identifier (round-3 Kyber, or an old name for ML-KEM)"

ALGORITHM_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("RSA", "RSA usage", re.compile(
        r"Crypto\.PublicKey\.RSA|Crypto\.PublicKey\s+import\s+RSA|"
        r"hazmat\.primitives\.asymmetric\.rsa|crypto/rsa|"
        # The same library imported the way Python actually writes it. The dotted
        # form above only reaches `asymmetric.rsa`; the common import is
        # `from ... asymmetric import rsa`, with the module name after a space
        # and often in a comma list. Measured on certbot: 5 lines used the
        # import form and 6 called the module, and every one of them was
        # invisible to this rule.
        r"asymmetric\s+import\s+[^\n#]*\brsa\b|"
        r"\brsa\.generate_private_key\b|"
        # Where the algorithm is actually used. Measured against Cryben: RSA
        # scored 0 of 11 on the exact line, because only the import was read.
        # Go's standard library, and the x509 helpers named after PKCS#1.
        r"\brsa\.(?:GenerateKey|GenerateMultiPrimeKey|EncryptOAEP|DecryptOAEP|"
        r"EncryptPKCS1v15|DecryptPKCS1v15|SignPSS|VerifyPSS|SignPKCS1v15|VerifyPKCS1v15)\b|"
        r"\bx509\.(?:Parse|Marshal)PKCS1(?:Private|Public)Key\b|"
        # Ruby, Java, Node, Rust, PKCS#11.
        r"OpenSSL::PKey::RSA\b|"
        r"\w*withRSA(?:andMGF1)?\b|Cipher\.getInstance\(\s*[\"']RSA[/\"']|"
        r"\bgenerateKeyPair(?:Sync)?\(\s*[\"']rsa(?:-pss)?[\"']|"
        # Node's RSA-only calls (doc/api/crypto.md) and node-forge's rsa namespace
        # (lib/rsa.js: forge.pki.rsa), ZA-OPRAVYANE row 69.
        r"\bcrypto\.(?:publicEncrypt|privateDecrypt|privateEncrypt|publicDecrypt)\b|"
        r"\bforge\.pki\.rsa\b|\bpki\.rsa\.|"
        r"\bcreate(?:Sign|Verify)\(\s*[\"']RSA[-\w]*[\"']|"
        r"\bRsaPrivateKey\b|\bRsaPublicKey\b|"
        # josepy's RSA key classes, and the signature OIDs of Python's `cryptography`.
        # certbot loads its account keys as `jose.JWKRSA.load(...)` in 19 files and none
        # was a finding.
        r"\bJWKRSA\b|\bComparableRSAKey\b|\bRSA_WITH_(?:MD5|SHA)\w*|"
        # pycryptodome's RSA schemes (Crypto.Signature.pkcs1_15/pss/PKCS1_v1_5,
        # Crypto.Cipher.PKCS1_OAEP/PKCS1_v1_5; also packaged as Cryptodome) and
        # python-rsa's newkeys (rsa/key.py), ZA-OPRAVYANE row 71.
        r"Crypto(?:dome)?\.(?:Signature|Cipher)\s+import\s+[^\n#]*\b(?:pkcs1_15|pss|PKCS1_OAEP|PKCS1_v1_5)\b|"
        r"Crypto(?:dome)?\.(?:Signature\.(?:pkcs1_15|pss)|Cipher\.PKCS1_OAEP|(?:Signature|Cipher)\.PKCS1_v1_5)\b|"
        r"\bpkcs1_15\.new\b|\bPKCS1_OAEP\.new\b|\brsa\.newkeys\b|"
        r"\bCKM_RSA_\w+|"
        # The names protocols and APIs use for the key type itself. OpenSSH's default
        # algorithm list, sshd_config, Vault's key types and AWS key specs name RSA
        # this way and nothing else here reached them: every other family on those
        # lines was reported and RSA was not.
        r"(?<![A-Za-z])ssh-rsa(?![A-Za-z])|(?<![A-Za-z])rsa-sha2-(?:256|512)(?![0-9])|"
        r"(?<![A-Za-z])rsa[-_](?:1024|2048|3072|4096|7680|8192|15360)(?![0-9])|"
        r"\bRSA_(?:1024|2048|3072|4096|8192)\b|"
        # .NET / PowerShell factory: RSA.Create() and [System.Security.Cryptography.RSA]::Create()
        r"\bRSA\]?(?:::|\.)Create\s*\(|"
        # OpenSSL's low-level accessors, which a C tree uses far more than the
        # constructors: RSA_get0_key, RSA_set0_crt_params, EVP_PKEY_get1_RSA.
        r"\bRSA_(?:get|set)[01]_\w+|\bEVP_PKEY_get[01]_RSA\b|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']|openssl\s+genrsa|-newkey\s+rsa|"
        # C / OpenSSL: the library's own API, which is what a C tree actually contains.
        r"\bRSA_new\b|\bRSA_generate_key\w*|\bRSA_public_encrypt\b|\bRSA_private_decrypt\b|"
        # The signature pair and RSA without padding -- the raw oracle the 2026 forgery
        # needs (ePrint 2026/2131). 0.25 gave these a role, but a role is put only on a
        # finding, and none of the four was one: a line of its own was invisible.
        r"\bRSA_private_encrypt\b|\bRSA_public_decrypt\b|\bRSA_padding_add_none\b|\bRSA_NO_PADDING\b|"
        # The signing calls themselves, which a secure-boot verifier is made of: one
        # RSA_verify against a key fused at manufacture scanned as nothing (ZA-OPRAVYANE
        # row 34, 22.10.2026). Names from OpenSSL's include/openssl/rsa.h.
        r"\bRSA_(?:sign|verify)(?:_ASN1_OCTET_STRING)?\b|\bRSA_verify_PKCS1_PSS(?:_mgf1)?\b|"
        r"\bRSA_padding_(?:add|check)_(?:PKCS1_PSS(?:_mgf1)?|PKCS1_type_1|X931)\b|\bRSA_PKCS1_PSS_PADDING\b|"
        r"\bEVP_PKEY_RSA\b|\bEVP_RSA_gen\b|\bPEM_read_\w*RSA\w*|\bd2i_RSA\w*|"
        # The EVP control calls and the size accessor (include/openssl/rsa.h), and the
        # header itself (ZA-OPRAVYANE row 65).
        r"\bEVP_PKEY_CTX_set_rsa_\w+|\bRSA_size\s*\(|[<\"]openssl/rsa\.h[>\"]|"
        # .NET / PowerShell: a Windows estate keeps its certificate handling here.
        r"\bRSACryptoServiceProvider\b|\bRSACng\b|\bRSAOpenSsl\b|\bRSA\.Create\b|"
        r"\bRSACertificateExtensions\b|\bGetRSAPublicKey\b|\bGetRSAPrivateKey\b|"
        r"\bCngAlgorithm\.Rsa\b|"                       # CngAlgorithm.cs, row 70
        r"-KeyAlgorithm\s+[\"']?RSA",
        re.IGNORECASE,
    )),
    ("DSA", "DSA usage", re.compile(
        r"Crypto\.PublicKey\s+import\s+DSA|"
        r"hazmat\.primitives\.asymmetric\.dsa|crypto/dsa|"
        r"asymmetric\s+import\s+[^\n#]*\bdsa\b|\bdsa\.generate_private_key\b|"
        # The call sites, as for RSA above. "withDSA" cannot reach withECDSA:
        # that text has no "withDSA" in it.
        # Not ML-DSA.Sign() or SLH-DSA.Sign(): those are the post-quantum
        # replacements, and naming them DSA is the worst way to be wrong.
        # Nor ml_dsa.sign / slh_dsa.sign, the same names with an underscore (row 78).
        r"(?<![A-Za-z_-])dsa\.(?:GenerateKey|GenerateParameters|Sign|Verify)\b|"
        r"OpenSSL::PKey::DSA\b|\w*withDSA\b|\bDsa::generate\b|\bDSA\.generate\b|"
        r"\bCKM_DSA_\w+|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']|openssl\s+dsaparam|"
        r"\bDSA_new\b|\bDSA_generate_key\w*|\bEVP_PKEY_DSA\b|"
        r"\bgenerateKeyPair(?:Sync)?\(\s*[\"']dsa[\"']|"     # Node, row 69
        r"\bDSSKey\b|"                                    # paramiko dsskey.py, row 71
        # include/openssl/dsa.h: the signing calls and the header (row 65).
        r"\bDSA_(?:do_)?(?:sign|verify)\b|[<\"]openssl/dsa\.h[>\"]|"
        r"\bDSACryptoServiceProvider\b|\bDSACng\b|\bDSA\.Create\b|"     # DSA.cs, row 70
        r"(?<![A-Za-z])ssh-dss(?![A-Za-z])",
        re.IGNORECASE,
    )),
    # DNSSEC algorithm mnemonics (IANA DNSSEC Algorithm Numbers), as BIND's
    # dnssec-policy and dnssec-keygen -a, Knot's `algorithm:` and PowerDNS write them.
    # Before "ECDSA usage", so the curve the mnemonic names is kept (DNSSEC_CURVES).
    # ED25519, ED448 and MLDSA44 are already reached by their own rules below, and so is
    # PowerDNS's `ecdsa256`/`ecdsa384` -- by "ECDSA usage", without a curve: the same
    # word is an ordinary variable name in OpenSSH, where it means no DNSSEC algorithm.
    ("ECDSA", "ECDSA P-256 named by a DNSSEC algorithm (13, ECDSAP256SHA256)", re.compile(
        r"(?<![A-Za-z0-9])ECDSAP256SHA256(?![A-Za-z0-9])", re.IGNORECASE)),
    ("ECDSA", "ECDSA P-384 named by a DNSSEC algorithm (14, ECDSAP384SHA384)", re.compile(
        r"(?<![A-Za-z0-9])ECDSAP384SHA384(?![A-Za-z0-9])", re.IGNORECASE)),
    ("RSA", "RSA named by a DNSSEC algorithm (1, 5, 7, 8 or 10)", re.compile(
        r"(?<![A-Za-z0-9])(?:RSAMD5|RSASHA1(?:-NSEC3-SHA1)?|RSASHA256|RSASHA512)(?![A-Za-z0-9])",
        re.IGNORECASE)),
    ("DSA", "DSA named by a DNSSEC algorithm (6, DSA-NSEC3-SHA1)", re.compile(
        r"(?<![A-Za-z0-9])DSA-NSEC3-SHA1(?![A-Za-z0-9])", re.IGNORECASE)),
    ("ECDSA", "ECDSA usage", re.compile(
        r"crypto/ecdsa|(?<![A-Za-z])ECDSA|"
        # C / OpenSSL.
        r"\bECDSA_do_sign\b|\bECDSA_sign\b|\bECDSA_verify\b|\bECDSA_SIG_\w+|"
        r"\w*withECDSA\b|"
        # .NET spells it ECDsa, so \bECDSA\b does not reach ECDsaCng or
        # ECDsaCertificateExtensions -- the exact call our own Windows agent makes.
        r"\bECDsaCng\b|\bECDsaOpenSsl\b|\bECDsa\.Create\b|"
        r"\bECDsaCertificateExtensions\b|\bGetECDsaPublicKey\b|\bGetECDsaPrivateKey\b",
        re.IGNORECASE,
    )),
    ("EC", "Elliptic curve usage", re.compile(
        r"hazmat\.primitives\.asymmetric\.ec\b|crypto/elliptic|"
        # The same library imported the way Python actually writes it. The dotted
        # form above only reaches `asymmetric.ec`; the common import is
        # `from ... asymmetric import ec`, with the module name after a space
        # and often in a comma list. Measured on certbot: 10 lines used the
        # import form and 16 called the module, and every one of them was
        # invisible to this rule.
        r"asymmetric\s+import\s+[^\n#]*\bec\b|"
        r"\bec\.(?:generate_private_key|derive_private_key|SECP\w+|SECT\w+)\b|"
        # The curve as an identifier: RustCrypto's p256/p384/p521 crates (`p256::SecretKey`)
        # and @noble/curves' NIST exports (src/nist.ts: `export const p256`), row 75.
        r"\bp(?:224|256|384|521)::|@noble/curves/(?:nist|p256|p384|p521)\b|"
        r"\bimport\s*\{[^}]*\bp(?:256|384|521)\b[^}]*\}\s*from\s*[\"']@noble/curves|"
        # pycryptodome's ECC module (Crypto/PublicKey/ECC.py), row 71.
        r"Crypto(?:dome)?\.PublicKey\s+import\s+[^\n#]*\bECC\b|Crypto(?:dome)?\.PublicKey\.ECC\b|"
        r"\bECC\.(?:generate|import_key|construct)\b|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']EC[\"']|openssl\s+ecparam|"
        r"\bEC_KEY_new\w*|\bEC_KEY_generate_key\b|\bEC_GROUP_new\w*|\bEVP_PKEY_EC\b|\bEC_POINT_\w+|"
        r"OpenSSL::PKey::EC\b|\bgenerateKeyPair(?:Sync)?\(\s*[\"']ec[\"']|"
        r"\bx509\.(?:Parse|Marshal)ECPrivateKey\b|"
        # Go names its NIST curves in crypto/elliptic; the curve is the algorithm.
        r"\belliptic\.P(?:224|256|384|521)\b|\becdh\.P(?:256|384|521)\b|"
        r"\bECCurve\.|\bECParameters\b|"
        # IKE proposal syntax: ecp384 is NIST P-384 and lives in swanctl.conf,
        # where a scanner reading only library calls never meets it.
        r"(?<![A-Za-z])ecp(?:192|224|256|384|521)(?![0-9])|"
        # The same NIST curve under the name TLS configuration actually writes.
        # `ec.SECP256R1` is seen, but `prime256v1` in an nginx `ssl_ecdh_curve`
        # or an OpenSSL `Groups =` line is a different spelling of P-256 and was
        # invisible -- found missing against the Olewinski et al. (ARES 2026)
        # ground truth. `secp256r1` also reaches Java `ECGenParameterSpec`. The
        # explicit r1/v1 suffix is what keeps secp256k1 routed to ECDSA below.
        r"(?<![A-Za-z])(?:prime(?:192|256)v1|secp(?:192|224|256|384|521)r1)(?![0-9])|"
        # The bare names OpenSSH and Java write for the same curves.
        r"(?<![A-Za-z])nistp(?:256|384|521)(?![0-9])",
        re.IGNORECASE,
    )),
    ("DH", "Diffie-Hellman usage", re.compile(
        # Not the tail of ECDiffieHellman, which is elliptic-curve and handled there.
        r"hazmat\.primitives\.asymmetric\.dh\b|crypto/dh\b|(?<!EC)Diffie[- ]?Hellman|"
        r"asymmetric\s+import\s+[^\n#]*\bdh\b|\bdh\.generate_parameters\b|"
        r"\bDH_new\b|\bDH_generate_key\b|\bEVP_PKEY_DH\b|"
        r"\bgenerateKeyPair(?:Sync)?\(\s*[\"']dh[\"']|"      # Node, row 69
        # include/openssl/dh.h and the RFC 7919 group NIDs (crypto/objects/objects.txt).
        r"\bDH_compute_key(?:_padded)?\b|\bNID_ffdhe\d+\b|[<\"]openssl/dh\.h[>\"]|"
        # Ruby, the Rust openssl crate, and BouncyCastle -- the vocabulary a rival
        # reads and this scanner did not. Fix #9 of the September comparison.
        r"\bdh\.compute_key\b|\bDh::generate_params\b|\bDh::from_params\b|"
        r"\bDHBasicAgreement\b|\bDHKeyPairGenerator\b|\bDHParametersGenerator\b|"
        # IKE modp groups: modp2048 is group 14, and Shor breaks it like any
        # finite-field Diffie-Hellman.
        r"(?<![A-Za-z])modp(?:768|1024|1536|2048|3072|4096|6144|8192)(?![0-9])",   # 768: row 141
        re.IGNORECASE,
    )),
    ("MD5", "MD5 usage", re.compile(
        r"hashlib\.md5|crypto/md5|MessageDigest\.getInstance\(\s*[\"']MD5[\"']|"
        r"createHash\(\s*[\"']md5[\"']|openssl\s+dgst\s+-md5|"
        r"\bMD5_Init\b|\bMD5_Update\b|\bEVP_md5\b|"
        r"\bMD5CryptoServiceProvider\b|\bMD5\.Create\b|"
        # The idioms the comparison found in the wild: pyca objects, hashlib.new,
        # the BSD-style C calls and headers, and Go used without its import line.
        r"hashes\.MD5\s*\(|hashlib\.new\(\s*[\"']md5[\"']|"
        r"\bMD5(?:Init|Update|Final|Transform)\b|<md5\.h>|\bmd5\.(?:New|Sum)\b|"
        # OpenSSL's one-shot MD5() (include/openssl/md5.h) and its header (row 65).
        r"\bMD5\(|[<\"]openssl/md5\.h[>\"]|"
        # .NET 5+ one-shots and the hash name a signature call takes (MD5.cs,
        # HashAlgorithmName.cs; row 70).
        r"\bMD5\.HashData(?:Async)?\b|\bHashAlgorithmName\.MD5\b|"
        r"\b[Mm]d5::|"                                   # Rust md-5 / md5 crates, row 75
        # pycryptodome (Crypto/Hash/MD5.py), row 71.
        r"Crypto(?:dome)?\.Hash\s+import\s+[^\n#]*\bMD5\b|Crypto(?:dome)?\.Hash\.MD5\b|\bMD5\.new\b",
        re.IGNORECASE,
    )),
    ("SHA1", "SHA-1 usage", re.compile(
        r"hashlib\.sha1|crypto/sha1|MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']|"
        r"createHash\(\s*[\"']sha1[\"']|openssl\s+dgst\s+-sha1|"
        r"\bSHA1_Init\b|\bSHA1_Update\b|\bEVP_sha1\b|"
        r"\bSHA1CryptoServiceProvider\b|\bSHA1Managed\b|\bSHA1\.Create\b|"
        r"hashes\.SHA1\s*\(|hashlib\.new\(\s*[\"']sha-?1[\"']|"
        r"\bSHA1(?:Init|Update|Final|Transform)\b|<sha1\.h>|\bsha1\.(?:New|Sum)\b|"
        # OpenSSL's one-shot SHA1() (include/openssl/sha.h), row 65. Not the header:
        # sha.h declares SHA-256 and SHA-512 as well.
        r"\bSHA1\(|"
        r"\bSHA1\.HashData(?:Async)?\b|\bHashAlgorithmName\.SHA1\b|"     # .NET, row 70
        r"\b[Ss]ha1::|"                                  # RustCrypto sha1 (src/lib.rs), row 75
        # pycryptodome (Crypto/Hash/SHA1.py, and SHA.py, its old alias), row 71.
        r"Crypto(?:dome)?\.Hash\s+import\s+[^\n#]*\bSHA1?\b|Crypto(?:dome)?\.Hash\.SHA1?\b|\bSHA1\.new\b",
        re.IGNORECASE,
    )),
    # SHA-224, SHA3-224 and AES in ECB mode, which NIST SP 800-131A Rev. 3's initial public
    # draft proposes to retire (ZA-OPRAVYANE row 104): none was seen at all. The calls are
    # the libraries' own (pyca hashes.SHA224/SHA3_224 and modes.ECB, hashlib, JCA names,
    # Node createHash, OpenSSL EVP_sha224/EVP_sha3_224/EVP_aes_*_ecb, Go sha256.Sum224,
    # PyCryptodome AES.MODE_ECB). ECB only next to AES: `modes.ECB()` under TripleDES is 3DES.
    ("SHA224", "SHA-224 usage", re.compile(
        r"hashes\.SHA224\s*\(|hashlib\.sha224\b|hashlib\.new\(\s*[\"']sha224[\"']|"
        r"MessageDigest\.getInstance\(\s*[\"']SHA-?224[\"']|createHash\(\s*[\"']sha224[\"']|"
        r"\bEVP_sha224\b|\bsha256\.(?:New224|Sum224)\b", re.IGNORECASE)),
    ("SHA3-224", "SHA3-224 usage", re.compile(
        r"hashes\.SHA3_224\s*\(|hashlib\.sha3_224\b|hashlib\.new\(\s*[\"']sha3[-_]224[\"']|"
        r"MessageDigest\.getInstance\(\s*[\"']SHA3-224[\"']|createHash\(\s*[\"']sha3-224[\"']|"
        r"\bEVP_sha3_224\b|\bsha3\.(?:New224|Sum224)\b", re.IGNORECASE)),
    ("AES-ECB", "AES in ECB mode", re.compile(
        r"algorithms\.AES\w*\([^\n]*modes\.ECB\s*\(|getInstance\(\s*[\"']AES(?:_\d+)?/ECB|"
        r"\bAES\.MODE_ECB\b|[\"']aes-?(?:128|192|256)-ecb[\"']|\bEVP_aes_(?:128|192|256)_ecb\b",
        re.IGNORECASE)),
    ("RC4", "RC4 usage", re.compile(
        # Not a release suffix: "1.0.0-rc4" is a version. A cipher suite such as
        # "EXP-RC4-MD5" also has a dash before it, so only a digit then a dash or dot
        # marks a version (an earlier, wider exclusion dropped 13 OpenSSL suites).
        # `ARC4` is PyCryptodome's spelling and has no word boundary before RC4,
        # so `\bRC4\b` never matched the one call an application actually writes.
        # A test pinned `cipher = ARC4.new(key)  # RC4` as found, and it was --
        # by reading the comment. Labelling evidence by position took the comment
        # away and left the gap visible, which is what it was there to hide.
        r"crypto/rc4|(?<!\d[-.])\bRC4\b|\bARC4\b|\bRC4_set_key\b|\bEVP_rc4\b",
        re.IGNORECASE,
    )),
    # JOSE / JWT. The algorithm is named nowhere else: a service that signs its
    # tokens with RS256 has RSA in it, and the only trace is a four-character
    # string in a quoted argument. Measured: 35 such lines in Vault, 1 in certbot,
    # 9 in the qscan corpus. Quoted or as a library constant, so that the word in
    # a sentence stays what it is -- a word in a sentence.
    # Library API vocabularies, from the corpus of 2026-09-28: Jev labels over 140 public
    # repositories compared with 0.26 (the 45 held out for measurement were not read). Each
    # branch is a whole vocabulary, not the one member the labeller happened to hit.
    # Case-SENSITIVE, unlike "RSA usage": `RSAKey` and `DSAParams` are types, `rsaKey` and
    # `dsaparams` are variable names -- a name without an operation, like `ssl_dhparams`.
    ("RSA", "RSA named by a library API", re.compile(
        r"\bRSA(?:Public|Private|PrivateCrt)?KeySpec\b|\bRSAKey(?:Provider)?\b|"   # JCA, auth0
        r"\bAlgorithm\.RSA(?:256|384|512)\b|"                                       # auth0 java-jwt
        r"[\"'](?:RSASSA-PKCS1-v1_5|RSASSA-PSS|RSA-PSS)[\"']|"                      # WebCrypto, JOSE
        r"\bmbedtls_rsa_\w+|\bMBEDTLS_PK_RSA\w*|\bMBEDTLS_RSA_\w+|"                 # Mbed TLS
        r"\bOPENSSL_KEYTYPE_RSA\b|\bTPM_ALG_RSA\w*|\bKeyType\.RSA\b|"             # enum families
        r"\*?\brsa\.(?:PublicKey|PrivateKey)\b|\bParseRSA(?:Private|Public)KeyFromPEM\b|"  # Go
        r"\bRSA(?:Signature|Encryption)Padding\.\w+|"                               # .NET
        # ring / aws-lc-rs (src/rsa/keypair.rs, verification.rs) and rustls's
        # SignatureScheme (src/crypto/enums.rs), ZA-OPRAVYANE row 75.
        r"\bRsaKeyPair\b|\bRSA_PKCS1_\w+|\bRSA_PSS_\w+|"
        # A JWK names its key type in `kty`; the value in any other field is a label.
        r"\bkty[\"']?\s*(?::|==|!=|=)\s*[\"']RSA[\"']|[\"']kty[\"']\)\s*(?:==|!=)\s*[\"']RSA[\"']",
    )),
    # The JCA's elliptic-curve types (java.security.spec, java.security.interfaces). Where
    # the curve comes from a constant or a resource, they are the only trace of EC key
    # generation (ZA-OPRAVYANE row 86, identity-samples). Case-sensitive, as above.
    ("EC", "EC named by a JCA type", re.compile(
        r"\bEC(?:GenParameterSpec|ParameterSpec|PublicKeySpec|PrivateKeySpec|PublicKey|"
        r"PrivateKey|Point)\b",
    )),
    ("DSA", "DSA named by a library API", re.compile(
        r"\bDSA(?:Public|Private)Key(?:Spec)?\b|\bDSAParams\b|"                     # JCA
        r"\bDsa(?:KeyPair|Parameters)Generator\b|"                                  # Bouncy Castle
        r"\bOPENSSL_KEYTYPE_DSA\b|\bx509\.DSAWithSHA\d+\b|\bKeyType\.DSA\b",
    )),
    # wolfCrypt, wolfSSL's crypto library: its classical API names the family only inside
    # a wc_ identifier, and a whole wolfSSL program scanned as empty (ZA-OPRAVYANE row 72).
    # Every prefix checked against wolfssl/wolfcrypt/{rsa,ecc,dh,md5,sha,hash,des3,falcon}.h
    # in the corpus copy. Case-sensitive: wolfCrypt writes them exactly so.
    ("RSA", "RSA named by the wolfCrypt API", re.compile(
        r"\bwc_\w*Rsa\w*|\bWC_RSA_\w+|\bRsaKey\b|[<\"]wolfssl/wolfcrypt/rsa\.h[>\"]")),
    ("ECDSA", "ECDSA named by the wolfCrypt API", re.compile(r"\bwc_ecc_(?:sign|verify)\w*")),
    ("ECDH", "ECDH named by the wolfCrypt API", re.compile(r"\bwc_ecc_shared_secret\w*")),
    ("EC", "EC named by the wolfCrypt API", re.compile(
        r"\bwc_ecc_\w+|\bwc_Ecc\w+|\becc_key\b|[<\"]wolfssl/wolfcrypt/ecc\.h[>\"]")),
    ("DH", "DH named by the wolfCrypt API", re.compile(
        r"\bwc_(?:Dh|InitDhKey|FreeDhKey)\w*|\bDhKey\b|[<\"]wolfssl/wolfcrypt/dh\.h[>\"]")),
    ("MD5", "MD5 named by the wolfCrypt API", re.compile(
        r"\bwc_(?:InitMd5|Md5)\w*|[<\"]wolfssl/wolfcrypt/md5\.h[>\"]")),
    # SHA-1 only: wc_Sha256*, wc_Sha3_* and wc_Shake* are other functions.
    ("SHA1", "SHA-1 named by the wolfCrypt API", re.compile(
        r"\bwc_(?:InitSha(?:_ex)?|Sha(?:Copy|Final(?:Raw)?|Free|GetFlags|GetHash|SetFlags|"
        r"SizeSet|Transform|Update|Hash))\b|[<\"]wolfssl/wolfcrypt/sha\.h[>\"]")),
    ("3DES", "3DES named by the wolfCrypt API", re.compile(
        r"\bwc_Des3_\w+|[<\"]wolfssl/wolfcrypt/des3\.h[>\"]")),
    ("DES", "DES named by the wolfCrypt API", re.compile(r"\bwc_Des_\w+")),
    # strongSwan's credential API names RSA and the IKE DH groups by constant: 87 of 109
    # C files using them had no RSA finding, while KEY_ECDSA was seen in all 68 (ZA-OPRAVYANE
    # row 80, swarm C). From credentials/keys/{public_key,private_key}.h and
    # crypto/key_exchange.h in strongSwan; the plugins' own prefixes (gmp_rsa_*,
    # openssl_rsa_*, botan_rsa_*, wolfssl_rsa_*) from src/libstrongswan/plugins. OpenSSH's
    # sshkey.h has the same KEY_RSA, so the description names neither project.
    ("RSA", "RSA named by a key-type or scheme constant (KEY_RSA, SIGN_RSA_*, ...)", re.compile(
        r"\bKEY_RSA\b|\bSIGN_RSA_\w+|\bENCRYPT_RSA_\w+|\b(?:gmp|openssl|botan|wolfssl)_rsa_\w+")),
    ("DH", "DH named by an IKE MODP group constant (strongSwan)", re.compile(
        r"\bMODP_(?:\d+_(?:BIT|\d+)|CUSTOM)\b")),
    # Mbed TLS beyond mbedtls_rsa_/ecdsa/ecdh, and its PSA key types and algorithms
    # (ZA-OPRAVYANE row 73). Checked against mbedtls-3.6 include/mbedtls/{dhm,ecp,md5,sha1,
    # des,md}.h and include/psa/crypto_values.h (read 23.10.2026).
    ("DH", "DH named by the Mbed TLS API", re.compile(
        r"\bmbedtls_dhm_\w+|\bMBEDTLS_DHM_\w+|\bPSA_ALG_FFDH\b|\bPSA_KEY_TYPE_DH_\w+")),
    ("RSA", "RSA named by the PSA Crypto API", re.compile(
        r"\bPSA_KEY_TYPE_RSA_\w+|\bPSA_ALG_RSA_\w+")),
    ("EC", "EC named by the Mbed TLS API", re.compile(
        r"\bmbedtls_ecp_\w+|\bMBEDTLS_ECP_DP_\w+|\bPSA_KEY_TYPE_ECC_\w+")),
    ("MD5", "MD5 named by the Mbed TLS API", re.compile(
        r"\bmbedtls_md5\w*|\bMBEDTLS_MD_MD5\b|\bPSA_ALG_MD5\b")),
    ("SHA1", "SHA-1 named by the Mbed TLS API", re.compile(
        r"\bmbedtls_sha1\w*|\bMBEDTLS_MD_SHA1\b|\bPSA_ALG_SHA_1\b")),
    ("3DES", "3DES named by the Mbed TLS API", re.compile(r"\bmbedtls_des3_\w+")),
    ("DES", "DES named by the Mbed TLS API", re.compile(r"\bmbedtls_des_\w+")),
    # Bouncy Castle's lightweight API names the algorithm in a class name glued to
    # Engine/Digest/Signer/KeyPairGenerator (ZA-OPRAVYANE row 74). Each class checked in
    # bc-java core/src/main/java/org/bouncycastle (read 23.10.2026). DESedeEngine is already
    # 3DES by its own rule.
    ("RSA", "RSA named by the Bouncy Castle API", re.compile(
        r"\bRSA(?:Blinded)?Engine\b|\bRSAKeyPairGenerator\b")),
    ("DES", "DES named by the Bouncy Castle API", re.compile(r"\bDESEngine\b")),
    ("RC4", "RC4 named by the Bouncy Castle API", re.compile(r"\bRC4Engine\b")),
    ("MD5", "MD5 named by the Bouncy Castle API", re.compile(r"\bMD5Digest\b")),
    ("SHA1", "SHA-1 named by the Bouncy Castle API", re.compile(r"\bSHA1Digest\b")),
    ("Falcon", "Falcon named by the Bouncy Castle API", re.compile(
        r"\bFalcon(?:Signer|KeyPairGenerator)\b")),
    ("RSA", "RSA named as a JOSE/JWT algorithm", re.compile(
        r"[\"'](?:RS|PS)(?:256|384|512)[\"']|"
        r"\bSigningMethod(?:RS|PS)(?:256|384|512)\b|\bAlgorithm::(?:RS|PS)(?:256|384|512)\b|"
        # Reached as an attribute rather than a string: `jose.RS256`, `Algorithms.PS512`.
        # certbot's own default (`alg: jose.JWASignature = jose.RS256`) in acme/client.py
        # and acme/challenges.py was missed because the rule required quotes. qscan's
        # recall corpus labels this shape under `aliased`, so an external reference
        # counts it -- and `RS256` is not an English word, which is why a bare token is
        # safe here and a bare `RSA` is not.
        r"(?<![A-Za-z0-9_])(?:RS|PS)(?:256|384|512)(?![0-9A-Za-z_])|"
        r"[\"']?RSA-OAEP(?:-(?:256|384|512))?[\"']?|[\"']RSA1_5[\"']",
    )),
    # A configuration value that names the algorithm is an occurrence: qscan's recall
    # corpus has a whole `config` difficulty class for exactly this
    # (`diffie-hellman-group14-sha256 kex`). certbot sets its project-wide default in
    # one assignment -- `rsa_key_size=2048` in constants.py -- and exposes
    # `--rsa-key-size` on the CLI; neither was a finding, and "this tool defaults to
    # RSA 2048" is the most actionable thing an inventory can say about it.
    ("RSA", "RSA key size named as a setting", re.compile(
        r"\brsa[_-]?(?:key[_-]?(?:size|bits|length)|modulus[_-]?(?:size|bits|length))\b",
        re.IGNORECASE,
    )),
    ("ECDSA", "ECDSA named as a JOSE/JWT algorithm", re.compile(
        r"[\"']ES(?:256|384|512)K?[\"']|"
        r"\bSigningMethodES(?:256|384|512)\b|\bAlgorithm::ES(?:256|384|512)\b|"
        # Same shape, same reason: `jose.ES384` is how certbot's own tests reach it.
        r"(?<![A-Za-z0-9_])ES(?:256|384|512)K?(?![0-9A-Za-z_])",
    )),
    ("3DES", "3DES (triple DES) usage", re.compile(
        # No word boundaries: the real spellings are glued into identifiers
        # (OPT_3DES_WRAP, OIDEncryptionAlgorithmDESEDE3CBC, NewTripleDESCipher).
        r"3DES|DES[-_]?EDE3?|TripleDES|EVP_des_ede3\w*|"
        # include/openssl/des.h: three-key DES in ECB, by its own name (row 65).
        r"\bDES_ecb3_encrypt\b|"
        # pycryptodome (Crypto/Cipher/DES3.py), row 71.
        r"Crypto(?:dome)?\.Cipher\s+import\s+[^\n#]*\bDES3\b|Crypto(?:dome)?\.Cipher\.DES3\b|\bDES3\.new\b",
        re.IGNORECASE,
    )),
    ("DES", "DES usage", re.compile(
        # Single DES only: the triple-DES spellings have their own rule above, and
        # the EVP_des_ede* family (two- and three-key) must not fall in here.
        r"crypto/des\b|\bDES_set_key\w*|\bDES_ecb_encrypt\b|"
        r"\bEVP_des_(?!ede)\w+|\bDESCryptoServiceProvider\b|\bdes\.NewCipher\b|"
        r"\bDES\.Create\b|"                             # .NET DES.cs, row 70
        r"Crypto(?:dome)?\.Cipher\s+import\s+[^\n#]*\bDES\b|Crypto(?:dome)?\.Cipher\.DES\b|"   # row 71
        # Node passes the cipher name to OpenSSL: single DES in one of its modes, not
        # des-ede3-* (row 69).
        r"\bcreate(?:Cipheriv|Decipheriv|Cipher|Decipher)\(\s*[\"']des(?:-(?:cbc|ecb|cfb|cfb1|cfb8|ofb))?[\"']",
        re.IGNORECASE,
    )),
    # Blockchain / wallet signing. These map onto the same classical primitives -- a
    # secp256k1 signature is ECDSA, and Shor breaks it like any other elliptic curve.
    ("ECDSA", "secp256k1 (ECDSA) usage", re.compile(
        r"secp256k1|\bbtcec\b|bitcoinjs-lib|\bECPair\b|"
        r"\becrecover\s*\(|ECDSA\.recover|\bethers\b|\bweb3\b|"
        # Whole method names: `personal_signature` is a form field, not the JSON-RPC
        # call (ZA-OPRAVYANE row 78).
        r"(?<![A-Za-z0-9])(?:eth_sign\w*|personal_sign)(?![A-Za-z0-9])|signTypedData",
        re.IGNORECASE,
    )),
    # RFC 8784. Quantum resistance with no post-quantum algorithm to find, so it
    # is matched by the configuration directives that turn it on rather than by a
    # scheme name. Bare "ppk" is deliberately not enough: .ppk is also PuTTY's key
    # format, and a key file is not a postquantum preshared key.
    ("PPK", "RFC 8784 postquantum preshared key", re.compile(
        r"(?<![A-Za-z])ppk_(?:id|required|secret|dynamic)(?![A-Za-z])|"
        r"@ppk(?![A-Za-z])|"
        r"(?<![A-Za-z])ppk[ \t]+(?:manual|dynamic)(?![A-Za-z])|"
        r"RFC[ \t-]?8784",
        re.IGNORECASE,
    )),
    # X25519 is the classical half of every RFC 10024 TLS hybrid. Without it,
    # "X25519MLKEM768" reports the post-quantum half only, and the component Shor
    # actually breaks disappears from the inventory.
    ("X25519", "X25519 key agreement usage", re.compile(
        r"(?<![A-Za-z])x25519|(?<![A-Za-z])curve25519|"
        # NaCl/libsodium never name it: crypto_box is curve25519xsalsa20poly1305,
        # crypto_kx is x25519blake2b, crypto_scalarmult is curve25519 (their own
        # *_PRIMITIVE, include/sodium/*.h); PyNaCl's nacl.public is the same box
        # (ZA-OPRAVYANE row 67). Not crypto_scalarmult_ed25519 or _ristretto255.
        r"\b(?:sodium_)?crypto_box_(?:keypair|seed_keypair|easy|open_easy|detached|"
        r"open_detached|beforenm|afternm|easy_afternm|open_easy_afternm|detached_afternm|"
        r"open_detached_afternm|open_afternm|seal|seal_open|open)\b|\bcrypto_box\s*\(|"
        r"\b(?:sodium_)?crypto_kx_\w+|\b(?:sodium_)?crypto_scalarmult(?:_base)?\b|"
        r"\bnacl\.public\b", re.IGNORECASE,
    )),
    # Uppercase X448 is unambiguous. Lowercase x448 is not: Bitcoin Core lists
    # node service flags in hex -- "x1, x5, x9, x408, x448, xc08" -- and three of
    # those read as the curve. Lowercase therefore has to be attached to an
    # identifier (asymmetric.x448, ossl_x448, param.x448) rather than standing
    # alone in prose.
    ("X448", "X448 key agreement usage", re.compile(r"(?<![A-Za-z])X448(?![0-9])")),
    ("X448", "X448 key agreement usage", re.compile(
        # `::` closes the Rust crate path: `use x448::{PublicKey, Secret}` matched
        # neither alternative, because :: is not in [._/-] and not in [._].
        r"(?<=[._/-])x448(?![0-9])|(?<![A-Za-z])x448(?=[._]|::)",
    )),
    ("X448", "X448 key agreement usage", re.compile(
        r"\bX448(?:Agreement|KeyPairGenerator|PrivateKeyParameters|PublicKeyParameters)\b",
    )),
    # Three families the classifier table has always been able to explain and no
    # rule could ever find: a scanner that answers "yes, I know Ed448" and then
    # reports nothing in a tree carrying 315 mentions of it is hiding
    # cryptography, which is the same defect as inventing it. Counts measured
    # across OpenSSL, OpenSSH and certbot: ECDH 679, Ed448 315, EdDSA 65, and 23
    # ecdh-sha2-nistp lines in SSH configuration where no library call appears.
    ("ECDH", "ECDH key agreement usage", re.compile(
        # ECDHE, the ephemeral form, is the one that actually appears in a cipher
        # list: 1329 mentions across the three repositories against 679 bare ECDH.
        # Excluding it would have left the most common spelling of the thing
        # invisible while claiming the family was covered.
        r"(?<![A-Za-z])ECDHE?(?![A-Za-z])|\bECDH_compute_key\b|\bEVP_PKEY_ECDH\b|"
        r"\bec\.ECDH\b|(?<![A-Za-z])ecdh-sha2-nistp(?:256|384|521)|"
        # pycryptodome's Crypto.Protocol.DH takes ECC keys only -- NIST curves,
        # Curve25519, Curve448 (Crypto/Protocol/DH.py) -- so it is ECDH, not
        # finite-field DH (row 71).
        r"Crypto(?:dome)?\.Protocol\.DH\b|Crypto(?:dome)?\.Protocol\s+import\s+[^\n#]*\bDH\b|"
        # .NET's elliptic-curve Diffie-Hellman; it was filed under finite-field DH.
        r"\bECDiffieHellman(?:Cng|OpenSsl)?\b|"
        # Go's TLS curve IDs (crypto/tls/common.go): a key exchange group, as the TLS
        # group table files curvep256 (row 75).
        r"\btls\.CurveP(?:256|384|521)\b",
        re.IGNORECASE,
    )),
    # oqs-provider names its hybrids by prefix: p384_mlkem768, bp256_mlkem512,
    # p256_mldsa44, rsa3072_mldsa44 (ALGORITHMS.md, read 23.10.2026). The post-quantum half
    # was seen and the classical one was not, so `Groups = p384_mlkem768` read pqc_ready
    # (ZA-OPRAVYANE row 82). x25519_ and x448_ were already reached by their own rules.
    ("ECDH", "ECDH half of an oqs-provider hybrid key exchange", re.compile(
        r"(?<![A-Za-z0-9])b?p(?:256|384|512|521)_(?=e?frodo|bikel|hqc|mlkem|kyber)",
        re.IGNORECASE)),
    ("ECDSA", "ECDSA half of an oqs-provider composite signature", re.compile(
        r"(?<![A-Za-z0-9])p(?:256|384|521)_(?=mldsa|falcon|mayo|snova|mqom|OV_|sphincs|slhdsa)",
        re.IGNORECASE)),
    ("RSA", "RSA half of an oqs-provider composite signature", re.compile(
        r"(?<![A-Za-z0-9])rsa(?:2048|3072)_(?=mldsa|falcon|sphincs|slhdsa)", re.IGNORECASE)),
    ("Ed448", "Ed448 usage", re.compile(
        r"(?<![A-Za-z])Ed448(?![0-9])|asymmetric\s+import\s+[^\n#]*\bed448\b|"
        r"\bNID_ED448\b|\bEVP_PKEY_ED448\b|\bEd448(?:Signer|KeyPairGenerator)\b",
        re.IGNORECASE,
    )),
    ("EdDSA", "EdDSA usage", re.compile(
        r"(?<![A-Za-z])EdDSA(?![A-Za-z])|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']EdDSA[\"']",
        re.IGNORECASE,
    )),
    ("Ed25519", "Ed25519 usage", re.compile(
        # The name glued into an identifier as well as standing alone: ED25519_sign
        # (BoringSSL), EVP_PKEY_ED25519, NID_ED25519, wc_ed25519_*, Ed25519PrivateKey,
        # ed25519_dalek, Go's x509.PureEd25519 (ZA-OPRAVYANE row 66). `\b` refused all of them.
        r"(?<![A-Za-z])ed25519|\bPureEd25519\b|tweetnacl|\bnacl\.sign\b|@solana/web3\.js|solana_program::|"
        r"sodium_crypto_sign|\bEd25519(?:Signer|KeyPairGenerator)\b|"
        # libsodium's crypto_sign is Ed25519 (crypto_sign_PRIMITIVE) and PyNaCl's
        # nacl.signing wraps it (row 67). Only the names the NIST/SUPERCOP signature API
        # does not share: crypto_sign_keypair, crypto_sign_open and the *BYTES constants
        # are also every post-quantum reference implementation's.
        r"\bcrypto_sign_(?:detached|verify_detached|seed_keypair|init|update|"
        r"final_create|final_verify|state|statebytes)\b|\bnacl\.signing\b",
        re.IGNORECASE,
    )),
    ("Schnorr", "Schnorr signature usage", re.compile(
        r"\bschnorr\b|\bbip340\b|\btaproot\b", re.IGNORECASE,
    )),
    ("BLS", "BLS signature usage", re.compile(
        r"bls12[-_]?381|\bblst\b|@chainsafe/bls|\bbls_sig\b", re.IGNORECASE,
    )),
    # MD5, SHA-1 and DES as a MAC or inside a key derivation: HmacSHA1, sshd's `MACs
    # hmac-sha1`, PBKDF2WithHmacSHA1, strongSwan's prfsha1, Bouncy Castle's DESMAC. Reported
    # as the hash or cipher it is, with the use and that a quantum computer does not break
    # it -- an inventory that skips it is silent about it (ZA-OPRAVYANE row 131, decided
    # 24.10.2026). Names from the JDK standard names, BC, .NET, Go x/crypto/ssh, ring, the
    # IANA SSH registry and strongSwan (qrp-kachestvo/imena-2026-10-23, class C09).
    # Before rows 136-143, whose generic SHA-1 and MD5 names would otherwise claim the line
    # first and drop the use; a lower-case word glued on is a variable (`hmac_md5_count`).
    ("SHA1", "SHA-1 in HMAC (a MAC, or the PRF of a key derivation); " + components.MAC_OR_KDF_NOTE,
     re.compile(r"(?:pbkdf2?[-_]?(?:with)?|pbe(?:with)?)?(?:hmac(?:pbe)?|prf)[-_/]?sha-?1"
                r"(?:[-_]?96)?(?![0-9])(?!_?(?-i:[a-z]))", re.IGNORECASE)),
    ("MD5", "MD5 in HMAC (a MAC, or the PRF of a key derivation); " + components.MAC_OR_KDF_NOTE,
     re.compile(r"(?:hmac|prf)[-_/]?md5(?:[-_]?96)?(?![0-9])(?!_?(?-i:[a-z]))", re.IGNORECASE)),
    ("DES", "DES as a MAC (CBC-MAC, ISO 9797); " + components.MAC_OR_KDF_NOTE,
     re.compile(r"(?<![A-Za-z0-9])DES(?:C?MAC(?:64)?|64|(?:WITH)?ISO9797\w*)")),
    # ---- ZA-OPRAVYANE row 139: families the vocabulary did not have. Measured 23.10.2026
    # (qrp-kachestvo/imena-2026-10-23): GOST R 34.10 in 331 library names, RC2 264, MD2 112,
    # MD4 76, SM2 47, ElGamal, the KpqC schemes -- all unreported, and SM2 called EC. Names
    # from Bouncy Castle r1rv86v2, OpenSSL 3.6 (include/openssl/{rc2,md2,md4}.h), pyca,
    # pycryptodome and RustCrypto. A short name only glued to an API word or in a call.
    ("GOST R 34.10", "GOST R 34.10 usage", re.compile(
        r"(?:(?<![A-Za-z])|(?<=with))(?:EC)?GOST[-_ ]?R?[-_ ]?34\.?10|"
        r"(?<![A-Za-z0-9])ECVKO|\bgost20(?:01|12)(?:_(?:256|512))?\b",
        re.IGNORECASE)),
    ("SM2", "SM2 usage", re.compile(
        r"\bSM2(?:Engine|Signer|KeyPairGenerator|KeyExchange|ParameterSpec|WITH|with)|"
        r"(?:WITH|With|with)SM2\b|\bcurveSM2\b|\bEVP_PKEY_SM2\b|\bsm2p256v1\b")),
    ("ElGamal", "ElGamal usage", re.compile(r"\bElGamal\w*|\bELGAMAL\w*")),
    ("RC2", "RC2 usage", re.compile(
        r"\bRC2(?:Engine|WrapEngine|ParameterSpec|CryptoServiceProvider)\b|\bRC2\.Create\b|"
        r"\bEVP_rc2\w*|\bRC2_(?:set_key|ecb_encrypt|encrypt|decrypt|cbc_encrypt|cfb64_encrypt|"
        r"ofb64_encrypt)\b|[<\"]openssl/rc2\.h[>\"]|\balgorithms\.RC2\b|\bARC2\.(?:new|MODE_\w+)\b|"
        r"Crypto(?:dome)?\.Cipher\s+import\s+[^\n#]*\bARC2\b|Crypto(?:dome)?\.Cipher\.ARC2\b|"
        r"\brc2::|\bforge\.rc2\b|(?i:[\"']rc2-(?:40-|64-|128-)?(?:cbc|ecb|cfb|ofb)[\"'])")),
    ("MD4", "MD4 usage", re.compile(
        r"\bMD4(?:Digest|_Init|_Update|_Final|Init|Update|Final)\b|\bEVP_md4\b|\bmd4::|"
        r"hashlib\.new\(\s*[\"']md4[\"']|Crypto(?:dome)?\.Hash(?:\s+import\s+[^\n#]*\b|\.)MD4\b|"
        r"\bMD4\.new\b|[<\"]openssl/md4\.h[>\"]")),
    ("MD2", "MD2 usage", re.compile(
        r"\bMD2(?:Digest|_Init|_Update|_Final|Init|Update|Final)\b|\bEVP_md2\b|\bmd2::|"
        r"Crypto(?:dome)?\.Hash(?:\s+import\s+[^\n#]*\b|\.)MD2\b|\bMD2\.new\b|[<\"]openssl/md2\.h[>\"]")),
    # NIST's name for triple DES and the RC4 alias; neither is a word.
    ("3DES", "3DES named as TDEA", re.compile(r"(?<![A-Za-z0-9])TDEA(?:WRAP)?(?![A-Za-z0-9])")),
    ("RC4", "RC4 named as ARCFOUR", re.compile(
        r"(?<![A-Za-z0-9])arcfour(?:128|256)?(?![A-Za-z0-9])", re.IGNORECASE)),
    # Korea's KpqC selections and BIKE by Bouncy Castle's parameter names. "Smaug" is a
    # dragon and "aimer" French, so both need their T or a parameter set or an API word.
    ("HAETAE", "HAETAE usage (KpqC)", re.compile(r"(?<![A-Za-z])haetae", re.IGNORECASE)),
    ("SMAUG-T", "SMAUG-T usage (KpqC)", re.compile(r"(?<![A-Za-z])(?i:smaug[-_]?t)(?![a-z])")),
    ("AIMer", "AIMer usage (KpqC)", re.compile(
        r"(?<![A-Za-z])AIM(?:er|ER)(?=[-_]?(?:128|192|256)|[A-Z])|"
        r"(?i:(?<![A-Za-z])aimer[-_]?(?:128|192|256)[fs]?)")),
    ("BIKE", "BIKE usage", re.compile(r"(?<![A-Za-z])BIKE(?:128|192|256)(?![0-9])")),
    # Bouncy Castle's lightweight classes for the post-quantum schemes (org/bouncycastle/
    # pqc/crypto/*), whose names put the API word straight after the scheme.
    *[(family, f"{family} named by a Bouncy Castle class", re.compile(
        rf"\b(?:{names})(?:KEMExtractor|KEMGenerator|KeyGenerationParameters|KeyPairGenerator|"
        rf"PrivateKeyParameters|PublicKeyParameters|Signer)\b"))
      for names, family in (("HQC", "HQC"), ("UOV", "UOV"), ("CMCE", "Classic McEliece"),
                            ("Falcon", "Falcon"), ("NTRU|NTRUPlus|NTRULPRime|SNTRUPrime", "NTRU"),
                            ("HAETAE", "HAETAE"), ("AIMer", "AIMer"), ("SmaugT", "SMAUG-T"),
                            ("Mayo", "MAYO"), ("LMS|HSS", "HSS/LMS"))],
    ("HSS/LMS", "HSS/LMS named by a Bouncy Castle class", re.compile(
        r"\bLM(?:Ots|Sig)Parameters\b")),
    # ---- ZA-OPRAVYANE row 137: the header a C file includes and the types it declares its
    # keys with (A-C classes G and H, 23.10.2026), and the Java/Bouncy Castle classes whose
    # API word follows the algorithm (B class C25). Header and type names from OpenSSL 3.6.5,
    # BoringSSL, Mbed TLS 3.6.7, wolfSSL 5.9.4, liboqs 0.16.0 and NSS 3.132; classes from
    # JDK 27 java.security.{spec,interfaces} and Bouncy Castle r1rv86v2; pyca 50.0.2.
    *[(family, f"{family} named by a library header", re.compile(rf"[<\"](?:{paths})\.h[>\"]"))
      for family, paths in (
          ("RSA", r"openssl/rsaerr|mbedtls/rsa"),
          ("DSA", r"openssl/dsaerr|wolfssl/wolfcrypt/dsa"),
          ("DH", r"openssl/dherr|mbedtls/dhm"),
          ("EC", r"openssl/ec(?:_key)?|mbedtls/ec(?:p|jpake)|wolfssl/wolfcrypt/(?:eccsi|sakke)"),
          ("DES", r"openssl/des|mbedtls/des"), ("MD5", r"mbedtls/md5"), ("SHA1", r"mbedtls/sha1"),
          ("MD4", r"wolfssl/wolfcrypt/md4"), ("MD2", r"wolfssl/wolfcrypt/md2"),
          ("RC2", r"wolfssl/wolfcrypt/rc2"), ("X448", r"wolfssl/wolfcrypt/curve448"),
          ("SM2", r"wolfssl/wolfcrypt/sm2"),
          ("HSS/LMS", r"mbedtls/lms|wolfssl/wolfcrypt/wc_lms|oqs/sig_stfl_lms(?:_wrap)?"),
          ("BIKE", r"oqs/kem_bike"), ("HQC", r"oqs/kem_hqc"), ("Falcon", r"oqs/sig_falcon"),
          ("MAYO", r"oqs/sig_mayo"), ("UOV", r"oqs/sig_uov"))],
    # C types. `RSA`, `DSA` and `DH` alone are words, so only as a pointer declaration.
    *[(family, f"{family} named by a C type", re.compile(
        rf"\b(?:{names})\b" + (rf"|(?<![\w.>])(?:const\s+)?{bare}\s*\*+\s*(?:const\s+)?[A-Za-z_]"
                                if bare else "")))
      for family, bare, names in (
          ("RSA", "RSA", r"RSA_METHOD|RSA_OAEP_PARAMS|RSA_PSS_PARAMS|rsa_st|rsa_meth_st|"
                         r"rsa_(?:pss|oaep)_params_st|RSA(?:Private|Public)KeyStr|RsaPadding|RsaNb|"
                         r"sp_rsa_ctx|gnutls_rsa_params_t"),
          ("DSA", "DSA", r"DSA_SIG|DSA_SIG_st|DSA_METHOD|dsa_st|DSA(?:Private|Public)KeyStr|DsaKey|"
                         r"WOLFSSL_DSA"),
          ("DH", "DH", r"DH_METHOD|dh_st|DHParams(?:Str)?|DH(?:Private|Public)Key(?:Str)?|"
                       r"SECKEYDHParams|DhParams|DhNb|WOLFSSL_DH|sp_dh_ctx|gnutls_dh_params_t|"
                       r"psa_dh_family_t"),
          ("EC", "", r"EC_(?:KEY|GROUP|POINT|METHOD|KEY_METHOD)|ec_key_st|"
                     r"WOLFSSL_EC_(?:KEY|GROUP|POINT|METHOD|BUILTIN_CURVE)|ecc_point|ecc_set_type|"
                     r"ecc_curve_id|ecc_oid_t|ECParams(?:Str)?|ECFieldID(?:Str)?|"
                     r"EC(?:Private|Public)KeyStr|psa_ecc_family_t|mbedtls_ecjpake_context"),
          ("DES", "", r"(?:const_)?DES_cblock|DES_key_schedule|DES_ks|DES_LONG|DESContext(?:Str)?"),
          ("MD5", "", r"MD5_CTX|MD5Context(?:Str)?|MD5state_st|md5_state_st"),
          ("MD4", "", r"MD4_CTX|MD4state_st|md4_state_st|wc_Md4"),
          ("MD2", "", r"MD2_CTX|MD2_INT|MD2Context(?:Str)?|MD2state_st|wc_Md2"),
          ("SHA1", "", r"SHA_CTX|SHA1Context(?:Str)?|wc_Sha"),
          ("RC4", "", r"RC4_KEY|rc4_key_st|RC4Context(?:Str)?"),
          ("RC2", "", r"RC2_KEY|RC2_INT|rc2_key_st|RC2Context(?:Str)?|wc_Rc2"),
          ("X448", "", r"curve448_key"), ("Falcon", "", r"falcon_key"),
          ("HSS/LMS", "", r"LmsKey|LmsParams|HssPrivKey|wc_Lms(?:Parm|Rc|State)|oqs_lms_\w+"))],
    # Java and Bouncy Castle classes (C25), and the JS/Python/Rust equivalents.
    ("DSA", "DSA named by a Java/Bouncy Castle class", re.compile(
        r"\bDSA(?:Signer|DigestSigner|KeyPairGenerator|ParametersGenerator|Key|"
        r"GenParameterSpec|ParameterSpec)\b|\bPlainDSAEncoding\b|\bdsa\.DSA\w+")),
    ("ECDH", "ECDH named by a Bouncy Castle class", re.compile(
        r"\bECDH(?:Basic|Raw|C)Agreement\b|\bECDHCUnifiedAgreement\b")),
    ("EC", "EC named by a Java/Bouncy Castle class", re.compile(
        r"\bECKey(?:PairGenerator)?\b|\bEllipticCurve\b|\bec\.(?:EllipticCurve\w*|Brainpool\w+)")),
    ("RSA", "RSA named by a Java/Bouncy Castle class", re.compile(
        r"\bRSA(?:KeyGenParameterSpec|PrivateCrtKey|MultiPrimePrivateCrtKey(?:Spec)?|"
        r"OtherPrimeInfo|DigestSigner|BlindingEngine|BlindingFactorGenerator|"
        r"BlindSignature(?:Client|Server)|KEMExtractor|KEMGenerator|KeyEncapsulation)\b|"
        r"\b(?:ISO9796d2(?:PSS)?|PSS|X931)Signer\b|\b(?:ISO9796d1|OAEP|PKCS1)Encoding\b|"
        r"\b(?:PSS|OAEP)ParameterSpec\b|\brsa\.RSA\w+|"
        r"\bforge\.pki\.(?:wrap|encrypt|decrypt)RsaPrivateKey\b|\bpublicKeyToRSAPublicKey(?:Pem)?\b")),
    ("DH", "DH named by a Java/pyca class", re.compile(
        r"\bDH(?:Key|GenParameterSpec|ParameterSpec|PrivateKeySpec|PublicKeySpec)\b|\bdh\.DH\w+")),
    ("DES", "DES named by a Java/Bouncy Castle class", re.compile(
        r"\bDES(?:KeyGenerator|KeySpec)\b|\bforge\.des\.")),
    ("3DES", "3DES named by the RustCrypto des crate", re.compile(r"\bdes::Tdes\w+")),
    ("EdDSA", "EdDSA named by a JCA type", re.compile(
        r"\bEdEC(?:Key|PrivateKey|PublicKey|Point|PrivateKeySpec|PublicKeySpec)\b|"
        r"\bEdDSAParameterSpec\b")),
    ("X25519", "XDH named by a JCA type (X25519, or X448)", re.compile(
        r"\bXEC(?:Key|PrivateKey|PublicKey|PrivateKeySpec|PublicKeySpec)\b")),
    ("BLS", "BLS named by a Bouncy Castle class", re.compile(r"\bBLS(?:Signer|KeyPairGenerator)\b")),
    ("Schnorr", "Schnorr named by a Bouncy Castle class", re.compile(r"\bBIP340Signer\b")),
    # ---- ZA-OPRAVYANE row 138: JCA and Bouncy Castle algorithm names the `withRSA`/`withDSA`
    # rules stopped short of (B classes C08, C10, C17, C18, C28, C29, C30, 23.10.2026): a
    # suffix after the family (`...WithRSAEncryption`, `...inP1363Format`), the digest/scheme
    # spelling (`SHA256/RSA`), and the EC and DH schemes not spelled ECDSA/ECDH. Names from
    # the Bouncy Castle r1rv86v2 provider and JDK 27 Standard Names.
    ("RSA", "RSA named by a JCA/Bouncy Castle signature or padding name", re.compile(
        r"\w*with(?:RSAEncryption|RSASSA[-_]PSS|RSA/?PSS|RSA/X9\.31|RSA/ISO9796-2)\b|"
        r"(?-i:(?<![A-Za-z0-9_])RAWRSA(?:SSA-PSS|PSS)?(?![A-Za-z0-9_]))|"
        r"\bpadding\.(?:PSS|OAEP|PKCS1v15)\b|\bPKCS1v15\s*\(", re.IGNORECASE)),
    ("RSA", "RSA named as <digest>/RSA", re.compile(
        r"(?<![A-Za-z0-9])(?:MD[245]|SHA[-0-9()]*|RIPEMD\d+|RMD\d+)/RSA(?![A-Za-z])")),
    ("DSA", "DSA named by a JCA/Bouncy Castle signature name", re.compile(
        r"\w*withDSAinP1363Format\b|(?<![A-Za-z0-9])DSAwithSHA|"
        r"(?<![A-Za-z0-9])(?:SHA[-0-9()]*|RIPEMD\d+)/DSA(?![A-Za-z])|"
        r"(?-i:(?<![A-Za-z0-9_])(?:RAW|DET)DSA(?![A-Za-z0-9_]))|\w*with(?:DET|D)DSA\b",
        re.IGNORECASE)),
    ("ECDSA", "ECDSA named by a JCA/Bouncy Castle signature name", re.compile(
        r"\w*withECDSAinP1363Format\b|(?:\w*with|(?<![A-Za-z0-9]))(?:DETECDSA|ECDDSA)\b",
        re.IGNORECASE)),
    # EC schemes that are not ECDSA or ECDH by name: Nyberg-Rueppel and ECCSI (RFC 6507) sign,
    # ECIES and ECMQV agree a key on the curve; the cofactor and unified ECDH variants.
    ("EC", "EC signature named as ECNR or ECCSI", re.compile(
        r"(?:\w*with|(?<![A-Za-z0-9]))ECNR(?:Signer)?\b|\bECCSI\w*", re.IGNORECASE)),
    ("ECDH", "ECDH named as ECIES, ECMQV or a cofactor/unified ECDH variant", re.compile(
        r"(?<![A-Za-z])ECIES\w*|(?<![A-Za-z])EC(?:C?DH[CU]?|MQV)(?:with\w*?C?KDF)?(?![A-Za-z])|"
        r"\bECDHC(?:Basic|Raw|Staged|Unified)Agreement\b|\bECMQV(?:Basic|Raw)Agreement\b|"
        r"(?<![A-Za-z])MQVwith\w*?KDF\b|\bhpke\.(?:New)?DHKEM\w*", re.IGNORECASE)),
    ("DH", "DH named by a KDF agreement, DHIES or a Bouncy Castle class", re.compile(
        r"(?i:(?<![A-Za-z])DHU?with\w*?C?KDF\b|(?<![A-Za-z])DHIES\w*)|"
        r"\bDH(?:Agreement|UnifiedAgreement|StandardGroups|BasicKeyPairGenerator)\b|"
        r"\bMQVBasicAgreement\b")),
    ("X25519", "XDH named by a Bouncy Castle agreement (X25519, or X448)", re.compile(
        r"\bXDH(?:Basic|Unified)Agreement\b|(?<![A-Za-z])XDHwith\w+")),
    ("ElGamal", "ElGamal named by Go's openpgp packages", re.compile(
        r"\belgamal\.\w+|\w+ElGamal\w*")),
    # The digest glued to the scheme in a signature or PBE name (`MD5withRSA`, `MD2/RSA`,
    # `PBEWITHMD5ANDDES`). SHA-1 in the same shapes is row 143.
    *[(family, f"{family} named in a signature or PBE name", re.compile(
        rf"(?<![A-Za-z0-9]){family}(?=with|/|and)|PBEWITH{family}AND", re.IGNORECASE))
      for family in ("MD5", "MD2", "MD4")],
    # PKCS#12 and PKCS#5 PBE names: PKCS#12's bare `SHA` is SHA-1, DES2KEY/DES3KEY two- and
    # three-key triple DES.
    ("SHA1", "SHA-1 named in a PBE name", re.compile(r"PBEWITHSHA(?:-?1)?AND", re.IGNORECASE)),
    ("RC2", "RC2 named in a PBE name", re.compile(r"PBEWITH\w*?AND\d*(?:BIT)?RC2", re.IGNORECASE)),
    ("RC4", "RC4 named in a PBE name", re.compile(r"PBEWITH\w*?AND\d*(?:BIT)?RC4", re.IGNORECASE)),
    ("3DES", "3DES named in a PBE name", re.compile(r"PBEWITH\w*?ANDDES[23]KEY", re.IGNORECASE)),
    ("DES", "DES named in a PBE name", re.compile(
        r"PBEWITH(?:MD2|MD5|SHA-?1?)ANDDES(?:-CBC)?(?![A-Za-z0-9])", re.IGNORECASE)),
    # ---- ZA-OPRAVYANE row 140: the family named only by the package, enum or constant it
    # is reached through (B classes C20-C24, C32, C33, C35, 23.10.2026). Members from Go
    # 1.27.3 and x/crypto v0.58.0 (crypto, crypto/{dsa,elliptic,rsa,des,md5,sha1,x509},
    # ssh, ssh/agent, openpgp/packet), RustCrypto, rustls 0.23.46, ring 0.17.14, aws-lc-rs
    # 1.18.2, .NET v10.0.13 and pycryptodome/python-rsa. Case-sensitive: each library
    # writes its names exactly so. Only named members where the package is also a word.
    ("DSA", "DSA named by a package, enum or constant", re.compile(
        r"(?<![A-Za-z_-])dsa\.(?:Parameters|PublicKey|PrivateKey|ParameterSizes|"
        r"ErrInvalidPublicKey|L\d{4}N\d{3})\b|"
        # RustCrypto's dsa crate by its own items: `namespace dsa` is also data structures
        # and algorithms in C++.
        r"\bdsa::(?:OID|Signature|SigningKey|VerifyingKey|Components|KeySize|BoxedUint)\b|"
        r"\bx509\.DSA\b|"
        r"\bssh\.(?:Insecure)?(?:KeyAlgo|CertAlgo|CertSigAlgo|SigAlgo)DSA\w*|"
        r"\bpacket\.(?:PubKeyAlgo|New)DSA\w*|\bSignatureAlgorithm::DSA\b|"
        r"\bCngAlgorithmGroup\.Dsa\b|\bDSA(?:OpenSsl|Parameters|Signature(?:De)?[Ff]ormatter|"
        r"CertificateExtensions)\b|CryptoConfig\.\w+\(\s*\"(?:System\.Security\.Cryptography\.)?DSA\"")),
    ("EC", "EC named by a package, enum or constant", re.compile(
        r"\belliptic\.(?:GenerateKey|Marshal|MarshalCompressed|Unmarshal|UnmarshalCompressed|"
        r"Curve|CurveParams)\b|\belliptic_curve::|\bk256::|\bCngKeyBlobFormat\.Ecc\w+|\bECCurve\b")),
    ("RSA", "RSA named by a package, enum or constant", re.compile(
        r"\brsa\.(?:EncryptOAEPWithOptions|PSSOptions|PSSSaltLength\w+|DecryptPKCS1v15SessionKey|"
        r"PKCS1v15DecryptOptions|OAEPOptions|PrecomputedValues|CRTValue|ErrMessageTooLong|"
        r"ErrDecryption|ErrVerification|encrypt|decrypt|sign|verify|find_signature_hash|"
        r"compute_hash|sign_hash)\b|\brsa::|\bx509\.RSA\b|"
        r"\bssh\.(?:Insecure)?(?:KeyAlgo|CertAlgo|CertSigAlgo|SigAlgo)RSA\w*|"
        r"\bagent\.SignatureFlagRsa\w*|\bpacket\.(?:PubKeyAlgo|New)RSA\w*|"
        r"\bSignatureAlgorithm::RSA\b|\bOAEP_SHA\d+_MGF1SHA\d+\b|\bCngAlgorithmGroup\.Rsa\b|"
        r"\bRSA(?:Encryption|Signature)Padding(?:Mode\.\w+)?\b|\bRSAParameters\b|"
        r"\bRSA(?:OAEP|PKCS1)(?:KeyExchange|Signature)(?:De)?[Ff]ormatter\b|"
        r"\bPKCS1MaskGenerationMethod\b|\bExchangeAlgorithmType\.Rsa\w+|"
        r"\bRSA\.(?:generate|import_key|importKey|construct)\b|"
        r"CryptoConfig\.\w+\(\s*\"(?:System\.Security\.Cryptography\.)?RSA\"")),
    ("ECDSA", "ECDSA named by a Go ssh or openpgp constant", re.compile(
        r"\bssh\.(?:KeyAlgo|CertAlgo)(?:SK)?ECDSA\w*|\bpacket\.(?:PubKeyAlgo|New)ECDSA\w*")),
    ("ECDH", "ECDH named by a package, enum or constant", re.compile(
        r"\bssh\.KeyExchangeECDH\w*|\bpacket\.PubKeyAlgoECDH\b|\bECDiffieHellman\w+|"
        r"\bDH\.key_agreement\b")),    # pycryptodome's Crypto.Protocol.DH is ECDH (row 71)
    ("DH", "DH named by a package, enum or constant", re.compile(
        r"\bssh\.(?:Insecure)?KeyExchangeDH\w*|\bNamedGroup::FFDHE\d+\b")),
    ("X25519", "X25519 named by a Go ssh constant", re.compile(r"\bssh\.KeyExchangeCurve25519\w*")),
    ("X448", "X448 named as a pycryptodome curve", re.compile(
        r"\bECC\.generate\([^)\n]*curve\s*=\s*[\"'][Cc]urve448[\"']")),
    ("Ed25519", "Ed25519 named by a Go ssh constant", re.compile(
        r"\bssh\.(?:KeyAlgo|CertAlgo)(?:SK)?ED25519\w*")),
    ("ML-DSA", "ML-DSA named by a Go ssh constant", re.compile(
        r"\bssh\.(?:KeyAlgo|CertAlgo)MLDSA\w*")),
    ("RC4", "RC4 named by a package, enum or constant", re.compile(
        r"\bssh\.InsecureCipherRC4\w*|\b(?:CipherAlgorithmType|CngAlgorithm)\.Rc4\b")),
    ("MD5", "MD5 named by a package, enum or constant", re.compile(
        r"\bcrypto\.MD5(?:SHA1)?\b|\bmd5\.(?:Size|BlockSize)\b|\bssh\.FingerprintLegacyMD5\b|"
        r"\bHashAlgorithm::MD5\b|\bCngAlgorithm\.MD5\b|\bHashAlgorithmType\.Md5\b|"
        r"CryptoConfig\.\w+\(\s*\"(?:System\.Security\.Cryptography\.)?MD5(?:Cng|Managed|"
        r"CryptoServiceProvider)?\"|xmldsig-more#(?:rsa-)?md5\b")),
    ("SHA1", "SHA-1 named by a package, enum or constant", re.compile(
        r"\bcrypto\.(?:MD5)?SHA1\b|\bsha1\.(?:Size|BlockSize)\b|\bHashAlgorithm::SHA1\b|"
        r"\b(?:HKDF_)?SHA1_(?:FOR_LEGACY_USE_ONLY|OUTPUT_LEN)\b|\bCngAlgorithm\.Sha1\b|"
        r"\b(?:HashAlgorithmType|X509SubjectKeyIdentifierHashAlgorithm)\.(?:Sha1|ShortSha1|"
        r"CapiSha1)\b|\bSHA\.new\b|CryptoConfig\.\w+\(\s*\"(?:System\.Security\.Cryptography\.)?"
        r"SHA1?(?:Cng|Managed|CryptoServiceProvider)?\"|xmldsig#(?:rsa-|dsa-|hmac-)?sha1\b")),
    ("MD4", "MD4 named by a package or constant", re.compile(
        r"\bcrypto\.MD4\b|\bmd4\.(?:New|Size|BlockSize|Sum)\b")),
    ("DES", "DES named by a package, enum or constant", re.compile(
        r"\bdes\.(?:BlockSize|KeySizeError)\b|\bdes::(?:Des|WeakKeyError)\b|"
        r"\bDES_(?:FOR_LEGACY_USE_ONLY|KEY_LEN|"
        r"CBC_IV_LEN)\b|\bCipherAlgorithmType\.Des\b|"
        r"CryptoConfig\.\w+\(\s*\"(?:System\.Security\.Cryptography\.)?DES\"|xmlenc#des-cbc\b")),
    ("3DES", "3DES named by a package, enum or constant", re.compile(
        r"\bTDES_FOR_LEGACY_USE_ONLY\b|\bCipherAlgorithmType\.TripleDes\b|"
        r"CryptoConfig\.\w+\(\s*\"Triple ?DES\"|xmlenc#tripledes-cbc\b")),
    ("RC2", "RC2 named by a package, enum or constant", re.compile(
        r"\bCipherAlgorithmType\.Rc2\b|CryptoConfig\.\w+\(\s*\"(?:System\.Security\.Cryptography\.)?"
        r"RC2(?:CryptoServiceProvider)?\"")),
    # ---- ZA-OPRAVYANE row 141: protocol settings (B classes C04, C11-C15, 23.10.2026). Names
    # from IANA's TLS SignatureScheme, SSH, JOSE, COSE and DNSSEC registries (read 21.10 to
    # 29.09.2026), Go crypto/tls and strongSwan 6.1.0's proposal keywords. Short words only
    # under the key that gives them their meaning; the match starts at the key.
    ("RSA", "RSA named by a TLS SignatureScheme, SSH or JOSE/COSE name", re.compile(
        r"(?<![A-Za-z0-9_])rsa_(?:pss_(?:rsae|pss)_sha(?:256|384|512)|"
        r"pkcs1_(?:sha1|sha224|sha256|sha384|sha512|md5)(?:_legacy)?)(?![A-Za-z0-9_])|"
        r"\btls\.(?:PKCS1|PSS)WithSHA\d+\b|"
        r"(?<![A-Za-z0-9-])(?:rsa(?:1024|2048)-sha(?:1|256)|(?:spki|pgp)-sign-rsa|"
        r"x509v3-rsa2048-sha256)(?![A-Za-z0-9-])|(?<![A-Za-z])RSAES-OAEP\b|"
        r"[\"']alg[\"']\s*:\s*[\"']RS1[\"']")),
    ("DSA", "DSA named by an SSH host key type or a BIND algorithm", re.compile(
        r"(?<![A-Za-z0-9-])(?:spki|pgp)-sign-dss(?![A-Za-z0-9-])|"
        r"\balgorithm\s+[\"']?dsa[\"']?\s*;", re.IGNORECASE)),
    ("DH", "DH named by an SSH GSS key exchange or a BIND algorithm", re.compile(
        r"(?<![A-Za-z0-9-])gss-(?:group\d+|gex)-sha\d+-|\balgorithm\s+[\"']?dh[\"']?\s*;",
        re.IGNORECASE)),
    ("SM2", "SM2 named by a TLS SignatureScheme or DNSSEC mnemonic", re.compile(
        r"(?<![A-Za-z0-9])(?:sm2sig_sm3|sm2sm3)(?![A-Za-z0-9])", re.IGNORECASE)),
    ("GOST R 34.10", "GOST R 34.10 named by a DNSSEC mnemonic", re.compile(
        r"(?<![A-Za-z0-9-])ecc-gost(?:12)?(?![A-Za-z0-9-])", re.IGNORECASE)),
    ("DES", "DES named as an SSH cipher", re.compile(
        r"(?<![A-Za-z0-9])des-cbc(?:@ssh\.com)?(?![A-Za-z0-9-])", re.IGNORECASE)),
    ("MD5", "MD5 named as an SSH MAC", re.compile(
        r"(?<![A-Za-z0-9-])hmac-md5(?:-96)?(?:-etm@openssh\.com)?(?![A-Za-z0-9-])")),
    # strongSwan proposals (swanctl.conf `proposals`, ipsec.conf `ike`/`esp`/`ah`): the
    # keywords between dashes, read only on such a line.
    *[(family, f"{family} named in a strongSwan proposal", re.compile(
        rf"\b(?:proposals|ike|esp|ah)\s*=\s*[^#\n]*?(?<![A-Za-z0-9_])(?:{words})(?=[-,!\s]|$)",
        re.IGNORECASE))
      for family, words in (("DES", "des"), ("SHA1", "sha1?|sha1_160"), ("MD5", "md5(?:_128)?"))],
    ("EC", "EC named by a strongSwan brainpool group", re.compile(
        r"(?<![A-Za-z])ecp(?:224|256|384|512)bp(?![0-9A-Za-z])", re.IGNORECASE)),
    # JOSE (RFC 7518, draft-ietf-jose-hpke-encrypt) and COSE (RFC 9864) names, only as an
    # `alg` value or a quoted name: HPKE-0..2 and 7 are NIST curves, 3-4 X25519, 5-6 X448.
    ("SHA1", "SHA-1 named as a JOSE algorithm (RS1, HS1)", re.compile(
        r"[\"']alg[\"']\s*:\s*[\"'][RH]S1[\"']")),
    ("ECDSA", "ECDSA named as a fully specified JOSE/COSE algorithm (ESP*, ESB*)", re.compile(
        r"[\"'](?:ESP(?:256|384|512)|ESB(?:256|320|384|512))[\"']")),
    ("ECDH", "ECDH named as a JOSE HPKE algorithm (P-256, P-384, P-521)", re.compile(
        r"[\"']HPKE-[0127](?:-KE)?[\"']")),
    ("X25519", "X25519 named as a JOSE HPKE algorithm", re.compile(r"[\"']HPKE-[34](?:-KE)?[\"']")),
    ("X448", "X448 named as a JOSE HPKE algorithm", re.compile(r"[\"']HPKE-[56](?:-KE)?[\"']")),
    # A JWK/COSE key's curve and type (RFC 7518 6.2, RFC 9053 7.1).
    ("EC", "EC named by a JWK or COSE key's crv or kty", re.compile(
        r"[\"']crv[\"']\s*:\s*[\"'](?:P-(?:256|384|521)|brainpoolP\d{3}r1|secp256k1)[\"']|"
        r"[\"']kty[\"']\s*:\s*[\"']EC2?[\"']")),
    ("X448", "X448 named by Node's key generation", re.compile(
        r"\bgenerateKeyPair(?:Sync)?\(\s*[\"']x448[\"']")),
    # Curve448 by name: OpenSSH's curve448-sha512, strongSwan's curve448, pycryptodome.
    ("X448", "X448 named as curve448", re.compile(r"(?<![A-Za-z])curve448(?![0-9])", re.IGNORECASE)),
    # ---- ZA-OPRAVYANE row 142: composites and hybrids with a half unreported (B classes C03
    # and C31, 23.10.2026). .NET 10 CompositeMLDsaAlgorithm members, Go 1.27 crypto/hpke and
    # x/crypto/ssh, OpenSSL's curveSM2MLKEM768, Bouncy Castle's hash-then-sign and X-Wing
    # classes. The post-quantum scheme glued after `with` is read in capitals only.
    ("ML-DSA", "ML-DSA named by a composite or hash-then-sign name", re.compile(
        r"(?<=[Ww][Ii][Tt][Hh])ML-?DSA|\bHashMLDSASigner\b|\bCompositeMLDsa\w*")),
    ("SLH-DSA", "SLH-DSA named by a hash-then-sign name", re.compile(
        r"(?<=[Ww][Ii][Tt][Hh])(?:SLH-?DSA|SPHINCS)|\bHashSLHDSASigner\b")),
    ("ECDSA", "ECDSA half of an ML-DSA composite", re.compile(
        r"(?i:MLDsa\d+WithECDsa)|(?<![A-Za-z0-9])ssh-mldsa\d+-(?:nist)?p(?:256|384|521)(?![0-9])")),
    ("Ed25519", "Ed25519 half of an ML-DSA composite", re.compile(r"(?i:MLDsa\d+WithEd25519)")),
    ("Ed448", "Ed448 half of an ML-DSA composite", re.compile(r"(?i:MLDsa\d+WithEd448)")),
    ("RSA", "RSA half of an ML-DSA composite", re.compile(r"(?i:MLDsa\d+WithRSA)")),
    ("ECDH", "ECDH half of an ML-KEM hybrid (NIST curve)", re.compile(
        r"(?i:(?<![A-Za-z])MLKEM(?:768|1024)[-_]?P(?:256|384|521))(?![0-9])")),
    ("ML-KEM", "ML-KEM half of a Go ssh hybrid key exchange", re.compile(r"\bssh\.KeyExchangeMLKEM\w*")),
    ("SM2", "SM2 half of the curveSM2MLKEM768 hybrid", re.compile(r"\bcurveSM2MLKEM\d+\b")),
    *[(family, "X-Wing hybrid KEM (ML-KEM-768 + X25519), Bouncy Castle class", re.compile(
        r"\bXWing(?:KeyGenerationParameters|KeyPairGenerator|KeyParameters|PrivateKeyParameters|"
        r"PublicKeyParameters|KEMExtractor|KEMGenerator)\b")) for family in ("ML-KEM", "X25519")],
    # ---- ZA-OPRAVYANE row 143: narrow gaps (A-C sections 4-5, 23.10.2026). SHA-1 was found
    # for 29 of 535 library names: the rule above lists calls, and SHA1 glued to a scheme,
    # a separator or a camel-case word was never read. SHA-1 as a whole name here, after
    # `with`/`and`/`hmac`/`md5`/`mgf1`, or as `Sha1` after a lower-case letter; never before
    # a digit (SHA-128, SHA1024) or a lower-case word (`sha1sum` is a tool, not a name part)
    # other than with/and/kdf. Joined on at least one side (`_`, `-`, `.`, `/`, `=`, a glued
    # word, a capital) or quoted alone: "legacy SHA1 path removed" is prose, not a name (the
    # A-C negative control). Bare `SHA` only glued to `with` or `/` and a signature.
    ("SHA1", "SHA-1 named in a compound name", re.compile(
        r"(?:(?<=[_./=-])|(?<=[Ww][Ii][Tt][Hh])|(?<=[Aa][Nn][Dd])|(?<=[Hh][Mm][Aa][Cc])|"
        r"(?<=[Mm][Dd]5)|(?<=[Mm][Gg][Ff]1))(?i:sha[-_]?1)(?:(?![0-9a-z])|(?=with|and|kdf|ckdf))|"
        r"(?<![A-Za-z0-9])(?i:sha[-_]?1)(?=[_(-]|[A-Z]|with|and|kdf|ckdf)|"
        r"(?<=[\"'])(?i:sha-?1)(?=[\"'])|"
        r"(?<=[a-z])Sha1(?![0-9a-z])|(?<=[0-9])SHA1(?![0-9a-z])|"   # DH14SHA1, MD5SHA1
        r"(?<![A-Za-z0-9])SHA(?=(?:with|WITH|With)(?:RSA|DSA|ECDSA)|/(?:RSA|DSA|ECDSA)\b)")),
    # X448 and Ed25519 inside a camel-case name (wolfSSL's SetX448KeyGenCb, libgcrypt-style
    # HpkeDhKemX448Sha512), and libsodium's old batch Ed25519 signature.
    ("X448", "X448 named in a camel-case name", re.compile(r"(?<=[a-z])X448(?=[A-Z_])")),
    ("Ed25519", "Ed25519 named in a camel-case name or libsodium's batch signature", re.compile(
        r"(?<=[a-z])Ed25519(?=[A-Z_])|\bcrypto_sign_edwards25519sha512batch\w*|"
        r"[<\"]sodium/crypto_sign_edwards25519sha512batch\.h[>\"]")),
    # LMS through wolfSSL's parameter sets, liboqs's ids and Mbed TLS's API and types
    # (wolfssl/wolfcrypt/wc_lms.h, oqs/sig_stfl.h, mbedtls/lms.h).
    ("HSS/LMS", "HSS/LMS named by the wolfSSL, liboqs or Mbed TLS API", re.compile(
        r"\bWC_LMS_PARM_\w+|\bOQS_LMS_ID_\w+|\bmbedtls_lms_\w+|\bMBEDTLS_LMS_\w+|"
        r"\b(?:MBEDTLS_)?LMOTS_(?:SHA256|SHAKE)_N\d+_W\d+\b|\bMBEDTLS_LMOTS_\w+")),
    # Post-quantum schemes. Without these, a codebase that has already adopted
    # ML-KEM scans as having no post-quantum cryptography at all, which reads as
    # "not started" rather than "migrating".
    # Where the scheme name is also an ordinary English word (falcon, bike, hawk,
    # frodo), the pattern requires a parameter set: a false positive on a bicycle
    # is worse than missing an unparameterised mention.
    # Neither end carries a plain \b. Real code writes the parameter set as a
    # suffix (slh_dsa_sha2_128s, ml_kem_768_keygen, mceliece348864), and RFC 10024
    # names the TLS hybrids by concatenation: X25519MLKEM768 puts a digit in front
    # of the scheme. A word boundary refuses both. What does the protective work is
    # the lookbehind for a LETTER -- it is why "FXMSS" still does not match XMSS.
    ("ML-KEM", "ML-KEM usage", re.compile(r"(?<![A-Za-z])ml[-_]?kem", re.IGNORECASE)),
    # X-Wing (draft-connolly-cfrg-xwing-kem) is ML-KEM-768 with X25519 -- CIRCL's
    # kem/xwing/xwing.go holds an mlkem768 key and an x25519 key -- and was in no table
    # (ZA-OPRAVYANE row 77). Both halves, as for X25519MLKEM768. Only library spellings:
    # bare "X-Wing" is a starfighter.
    *[(family, "X-Wing hybrid KEM (ML-KEM-768 + X25519)", re.compile(
        r"crypto_kem_xwing\w*|kem/xwing\b|"
        r"\bxwing\.(?:Scheme|GenerateKeyPair|DeriveKeyPair|NewKeyFromSeed|Encapsulate\w*|"
        r"Decapsulate)\b|(?i:x-?wing[-_ ]?kem)")) for family in ("ML-KEM", "X25519")],
    # Round-3 Kyber is not ML-KEM: FIPS 203 Appendix C, a different Fujisaki-Okamoto
    # variant, and the two do not interoperate. Until 0.28.0 every spelling below was
    # reported as standardised ML-KEM (Mehrdad Daei, 5 Oct 2026). These are the names
    # the round-3 code carries: the reference and SUPERCOP/PQClean APIs, the Python
    # and Rust pqcrypto packages, liboqs's algorithm ids, CIRCL's package, and the
    # draft TLS hybrids (X25519Kyber768Draft00 and the oqs-provider group names).
    ("Kyber", "Kyber usage (a Kyber identifier, not FIPS 203 ML-KEM)", re.compile(
        r"pqcrystals[-_]?kyber|crypto_kem_(?:keypair_|enc_|dec_)?kyber|PQCLEAN_KYBER|"
        r"pqcrypto[-_.](?:kem\.)?kyber|pqcrypto\.kem\s+import\s+kyber|"
        r"(?<![A-Za-z])(?:x25519|x448|p256|p384|p521|secp\d+r1)[-_]?kyber|"
        r"kyber\d*[-_]?draft|OQS_KEM_(?:alg_)?kyber|circl/kem/kyber|(?<![A-Za-z])pqc_kyber",
        re.IGNORECASE,
    )),
    # The word alone. It names the round-3 scheme and is also an old name people
    # still use for ML-KEM, and the line does not say which; so it is not counted as
    # the standard. A line that names ML-KEM as well resolves it (see
    # KYBER_BY_NAME_ONLY in scan_source_file).
    ("Kyber", KYBER_BY_NAME_ONLY, re.compile(r"(?<![A-Za-z])kyber(?![A-Za-z])", re.IGNORECASE)),
    # OpenSSH 10.4's experimental composite, which 10.6 replaced without the suffix:
    # keys made with it "must be regenerated and/or removed" (10.6 release notes). Before
    # ML-DSA, which then skips the matches inside it (scan_source_file).
    ("ML-DSA-44-Ed25519 experimental", EXPERIMENTAL_SSH_MLDSA, re.compile(
        r"(?<![A-Za-z])ssh-mldsa44-ed25519@openssh\.com", re.IGNORECASE)),
    ("ML-DSA", "ML-DSA (Dilithium) usage", re.compile(
        # CIRCL's eddilithium2/3 hybrids carry Dilithium after "ed" (row 77).
        r"(?<![A-Za-z])ml[-_]?dsa|(?<![A-Za-z])(?:ed)?dilithium|pqcrystals[-_]?dilithium",
        re.IGNORECASE,
    )),
    # Their classical halves (sign/eddilithium2/eddilithium.go: "Ed25519-Dilithium2",
    # eddilithium3: "Ed448-Dilithium3"), read 23.10.2026.
    ("Ed25519", "Ed25519 half of the Ed25519-Dilithium2 hybrid (CIRCL eddilithium2)",
     re.compile(r"(?<![A-Za-z])eddilithium2(?![0-9])", re.IGNORECASE)),
    ("Ed448", "Ed448 half of the Ed448-Dilithium3 hybrid (CIRCL eddilithium3)",
     re.compile(r"(?<![A-Za-z])eddilithium3(?![0-9])", re.IGNORECASE)),
    ("SLH-DSA", "SLH-DSA (SPHINCS+) usage", re.compile(
        r"(?<![A-Za-z])slh[-_]?dsa|(?<![A-Za-z])sphincs", re.IGNORECASE,
    )),
    ("Falcon", "Falcon (FN-DSA) usage", re.compile(
        # The padded variant: liboqs OQS_SIG_alg_falcon_padded_512 (src/sig/sig.h), PQClean
        # FALCONPADDED512, oqs-provider falconpadded512 (ALGORITHMS.md), row 76.
        r"(?<![A-Za-z])falcon[-_]?(?:padded[-_]?)?(512|1024)|(?<![A-Za-z])fn[-_]?dsa|"
        r"\bwc_falcon_\w+|[<\"]wolfssl/wolfcrypt/falcon\.h[>\"]", re.IGNORECASE,
    )),
    ("Classic McEliece", "Classic McEliece usage", re.compile(
        r"(?<![A-Za-z])classic[-_ ]?mceliece|(?<![A-Za-z])mceliece", re.IGNORECASE,
    )),
    # A trailing guard as well as a leading one: "ntrunc" (n truncated) is a
    # variable in Bitcoin Core and matched 22 times. The real parameter sets are
    # spelled ntruhps2048509 / ntruhrss701 / ntru_prime, so they are named rather
    # than left to a boundary that cannot tell them from an ordinary word.
    ("NTRU", "NTRU usage", re.compile(
        # NTRU LPRime and NTRU+ (KpqC) by Bouncy Castle's names, row 139.
        r"(?<![A-Za-z])ntru(?:hps|hrss|prime|lpr|plus|[-_\d]|(?![A-Za-z]))|"
        r"(?<![A-Za-z])sntrup(?:\d+|rime)",
        re.IGNORECASE,
    )),
    ("BIKE", "BIKE usage", re.compile(r"(?<![A-Za-z])bike[-_]?l[135]", re.IGNORECASE)),
    # liboqs and oqs-provider now name HQC by security level: OQS_KEM_alg_hqc_1/3/5 and
    # hqc1/hqc3/hqc5 (src/kem/kem.h, ALGORITHMS.md; ZA-OPRAVYANE row 81).
    ("HQC", "HQC usage", re.compile(r"(?<![A-Za-z])hqc[-_]?(?:128|192|256|[135])(?![0-9])",
                                    re.IGNORECASE)),
    # Also hash-then-sign, SHA256WITHXMSSMT (Bouncy Castle), row 139.
    ("XMSS", "XMSS usage", re.compile(r"(?<![A-Za-z])xmss|(?<=with)xmss", re.IGNORECASE)),
    # Stateful hash-based, SP 800-208. CNSA 2.0 requires LMS or XMSS for firmware
    # and code signing, so a firmware pipeline that had complied scanned as empty.
    ("HSS/LMS", "LMS/HSS stateful signature usage", re.compile(
        # `lms_sha` needs its digest after it: LMS_SHARED_SECRET is a learning
        # management system's setting (row 78).
        r"(?<![A-Za-z])lms[-_]?sha(?=\d|ke)|(?<![A-Za-z])hss[-_/]?lms|(?<![A-Za-z])lms[-_]?(sha256|shake)|"
        r"(?<![A-Za-z])hsslms|lms_sha256_m\d+_h\d+|"
        # Through the library API (ZA-OPRAVYANE row 50): wolfSSL's wc_LmsKey_* (lms.h),
        # hash-sigs' hss_* entry points, Bouncy Castle's LMS/HSS signers. Whole names only:
        # bare `hss` is a home subscriber server and bare `lms` a learning system.
        r"\bwc_LmsKey_\w+|"
        r"\bhss_(?:validate_signature\w*|generate_private_key|generate_signature|"
        r"load_private_key)\b|\b(?:LMS|HSS)Signer\b",
        re.IGNORECASE,
    )),
    # The nine schemes NIST advanced to the third additional-signatures round on
    # 14 May 2026, plus CROSS, which it dropped. "mayo" and "cross" are ordinary
    # words, so those two need their parameter set, as falcon and bike do.
    ("FAEST", "FAEST usage", re.compile(r"(?<![A-Za-z])faest", re.IGNORECASE)),
    ("SQIsign", "SQIsign usage", re.compile(r"(?<![A-Za-z])sqisign", re.IGNORECASE)),
    ("SNOVA", "SNOVA usage", re.compile(r"(?<![A-Za-z])snova", re.IGNORECASE)),
    ("SDitH", "SDitH usage", re.compile(r"(?<![A-Za-z])sdith", re.IGNORECASE)),
    ("MQOM", "MQOM usage", re.compile(r"(?<![A-Za-z])mqom", re.IGNORECASE)),
    ("QR-UOV", "QR-UOV usage", re.compile(r"(?<![A-Za-z])qr[-_]?uov", re.IGNORECASE)),
    # liboqs's OQS_SIG_alg_uov_ov_Is and oqs-provider's OV_Is_pkc (src/sig/sig.h,
    # ALGORITHMS.md; row 81). OV_* only in liboqs's own capitalisation.
    ("UOV", "UOV usage", re.compile(
        r"(?<![A-Za-z])uov[-_]?(i|ip|iii|v|s|pkc)|(?<![A-Za-z])uov[-_]ov[-_]|"
        r"(?-i:(?<![A-Za-z0-9])OV_(?:Is|Ip|III|V)(?:_pkc(?:_skc)?)?(?![A-Za-z0-9]))",
        re.IGNORECASE)),
    ("MAYO", "MAYO usage", re.compile(r"(?<![A-Za-z])mayo[-_]?[1235]", re.IGNORECASE)),
    ("CROSS", "CROSS usage (dropped by NIST)", re.compile(
        r"(?<![A-Za-z])cross[-_]?r?[-_]?sdp", re.IGNORECASE,
    )),
    ("FrodoKEM", "FrodoKEM usage", re.compile(
        # e-: liboqs's ephemeral eFrodoKEM (OQS_KEM_alg_efrodokem_*), row 143.
        r"(?<![A-Za-z])e?frodokem|(?<![A-Za-z])e?frodo[-_]?(640|976|1344)", re.IGNORECASE,
    )),
    # Recognising these two is the point: both are post-quantum by design and
    # neither is safe to rely on. Unrecognised, they read as "nothing found".
    # Parameterised or hyphenated forms, case-insensitively. The bare word is
    # handled separately below: lowercase "sike" is a word in Venda, and matched
    # a translation string in Bitcoin Core -- which would have reported the one
    # broken scheme in the list as present in Bitcoin.
    ("SIKE", "SIKE usage (broken)", re.compile(
        r"(?<![A-Za-z])sikep?\d{3}|(?<![A-Za-z])sike[-_]", re.IGNORECASE,
    )),
    ("SIKE", "SIKE usage (broken)", re.compile(r"(?<![A-Za-z])SIKE(?![A-Za-z])")),
    ("HAWK", "HAWK usage (withdrawn)", re.compile(
        r"(?<![A-Za-z])hawk[-_]?(256|512|1024)", re.IGNORECASE,
    )),
    # Isogeny key exchange in no standardisation process (research, 7 Oct 2026). The
    # identifiers are the implementations' own: mike_c's API and CMake options and the
    # six primes, the Rust crate (not on crates.io), the SageMath module, the GitHub
    # org. `mike` alone never matches -- a person, the MkDocs versioning tool on PyPI,
    # MIKEY (RFC 3830) -- and neither does `import mike`, which cannot be told apart
    # from MkDocs by a regex.
    ("MIKE", "MIKE usage (isogeny NIKE, research)", re.compile(
        r"(?<![A-Za-z0-9_])mike_(?:keypair|exchange)\s*\(|"
        r"(?<![A-Za-z0-9_])MIKE_(?:BUILD_TYPE|PRIME_CHOICE|VARIANT|API|NAMESPACE)\b|"
        r"(?<![A-Za-z0-9])p(?:308_633|474_593|628_317|374_117|566_77|758_41)(?![0-9])|"
        r"(?<![A-Za-z0-9_])mike_rs(?![A-Za-z0-9_])|\bMike(?:PublicKey|PrivateKey|Parameters|Constants)\b|"
        r"from\s+mike\.mike\s+import\b|(?i:tensor-mike/mike_(?:c|rs|py))",
    )),
    # CSIDH and its constant-time CTIDH: CIRCL's dh/csidh, the reference code,
    # highctidh (C, PyPI, Go), secsidh and the csidh crate. The tokens did not occur
    # outside isogeny code on the research's negative corpus. `sidh` alone stays SIKE's.
    ("CSIDH/CTIDH", "CSIDH/CTIDH usage (isogeny NIKE, research)", re.compile(
        r"(?<![A-Za-z])d?csidh|(?<![A-Za-z])(?:d|high)?ctidh|(?<![A-Za-z])secsidh",
        re.IGNORECASE,
    )),
    # Merkle Tree Certificates: the three OIDs IANA assigned on 28 Sep 2026, Cloudflare's
    # experimental arc used until then, the draft's ASN.1 names, and BoringSSL/Chrome
    # identifiers. All three generations, because BoringSSL still uses the draft arc.
    # Trust Anchor IDs (TLSEXT_TYPE_trust_anchors, 0xca34) are a prerequisite, not MTC,
    # and `merkle` alone is CT, git and every blockchain.
    ("MTC", "Merkle Tree Certificate identifier (issuer or verifier code)", re.compile(
        r"(?<![\d.])1\.3\.6\.1\.5\.5\.7\.(?:6\.67|1\.38|25\.3)(?![\d])|"
        r"(?<![\d.])1\.3\.6\.1\.4\.1\.44363\.47(?:\.[0-5])?(?![\d])|"
        r"\b1,\s*3,\s*6,\s*1,\s*4,\s*1,\s*44363,\s*47(?:,\s*\d)?\b|"
        r"\b1L?,\s*3L?,\s*6L?,\s*1L?,\s*5L?,\s*5L?,\s*7L?,\s*(?:6L?,\s*67|1L?,\s*38|25L?,\s*3)L?\b|"
        r"\b(?:id[-_]alg[-_]mtcProof|id[-_]pe[-_]mtcCertificationAuthority(?:[-_]SHA256)?|"
        r"alg[-_]mtcProof[-_]draft|pe[-_]mtcCertificationAuthority[-_]draft|MTCProof|MTCLogEntry|"
        r"TBSCertificateLogEntry|MerkleTreeCertEntry)\b|"
        r"\b(?:X509_V_FLAG_USE_MTC_DRAFT_PLANTS_\d+|NID_(?:alg_mtcProof|pe_mtcCertificationAuthority)_draft|"
        r"MTCAnchor|kVerifyMTCs|VerifyMTCs|verify-mtcs)\b",
    )),
]

# The curve a DNSSEC mnemonic names, by the rule that matched it.
DNSSEC_CURVES = {
    "ECDSA P-256 named by a DNSSEC algorithm (13, ECDSAP256SHA256)": ("P-256", 256),
    "ECDSA P-384 named by a DNSSEC algorithm (14, ECDSAP384SHA384)": ("P-384", 384),
}


# A cheap test before each pattern (ZA-OPRAVYANE row 114). 0.35.0 runs 95 patterns per
# line instead of 60, and a full OpenSSH scan went from 88.7 s to 133.5 s. Most lines
# name no algorithm at all, so each pattern gets the literal strings one of which every
# match of it must contain, read off the regex itself -- never written by hand, because
# a hand-written list is where a lost finding would come from. A line holding none of
# them cannot match, and the pattern is not run. A pattern with no such string always
# runs. The literals are lower-cased and checked against the lower-cased line, which can
# only let more lines through; a non-ASCII line runs every pattern, because under
# IGNORECASE `s` also matches `ſ` and `k` the Kelvin sign, which .lower() does not give.
try:
    from re import _constants as _sre, _parser as _sre_parse
except ImportError:  # Python 3.10
    import sre_constants as _sre  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

_REPEATS = {_sre.MAX_REPEAT, _sre.MIN_REPEAT, getattr(_sre, "POSSESSIVE_REPEAT", None)} - {None}


def _required_literals(items) -> frozenset[str] | None:
    """Lower-cased strings, one of which every match of the parsed `items` contains.

    None when the regex promises no literal. Every element of a sequence must match, so
    any one element's set will do; the one with the fewest strings is kept (strings of
    three or more characters preferred), because it is the one checked fastest.
    """
    best: frozenset[str] | None = None
    run = ""

    def take(found: frozenset[str] | None) -> None:
        nonlocal best
        def rank(s: frozenset[str]) -> tuple[int, int, int]:
            shortest = min(map(len, s))
            return (min(shortest, 3), -len(s), shortest)
        if found and (best is None or rank(found) > rank(best)):
            best = found

    for op, av in items:
        if op is _sre.LITERAL:
            run += chr(av).lower()
            continue
        take(frozenset({run}) if run else None)
        run = ""
        if op is _sre.SUBPATTERN:
            take(_required_literals(av[-1]))
        elif op is _sre.BRANCH:
            alternatives = [_required_literals(a) for a in av[1]]
            if all(alternatives):
                take(frozenset().union(*alternatives))
        elif op in _REPEATS and av[0] >= 1:
            take(_required_literals(av[2]))
    take(frozenset({run}) if run else None)
    if best is None:
        return None
    # "rsa_new" is implied by "rsa": a line without the shorter has neither.
    return frozenset(s for s in best if not any(t != s and t in s for t in best))


def _prefilter(pattern: re.Pattern) -> tuple[str, ...] | None:
    try:
        found = _required_literals(_sre_parse.parse(pattern.pattern, pattern.flags))
    except Exception:  # unfamiliar regex internals: run the pattern on every line
        return None
    if not found or not all(s.isascii() for s in found):
        return None
    return tuple(sorted(found))


# ALGORITHM_PATTERNS with each pattern's literals; its shape is a public count, so the
# literals ride alongside instead of inside it.
_FILTERED_PATTERNS = [(algorithm, description, pattern, _prefilter(pattern))
                      for algorithm, description, pattern in ALGORITHM_PATTERNS]
# Any literal of any pattern: most lines hold none, and then no pattern is tried at all.
# One pattern without literals and the gate is the empty regex, which every line passes.
_ANY_LITERAL = re.compile("" if any(f[3] is None for f in _FILTERED_PATTERNS) else
                          "|".join(sorted({re.escape(s) for f in _FILTERED_PATTERNS for s in f[3]})))
# Which patterns a line can match, from the literals it holds. Rows 136-143 doubled the
# patterns, and checking each one's literals on every line came to cost more than the
# regexes did (OpenSSH 26 s -> 37 s). One scan finds, at every position, the longest
# literal starting there; any other literal on the line is a prefix of one of those, so
# the literals inside the ones found are exactly the literals present. The patterns tried
# are those holding one of them -- the same set the per-pattern check selects -- in list
# order, plus any pattern without literals.
def _trie_regex(words: list[str]) -> str:
    """The words as one regex shaped like a prefix tree, so each position is tried one
    branch per next character rather than one per word; at a position it matches the
    longest word starting there (children before the end of a word)."""
    tree: dict = {}
    for word in words:
        node = tree
        for ch in word:
            node = node.setdefault(ch, {})
        node[""] = {}

    def build(node: dict) -> str:
        branches = [re.escape(ch) + build(child) for ch, child in sorted(node.items()) if ch]
        if "" in node:
            branches.append("")
        if len(branches) == 1:
            return branches[0]
        return "(?:" + "|".join(branches) + ")"
    return build(tree)


_ALL_LITERALS = sorted({s for f in _FILTERED_PATTERNS if f[3] for s in f[3]},
                       key=lambda s: (-len(s), s))
_LITERAL_AT = re.compile("(?=(" + _trie_regex(_ALL_LITERALS) + "))")
_INSIDE = {s: frozenset(t for t in _ALL_LITERALS if t in s) for s in _ALL_LITERALS}
_PATTERNS_WITH = {s: frozenset(i for i, f in enumerate(_FILTERED_PATTERNS) if f[3] and s in f[3])
                  for s in _ALL_LITERALS}
_ALWAYS_TRIED = frozenset(i for i, f in enumerate(_FILTERED_PATTERNS) if not f[3])


def _candidate_patterns(lowered: str | None) -> list:
    """The patterns worth trying on a line; every pattern for a non-ASCII line."""
    if lowered is None:
        return _FILTERED_PATTERNS
    present: set[str] = set()
    for m in _LITERAL_AT.finditer(lowered):
        present |= _INSIDE[m.group(1)]
    indices = set(_ALWAYS_TRIED)
    for s in present:
        indices |= _PATTERNS_WITH[s]
    return [_FILTERED_PATTERNS[i] for i in sorted(indices)]

# (command_type, compiled regex) for signing commands found in CI/build configs.
SIGNING_COMMAND_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("gpg_sign", re.compile(r"\bgpg\s+(--detach-sign|--sign|-s)\b")),
    ("openssl_sign", re.compile(r"\bopenssl\s+(dgst|smime|cms)\b.*-sign\b")),
    ("cosign_sign", re.compile(r"\bcosign\s+sign\b")),
    ("signtool_sign", re.compile(r"\bsigntool\s+sign\b", re.IGNORECASE)),
    ("jarsigner", re.compile(r"\bjarsigner\b")),
    ("codesign", re.compile(r"\bcodesign\b")),
    # Secure Boot, kernel modules and IMA/EVM (ZA-OPRAVYANE row 34), from each tool's
    # manual: sbsign(1), pesign(1) `-s`/`--sign`, kmodsign(1), evmctl(1) `sign`,
    # `ima_sign`, `sign_hash`, and the kernel's scripts/sign-file (module-signing.rst).
    ("sbsign", re.compile(r"\bsbsign\b")),
    ("pesign", re.compile(r"\bpesign\b.*\s(?:-s|--sign)(?=\s|$)")),
    ("kmodsign", re.compile(r"\bkmodsign\b")),
    ("evmctl_sign", re.compile(r"\bevmctl\b.*\s(?:ima_sign|sign_hash|sign)(?=\s|$)")),
    ("kernel_sign_file", re.compile(r"(?:^|[\s/])sign-file\s+(?:-\w+\s+)*\w+\s+\S+\s+\S+")),
]

# The key a signing step names, so it can be joined to a key the scan found at that path.
# `openssl dgst -sign KEY` and `-inkey KEY`, `--key KEY` (sbsign, cosign, evmctl),
# signtool's `/f FILE`, and the second positional argument of kmodsign and sign-file.
_SIGNING_KEY_ARG = re.compile(
    r"(?:\s-sign|\s-inkey|\s--key|\s/f)(?:\s+|=)([^\s;|&)]+)|"
    r"(?:\bkmodsign|(?:^|[\s/])sign-file)\s+(?:-\w+\s+)*\w+\s+([^\s;|&)]+)")

# (algorithm, description, compiled regex) for key algorithms declared in IaC syntax
# (Terraform tls_private_key/aws_kms_key resources, cert-manager Certificate manifests) --
# distinct from ALGORITHM_PATTERNS, which target source-code import/API syntax that doesn't
# appear in HCL or YAML.
IAC_ALGORITHM_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("RSA", "RSA key algorithm declared in IaC", re.compile(
        r"algorithm\s*[:=]\s*\"?RSA\"?|customer_master_key_spec\s*=\s*\"RSA_\d+\"|"
        r"key_algorithm\s*[:=]\s*\"?RSA\"?",
        re.IGNORECASE,
    )),
    ("ECDSA", "ECDSA key algorithm declared in IaC", re.compile(
        r"algorithm\s*[:=]\s*\"?ECDSA\"?|customer_master_key_spec\s*=\s*\"ECC_\w+\"",
        re.IGNORECASE,
    )),
]

# A TLS cipher suite names its families in one token: ECDHE-RSA-AES128-GCM-SHA256 is
# ECDH *and* RSA. Reading the suite as a word found ECDHE and missed the rest, so an
# Apache or nginx line reported elliptic-curve exchange and no RSA, DH, DSA or 3DES.
_SUITE_COMPONENT = {
    "DHE": "DH", "EDH": "DH", "ADH": "DH", "KDHE": "DH", "DH": "DH",
    "ECDHE": "ECDH", "ECDH": "ECDH", "EECDH": "ECDH", "AECDH": "ECDH",
    "RSA": "RSA", "ARSA": "RSA", "KRSA": "RSA",
    "DSS": "DSA", "ADSS": "DSA", "DSA": "DSA",
    "ECDSA": "ECDSA", "AECDSA": "ECDSA",
    "3DES": "3DES", "CBC3": "3DES", "EDE3": "3DES", "DES": "DES", "DES40": "DES",
    "RC4": "RC4", "MD5": "MD5",
    # ZA-OPRAVYANE row 136. `SHA` alone is the record MAC, HMAC-SHA-1 (SHA256 and SHA384 are
    # other parts); MD5 and SHA-1 as a MAC are reported. RC2 is the export suites' cipher,
    # ECCPWD (RFC 8492) an elliptic-curve password exchange.
    "SHA": "SHA1", "RC2": "RC2", "ECCPWD": "EC",
}
# A line is read as a cipher list only when it carries a suite-shaped token: at least
# three dash-joined parts, or an IANA TLS_ name. "rsa-2048" is not a suite.
# Row 136: OpenSSL's own constants (`TLS1_CK_`, `SSL3_TXT_`, include/openssl/{tls1,ssl3}.h),
# JSSE's `SSL_*_WITH_*` names, and IANA's lowercase `anon` (TLS_DH_anon_WITH_...).
_SUITE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:TLS_[A-Z0-9_]+(?:anon_[A-Z0-9_]+)?|"
    r"(?:SSL3|TLS1(?:_[123])?)_(?:CK|TXT|RFC)_[A-Z0-9_]+|"
    r"SSL_(?:[A-Z0-9]+_|anon_)+?WITH_[A-Z0-9_]+|"
    r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+){2,})(?![A-Za-z0-9])")
_SUITE_PREFIX = re.compile(r"TLS_|(?:SSL3|TLS1(?:_[123])?)_(?:CK|TXT|RFC)_|SSL_\w+_WITH_")


# What makes a dash-joined token a cipher suite rather than an ordinary hyphenated
# string: it names a bulk cipher AND a mode or MAC. Anything looser produced real
# false positives on real trees: "ML-DSA-65" read as DSA, "slh-dsa-sha2-128s" read as
# DSA, and a French translation ("Remplacer-par-des-frais") read as DES.
_SUITE_CIPHER = ("AES", "CAMELLIA", "CHACHA", "SEED", "IDEA", "RC4", "DES", "3DES", "NULL",
                 "ARIA", "RC2")     # row 136
_SUITE_MODE_OR_MAC = ("CBC", "GCM", "CCM", "POLY1305", "SHA", "MD5", "UMAC")


# OpenSSL 3 names the algorithm in a string rather than in the function name:
# EVP_PKEY_Q_keygen(libctx, propq, "RSA", bits). The old rules knew RSA_new and
# EVP_PKEY_RSA, so a file called EVP_PKEY_RSA_keygen.c produced no findings at all.
_FETCH_CALL = re.compile(
    r"\bEVP_(?:PKEY_Q_keygen|PKEY_CTX_new_from_name|PKEY_is_a|PKEY_CTX_is_a|"
    r"SIGNATURE_fetch|KEYMGMT_fetch|KEM_fetch|KEYEXCH_fetch|MD_fetch|CIPHER_fetch|"
    r"ASYM_CIPHER_fetch)\s*\([^)\n]*?[\"']([A-Za-z0-9][A-Za-z0-9._\-]*)[\"']")

# Only names this scanner already claims as families. An unrecognised name is left
# alone rather than turned into a family nobody can check.
_FETCH_NAME_FAMILY = {
    "RSA": "RSA", "RSA-PSS": "RSA", "RSASSA-PSS": "RSA",
    "EC": "EC", "ECDSA": "ECDSA", "ECDH": "ECDH", "SM2": "SM2",     # SM2: row 139
    "ED25519": "Ed25519", "ED448": "Ed448", "X25519": "X25519", "X448": "X448",
    "DSA": "DSA", "DH": "DH", "DHX": "DH",
    "ML-KEM": "ML-KEM", "ML-KEM-512": "ML-KEM", "ML-KEM-768": "ML-KEM", "ML-KEM-1024": "ML-KEM",
    "ML-DSA": "ML-DSA", "ML-DSA-44": "ML-DSA", "ML-DSA-65": "ML-DSA", "ML-DSA-87": "ML-DSA",
    "SLH-DSA": "SLH-DSA", "LMS": "HSS/LMS", "XMSS": "XMSS",
    "SHA1": "SHA1", "SHA-1": "SHA1", "MD5": "MD5",
    "DES-EDE3-CBC": "3DES", "DES-EDE3": "3DES", "DES-CBC": "DES", "RC4": "RC4",
}


# The Java Cryptography Architecture names the algorithm the same way: a string to
# getInstance. Only KeyPairGenerator and Cipher next to RSA/EC/DSA were read, so
# KeyFactory/KeyAgreement and the JDK's own aliases were not (ZA-OPRAVYANE row 68). The
# names and aliases are the JDK's: com/sun/crypto/provider/SunJCE.java, sun/security/ec/
# SunEC.java and sun/security/util/KnownOIDs.java (DiffieHellman alias DH, ARCFOUR alias
# RC4, SHA-1 aliases SHA and SHA1), read 23.10.2026; `XDH` generates X25519 unless
# initialised otherwise (XDHKeyPairGenerator.DEFAULT_PARAM_SPEC). FALCON is Bouncy
# Castle's BCPQC name (org/bouncycastle/pqc/jcajce/provider/Falcon.java). A Cipher
# transformation is read by its algorithm, the part before the first `/`.
_JCA_CALL = re.compile(
    r"\b(?:KeyFactory|KeyAgreement|KeyPairGenerator|Signature|Cipher|MessageDigest|"
    r"KeyGenerator|SecretKeyFactory|AlgorithmParameters|AlgorithmParameterGenerator|KEM)"
    r"\.getInstance\(\s*[\"']([A-Za-z0-9][A-Za-z0-9._\-]*)[\"'/]")

_JCA_NAME_FAMILY = {
    "RSA": "RSA", "RSASSA-PSS": "RSA", "EC": "EC", "ECDSA": "ECDSA", "ECDH": "ECDH",
    "DH": "DH", "DIFFIEHELLMAN": "DH", "DSA": "DSA",
    "XDH": "X25519", "X25519": "X25519", "X448": "X448",
    "EDDSA": "EdDSA", "ED25519": "Ed25519", "ED448": "Ed448",
    "DES": "DES", "DESEDE": "3DES", "TRIPLEDES": "3DES", "ARCFOUR": "RC4", "RC4": "RC4",
    "SHA": "SHA1", "SHA-1": "SHA1", "SHA1": "SHA1", "MD5": "MD5",
    "FALCON": "Falcon", "FALCON-512": "Falcon", "FALCON-1024": "Falcon",
}
# Row 139: the families added then, and Bouncy Castle's names for the post-quantum ones
# (BouncyCastlePQCProvider, read in r1rv86v2).
_JCA_NAME_FAMILY.update({
    "SM2": "SM2", "ELGAMAL": "ElGamal", "RC2": "RC2", "RC2WRAP": "RC2", "TDEA": "3DES",
    "TDEAWRAP": "3DES", "MD2": "MD2", "MD4": "MD4", "LMS": "HSS/LMS", "HSS": "HSS/LMS",
    "BIKE": "BIKE", "HAETAE": "HAETAE", "SMAUGT": "SMAUG-T", "SMAUG-T": "SMAUG-T",
    "AIMER": "AIMer", "NTRULPRIME": "NTRU", "SNTRUPRIME": "NTRU", "NTRUPLUS": "NTRU",
    "HQC": "HQC", "UOV": "UOV", "MAYO": "MAYO", "CMCE": "Classic McEliece",
})
# Row 138: Bouncy Castle's bare scheme names. DHKEM is HPKE's, over X25519/X448 or a NIST
# curve (RFC 9180, JDK's DHKEM), so elliptic-curve.
_JCA_NAME_FAMILY.update({
    "OAEP": "RSA", "PSS": "RSA", "RSAPSS": "RSA", "RSA-KTS-KEM-KWS": "RSA", "DDSA": "DSA",
    "DHKEM": "ECDH",
})


# COSE algorithm identifiers (IANA "COSE Algorithms", algorithms.csv, read 23.10.2026), as
# WebAuthn's pubKeyCredParams and mdoc requests write them: `{"type": "public-key",
# "alg": -7}` is ES256. A bare `"alg": -7` is a number, so the line has to say COSE or
# public-key as well (ZA-OPRAVYANE row 87, identity-samples CredentialManagerUtil.kt).
COSE_ALGORITHMS = {
    -7: ("ECDSA", "ES256"), -9: ("ECDSA", "ESP256"), -35: ("ECDSA", "ES384"),
    -36: ("ECDSA", "ES512"), -47: ("ECDSA", "ES256K"), -51: ("ECDSA", "ESP384"),
    -52: ("ECDSA", "ESP512"), -8: ("EdDSA", "EdDSA"), -19: ("Ed25519", "Ed25519"),
    -53: ("Ed448", "Ed448"), -37: ("RSA", "PS256"), -38: ("RSA", "PS384"),
    -39: ("RSA", "PS512"), -257: ("RSA", "RS256"), -258: ("RSA", "RS384"),
    -259: ("RSA", "RS512"), -48: ("ML-DSA", "ML-DSA-44"), -49: ("ML-DSA", "ML-DSA-65"),
    -50: ("ML-DSA", "ML-DSA-87"),
}
# Row 141: RS1 (-65535), the brainpool ESB* (-265..-268), HSS-LMS (-46), RSAES-OAEP
# (-40..-42), ECDH-ES/SS with and without key wrap (-25..-34) and SHA-1 (-14).
COSE_ALGORITHMS.update({
    -65535: ("RSA", "RS1"), -265: ("ECDSA", "ESB256"), -266: ("ECDSA", "ESB320"),
    -267: ("ECDSA", "ESB384"), -268: ("ECDSA", "ESB512"), -46: ("HSS/LMS", "HSS-LMS"),
    -40: ("RSA", "RSAES-OAEP"), -41: ("RSA", "RSAES-OAEP w/ SHA-256"),
    -42: ("RSA", "RSAES-OAEP w/ SHA-512"), -14: ("SHA1", "SHA-1"),
    **{n: ("ECDH", f"ECDH ({n})") for n in range(-34, -24)},
})
_COSE_ALG = re.compile(r"[\"']?\balg[\"']?\s*[:=]\s*(-\d{1,5})(?![0-9])")
_COSE_CONTEXT = re.compile(r"public-key|pubKeyCredParams|\bcose", re.IGNORECASE)


def scan_cose_algorithms(line: str) -> list[tuple[str, int, str]]:
    """(family, position, name) for each COSE algorithm identifier on a COSE/WebAuthn line."""
    if not _COSE_CONTEXT.search(line):
        return []
    out: list[tuple[str, int, str]] = []
    for m in _COSE_ALG.finditer(line):
        named = COSE_ALGORITHMS.get(int(m.group(1)))
        if named:
            out.append((named[0], m.start(), f"{named[1]} ({m.group(1)})"))
    return out


def scan_jca_names(line: str) -> list[tuple[str, int, str]]:
    """Families named as the algorithm of a JCA getInstance call, with the name used."""
    out: list[tuple[str, int, str]] = []
    for m in _JCA_CALL.finditer(line):
        family = _JCA_NAME_FAMILY.get(m.group(1).upper())
        if family:
            out.append((family, m.start(), m.group(1)))
    return out


def scan_openssl3_names(line: str) -> list[tuple[str, int]]:
    """Families named as a string argument to an OpenSSL 3 fetch or keygen call."""
    out: list[tuple[str, int]] = []
    for m in _FETCH_CALL.finditer(line):
        family = _FETCH_NAME_FAMILY.get(m.group(1).upper())
        if family:
            out.append((family, m.start()))
    return out


_ARIA_RSA_SUITES = {"ECDHE-ARIA128-GCM-SHA256", "ECDHE-ARIA256-GCM-SHA384",
                    "ECDH-ARIA128-GCM-SHA256", "ECDH-ARIA256-GCM-SHA384"}


def scan_cipher_suites(line: str) -> list[tuple[str, int]]:
    """Families named inside cipher-suite tokens, with the position that named them.

    The position matters: a component preceded by `!` is a ban, not a use, and that
    distinction is checked by the caller exactly as it is for ordinary matches.
    """
    out: list[tuple[str, int]] = []
    for token in _SUITE_TOKEN.finditer(line):
        text = token.group(0)
        pos = token.start()
        parts = re.split(r"[-_+]", text)
        upper = [part.upper() for part in parts]
        looks_like_suite = bool(_SUITE_PREFIX.match(text)) or (
            any(part.startswith(_SUITE_CIPHER) for part in upper)
            and any(part.startswith(_SUITE_MODE_OR_MAC) for part in upper))
        if not looks_like_suite:
            continue
        families = [_SUITE_COMPONENT.get(part.upper()) for part in parts]
        families = [family for family in families if family]
        # DES-CBC3-SHA decomposes to DES and CBC3. The suite is triple DES; the
        # bare DES part is the same cipher named twice, not a second one.
        if "3DES" in families:
            families = [family for family in families if family != "DES"]
        # OpenSSL's names for TLS_ECDH(E)_RSA_WITH_ARIA_* leave the RSA out (tls1.h), row 136.
        if text.upper() in _ARIA_RSA_SUITES:
            families.append("RSA")
        out.extend((family, pos) for family in families)
    return out + _cipher_string_parts(line) + _suite_table_entry(line)


def _suite_families(parts: list[str]) -> list[str]:
    families = [f for f in (_SUITE_COMPONENT.get(p.upper()) for p in parts) if f]
    return [f for f in families if f != "DES"] if "3DES" in families else families


# OpenSSL cipher strings join selectors with `+` and separate entries with `:`, `,` or a
# space: `RC4+RSA`, `EECDH+aRSA`, `EDH+aRSA` (ZA-OPRAVYANE row 121; certbot's nginx test
# data). An entry struck out with `!` or `-` is not a use. A dash-joined entry is a suite
# name and stays with the suite reader above, which knows DES-CBC3-SHA is one cipher.
_CIPHER_ENTRY = re.compile(r"[^:,;\s'\"]+")
# GnuTLS priority strings: `NORMAL:-SIGN-ALL:+SIGN-RSA-SHA512` (mbedtls tests/ssl-opt.sh).
# Only an entry added with `+`; its keyword parts are split as a name is, so that
# `+SIGN-ML-DSA-65` stays ML-DSA and never becomes DSA.
_GNUTLS_PRIORITY = re.compile(r"--priority[= ]|\bgnutls_priority_\w+\s*\(|\bPRIORITY\s*=",
                              re.IGNORECASE)
_GNUTLS_KEYWORD = ("SIGN-", "KX-", "GROUP-", "CURVE-")


def _cipher_string_parts(line: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    gnutls = _GNUTLS_PRIORITY.search(line)
    if gnutls:
        for entry in _CIPHER_ENTRY.finditer(line, gnutls.end()):
            text = entry.group(0)
            if text.startswith("+") and text[1:].upper().startswith(_GNUTLS_KEYWORD):
                out += [(f, entry.start()) for f in _suite_families(components.components(text[1:]))]
        return out
    if line.lstrip().startswith(_COMMENT_START) or not _cipher_setting(line):
        return out
    for entry in _CIPHER_ENTRY.finditer(line):
        text = entry.group(0).lstrip("+")
        if entry.group(0)[:1] in "!-" or "-" in text or not text:
            continue
        out += [(f, entry.start()) for f in _suite_families(text.split("+"))
                if f not in {"SHA1"}]   # a bare SHA selector picks MACs, not a cipher use
    return out


# A table of TLS suites in C, one macro per suite with the IANA code first and the name's
# parts as bare words: curl's `CS_ENTRY(0x009E, DHE,RSA,AES128,GCM,SHA256,,,)`.
_SUITE_TABLE_ENTRY = re.compile(r"\b\w+\(\s*0x[0-9A-Fa-f]{4}\s*,((?:\s*[A-Z0-9]*\s*,)+\s*[A-Z0-9]*)\s*\)")


def _suite_table_entry(line: str) -> list[tuple[str, int]]:
    match = _SUITE_TABLE_ENTRY.search(line)
    if not match:
        return []
    parts = [p.strip() for p in match.group(1).split(",") if p.strip()]
    if not any(p.startswith(_SUITE_CIPHER) for p in parts):
        return []
    return [(f, match.start(1)) for f in _suite_families(parts)]


# --- key sizes named on the same line as the algorithm ---
_KEY_SIZE = re.compile(
    r"key_size\s*=\s*(\d{3,5})|(?<![A-Za-z])bits\s*=\s*(\d{3,5})|"
    r"(?<![A-Za-z])rsa[:\-_](\d{3,5})(?![0-9])|\bRSA_(\d{3,5})\b|"
    r"GenerateKey\([^)]*?(\d{3,5})\s*\)|"
    r"\bRSA_generate_key(?:_ex)?\(\s*[^,]*,\s*(\d{3,5})|"
    r"\bgenrsa\b[^\n]*?(\d{3,5})|"
    r"EVP_PKEY_Q_keygen\([^)]*?(\d{3,5})\s*\)|"
    # DNSSEC: BIND's `algorithm rsasha256 2048` and `dnssec-keygen -a RSASHA256 -b 2048`.
    r"\balgorithm\s+rsa\w*\s+(\d{3,5})\b|\bdnssec-keygen\b[^\n]*?\s-b\s+(\d{3,5})\b",
    re.IGNORECASE)


def key_size_on_line(line: str) -> int | None:
    """The key size named on this line, if any. Only used for RSA, where a size below
    the minimum is itself the finding."""
    m = _KEY_SIZE.search(line)
    if not m:
        return None
    for group in m.groups():
        if group:
            return int(group)
    return None


# `ppk = ...` is a directive in a VPN configuration and an ordinary variable name in
# source code (a paramiko key), so it is matched in configuration files only.
PPK_CONFIG_ASSIGN = re.compile(r"(?<![A-Za-z])ppk[ \t]*=", re.IGNORECASE)

# PEM private key block header, embedded directly in an IaC file (e.g. a test key checked
# into a Terraform variable or a Kubernetes Secret manifest).
EMBEDDED_KEY_PATTERN = re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED)?\s*PRIVATE KEY-----")

# A base64 body line, which is what actually follows a PEM header when a key is
# really there. Long, and only the base64 alphabet.
_PEM_BODY = re.compile(r"^[A-Za-z0-9+/=]{32,}\s*$")


def _is_embedded_key(lines: list[str], index: int) -> bool:
    """Whether the PEM header on this line opens a key, or merely names one.

    `PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"` is a parser's constant, not
    key material, and an independent comparison counted it against this tool as
    key-material evidence in a file labelled clean. A real block has its header
    alone on the line and base64 beneath it; a constant has the header inside
    quotes with code around it and nothing beneath.

    Both conditions, because either alone is too weak: a header alone on a line
    with no body is a truncated example, and a body with no header is not a key.
    """
    line = lines[index]
    match = EMBEDDED_KEY_PATTERN.search(line)
    if not match:
        return False
    after = line[match.end():].strip()
    # A constant closes its string on the same line:
    #   PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
    # A real block does not -- the base64 follows on the lines beneath, and
    # the quote, if there is one, closes far below:
    #   KEY = """-----BEGIN RSA PRIVATE KEY-----
    # So the question is only whether the string ends right after the header.
    if after[:1] in ("\"", "'", "`"):
        # The string ends right after the header, so this line holds a header
        # and nothing else. It is key material only if the key is somewhere:
        # on the lines beneath, or escaped into this same line with its end
        # marker, which is how a key gets into a Terraform variable.
        for follower in lines[index + 1:index + 3]:
            if _PEM_BODY.match(follower.strip()):
                return True
        return False
    if "END" in after and "PRIVATE KEY" in after:
        return True
    return True


def display_path(rel: str) -> str:
    """A relative path that can always be printed and serialised.

    A file name that is not valid UTF-8 comes back from the filesystem with
    surrogate escapes; JSON and MCP serialisation reject those, which used to fail
    the whole scan. The bytes are kept visible as backslash escapes instead.
    """
    return os.fsencode(rel).decode("utf-8", "backslashreplace")


def _link_target(repo_path: Path, rel: str) -> str:
    """Where the link points, said without leaking a path outside the root."""
    try:
        resolved = (repo_path / rel).resolve(strict=False)
        inside = resolved.relative_to(repo_path.resolve(strict=False))
    except (OSError, ValueError, RuntimeError):
        return "outside the scanned directory"
    return display_path(inside.as_posix())


def _is_link(path: Path) -> bool:
    """A symlink, or a Windows junction, which is_symlink() does not report."""
    # On OSError the answer is False rather than True: lstat fails only when the
    # parent cannot be traversed, and then is_file() fails too, so the entry is
    # already reported as unreadable. Calling it a link instead would relabel a
    # permission problem as a policy decision and hide it.
    try:
        if path.is_symlink():
            return True
    except OSError:
        return False
    junction = getattr(os.path, "isjunction", None)
    if junction is None:
        return False
    try:
        return bool(junction(path))
    except OSError:
        return False


def iter_repo_files(repo_path: Path, excluded_counter: dict[str, int] | None = None,
                    problems: list[tuple[str, str]] | None = None):
    """Every file under the path, minus the vendored and generated directories.

    The exclusion is counted rather than silent. A directory name dropped here
    never reaches the denominator, so a filter that shapes the number and does
    not declare itself is the same defect this scanner exists to refuse -- and
    git will not tell you it happened, because build output is usually ignored
    and an ignored file leaves the tree reporting clean.

    What the walk cannot see is reported in ``problems`` as ("dir", path) for a
    directory it could not enter or list, and ("file", path) for an entry that is
    not a readable regular file (a broken link, a permission error on stat).

    Symlinks are not followed, and are reported as ("symlink", path) for a file
    and ("symlink_dir", path) for a directory. A link is a path out of the
    directory the caller named, and following one lets the scanned tree decide
    what this tool reads: an external audit of 0.9.0 found a link called
    linked.py returning the contents of a file next to the repository, presented
    as linked.py. The excerpt travels to an MCP client and into an exported CBOM,
    so that is the declared boundary failing rather than a cosmetic error.
    Before this, such directories vanished and the scan still said it had read
    every file. Only directory names exclude: a *file* called ``build`` is a file.
    """
    def rel(p: str) -> str:
        return display_path(Path(p).relative_to(repo_path).as_posix())

    def onerror(err: OSError) -> None:
        if problems is not None and err.filename:
            problems.append(("dir", rel(err.filename)))

    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo_path, onerror=onerror):
        dirnames.sort()
        dir_parts = Path(dirpath).relative_to(repo_path).parts
        hit = next((part for part in dir_parts if part in EXCLUDED_DIRS), None)
        # os.walk already declines to descend into a linked directory; without this
        # it simply vanished, and the scan still said it had read every file.
        if hit is None:
            for name in list(dirnames):
                candidate = Path(dirpath) / name
                if _is_link(candidate):
                    if problems is not None:
                        problems.append(("symlink_dir", rel(str(candidate))))
                    dirnames.remove(name)
        for name in filenames:
            path = Path(dirpath) / name
            if hit is not None:
                if excluded_counter is not None:
                    excluded_counter[hit] = excluded_counter.get(hit, 0) + 1
                continue
            if _is_link(path):
                # Not read, and named. A broken link is reported the same way: it
                # is still a link, and its target is still outside this tool's say.
                if problems is not None:
                    problems.append(("symlink", rel(str(path))))
                continue
            try:
                regular = path.is_file()
                broken = not regular and (path.is_symlink() or not path.exists())
            except OSError:
                # Listed but not stat-able: a directory that can be read but not entered.
                regular, broken = False, True
            if not regular:
                # Sockets, FIFOs and devices are not files the tool reads; a broken or
                # unreachable entry is a file it could not read, and says so.
                if broken and problems is not None:
                    problems.append(("file", rel(str(path))))
                continue
            found.append(path)
    yield from sorted(found)


def is_ci_config_file(path: Path, repo_path: Path) -> bool:
    rel = path.relative_to(repo_path).as_posix()
    if rel.startswith(".github/workflows/") and path.suffix.lower() in {".yml", ".yaml"}:
        return True
    if rel.startswith(".circleci/") and path.suffix.lower() in {".yml", ".yaml"}:
        return True
    return path.name in CI_CONFIG_FILENAMES


def is_config_file(path: Path) -> bool:
    """A configuration file, by extension or by one of the extensionless names."""
    return (path.suffix.lower() in CONFIG_EXTENSIONS or path.name in CONFIG_FILENAMES
            or bool(CONFIG_FILENAME_PATTERN.match(path.name))
            or (not path.suffix and path.parent.name in CONFIG_DIRECTORIES))


# Returned when the platform cannot open relative to a directory descriptor, to
# tell "this machine cannot do the chained open" apart from "the chained open
# refused". Falling back on a refusal would re-open the very path that was
# rejected, through the parent that was just swapped -- which is how the first
# version of this guard let an external file in while looking like it worked.
_NO_DIRFD = object()


def _read_within(root: Path, path: Path) -> bytes | None | object:
    """Read a file, refusing to leave `root` by any component of the path.

    `O_NOFOLLOW` on the final component closes the common window; it does not
    close the one an independent analysis used, which replaced a PARENT directory
    with a link after the walk and got content from outside the tree. Each
    component is opened relative to the one before it, with the link check applied
    at every step, so a directory swapped after the walk fails the open instead of
    redirecting it.

    Linux and the other platforms that carry `dir_fd`. Where the interpreter has no
    `dir_fd` support -- Windows -- this falls back to the single-component
    protection, and that limit is stated rather than implied away.
    """
    if not (os.open in os.supports_dir_fd and getattr(os, "O_NOFOLLOW", 0)):
        return _NO_DIRFD
    try:
        relative = path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    parts = relative.parts
    if not parts:
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW
    opened: list[int] = []
    try:
        current = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        opened.append(current)
        for name in parts[:-1]:
            nxt = os.open(name, flags | getattr(os, "O_DIRECTORY", 0), dir_fd=current)
            opened.append(nxt)
            current = nxt
        descriptor = os.open(parts[-1], flags, dir_fd=current)
    except OSError:
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass
        return None
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            return handle.read()
    except OSError:
        return None
    finally:
        for fd in opened:
            try:
                os.close(fd)
            except OSError:
                pass


def _read_file(path: Path, root: Path | None = None) -> tuple[bytes, list[str]] | None:
    """The file's bytes and its lines, read once, or None when it could not be read.

    One snapshot, two uses. The text scan, the binary parsers and the corpus digest
    all have to describe the same read: taking the bytes twice let a file change
    between them, and digesting the decoded text rather than the bytes let two
    different files agree. An external retest of 0.11.0 found both -- two DER blobs
    differing in one byte, one detected as RSA and one not, sharing a digest.

    The open refuses to follow a link at the final component (`O_NOFOLLOW`). The
    check that a path is a link happens while walking the tree, and the read comes
    after it; between the two, the entry can be replaced with a link to somewhere
    outside the root, which the same retest demonstrated. Opening without following
    closes that window.

    It does not close all of it: a PARENT directory swapped for a link after the
    walk is still followed, because each component would have to be opened relative
    to the last. That is stated here rather than implied away -- the tool says what
    it does not cover.
    """
    if root is not None:
        raw = _read_within(root, path)
        if raw is _NO_DIRFD:
            pass  # no dir_fd on this platform: the single-component read below
        elif raw is None:
            return None  # the chained open refused. It does not get a second try.
        else:
            return raw, _decode(raw)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            raw = handle.read()
    except OSError:
        return None
    return raw, _decode(raw)


def _decode(raw: bytes) -> list[str]:
    """Bytes to lines, with the encodings a repository actually contains."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore").splitlines()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    # UTF-16 without a byte-order mark: ASCII text puts a NUL in every pair, on the same
    # side. Decoded as UTF-8 it read as clean and was counted as read (ZA-OPRAVYANE row 61).
    head = raw[:4096]
    pairs = len(head) // 2
    if pairs >= 4:
        odd, even = head[1::2].count(0), head[0::2].count(0)
        if odd >= 0.9 * pairs and even == 0:
            return raw.decode("utf-16-le", errors="ignore").splitlines()
        if even >= 0.9 * pairs and odd == 0:
            return raw.decode("utf-16-be", errors="ignore").splitlines()
    return raw.decode("utf-8", errors="ignore").splitlines()


def _read_lines(path: Path) -> list[str] | None:
    """Lines of the file, or None when it could not be read.

    None is not an empty file. A file the scanner cannot open -- no permission, an I/O
    error, a path it lacks the rights for -- yields no findings, and returning [] here
    would make that indistinguishable from a file that WAS read and is clean. scan_repo
    reports those paths separately, so a failed check cannot read as a pass.
    """
    read = _read_file(path)
    return None if read is None else read[1]


def is_iac_file(path: Path, repo_path: Path, lines: list[str] | None = None) -> bool:
    if path.suffix.lower() in IAC_EXTENSIONS:
        return True
    if path.suffix.lower() in {".yaml", ".yml"}:
        # Content-sniff for a Kubernetes manifest shape rather than trusting the extension
        # alone -- most .yaml files in a repo are not IaC.
        lines = (_read_lines(path) or []) if lines is None else lines
        has_api_version = any(re.match(r"^apiVersion:\s*\S+", line) for line in lines)
        has_kind = any(re.match(r"^kind:\s*\S+", line) for line in lines)
        return has_api_version and has_kind
    return False


# A cipher suite names what it excludes as well as what it allows: an OpenSSL
# cipher string writes "!3DES !MD5 !RC4". Reporting those as usage does not pad
# the answer, it inverts it -- the one configuration that took the trouble to ban
# a primitive gets recorded as using it. Found in Certbot's Apache fixtures,
# where eight of nine DES findings were the string "!3DES".
#
# This applies to CONFIGURATION ONLY. In C, "!" is logical negation, and applying
# the rule to source deleted 190 real findings in OpenSSL alone -- if (!MD5_Init(&c)),
# if (!EC_POINT_set_affine_coordinates(...)), if (!ml_kem_has(key, selection)).
# A rule that hides real cryptography is the same failure as one that invents it.
def _is_excluded(line: str, start: int) -> bool:
    """True when the match is an exclusion in a cipher list, not a use of it."""
    i = start - 1
    # Step back over a leading digit, so "!3DES" is judged from the "!" and not
    # from the "3" that the DES pattern happens to start on.
    while i >= 0 and line[i].isdigit():
        i -= 1
    return i >= 0 and line[i] == "!"


# A long hexadecimal or base64 blob can spell an algorithm name by accident: a NIST
# test vector in OpenSSH contains "ed448" inside the message bytes. A match that
# starts inside such a run is an accident of the alphabet, not a use.
_BLOB = re.compile(r"(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/]{40,}={0,2})")


def _blob_spans(line: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in _BLOB.finditer(line)]


def _in_blob(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= pos < end for start, end in spans)


def _masked(line: str, spans: list[tuple[int, int]]) -> str:
    """The line with the inside of each blob blanked, for searching only.

    A match that starts inside a blob is thrown away anyway, but searching through the
    blob first cost time that grows with the square of its length: a pattern that opens
    with `\\w*` walks to the end of the run from every position in it. One ML-DSA test
    vector line of 9,272 hex digits took 2.8 s for the 48 patterns, and BoringSSL has
    12,921 lines over 2,000 characters -- the scan never finished (2026-09-28). The first
    and last character stay, so a look-behind at the edge of a blob sees what it saw
    before; positions do not move, so every offset still points into the real line.
    """
    if not spans:
        return line
    chars = list(line)
    for start, end in spans:
        for i in range(start + 1, end - 1):
            chars[i] = " "
    return "".join(chars)


# What kind of evidence a line is. Asked for by an external audit and by a
# measured precision gap: a bare word in a comment and a real call site looked
# alike, and the same algorithm was reported twice -- once where its module is
# imported and once where it is called. A rival strips comments before matching;
# this scanner keeps them and says what they are, which is more information
# rather than less, provided the report says which is which.
# `#` opens a comment in shell, Python, Ruby, YAML and most configuration, and
# opens a preprocessor directive in C. `#define SSH_HOSTKEY_ALGS "ssh-ed25519"`
# is code, and calling it a comment hid a real finding -- caught by the suite
# rather than by reasoning about it.
_C_DIRECTIVE = re.compile(
    r"^\s*#\s*(?:define|include|if|ifdef|ifndef|elif|else|endif|pragma|undef|error|line)\b")
_COMMENT_LINE = re.compile(
    r"^\s*(?:#|//|--(?!\s*\w+\s*=)|;|/\*|\*(?!/)|<!--|\.\.\s|%|\bREM\b)", re.IGNORECASE)
_IMPORT_LINE = re.compile(
    r"^\s*(?:import\b|from\s+\S+\s+import\b|#\s*include\b|use\s+\S+;|require\s*\(|"
    r"using\s+\S+;|package\s+\S+;|\s*\"[\w./-]+\"\s*$)")
_CALL_SHAPE = re.compile(r"\w\s*\(")


# Which comment markers a file actually uses. Applying all of them everywhere is
# how `;` in C or `#` in a preprocessor line becomes a comment that is not there,
# so an unknown extension gets no mid-line comment detection at all and keeps the
# older whole-line behaviour.
_SLASH_COMMENT_EXT = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".java", ".js",
    ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rs", ".swift", ".kt",
    ".kts", ".scala", ".sc", ".php", ".m", ".mm", ".groovy", ".dart", ".proto",
    ".json5",
}
_HASH_COMMENT_EXT = {
    ".py", ".rb", ".sh", ".bash", ".zsh", ".pl", ".pm", ".ps1", ".psm1",
    ".yaml", ".yml", ".toml", ".conf", ".cnf", ".cfg", ".ini", ".properties",
    ".tf", ".tfvars", ".r", ".cmake", ".mk", ".t", ".env", ".gitignore",
}
_DASH_COMMENT_EXT = {".sql", ".lua", ".hs", ".adb", ".ads"}
# Languages whose triple-quoted strings are used as documentation. A docstring
# is a string to the interpreter and a comment to every reader, and an
# independent comparison counted an example call inside one as a use. Treated
# as a comment here for the same reason `#` is: nothing in it runs.
_DOCSTRING_EXT = {".py", ".pyi"}
_TRIPLE = ('"""', "'''")


def _docstring_spans(line: str, inside: str) -> tuple[list[tuple[int, int]], str]:
    "Triple-quoted regions on this line, and which delimiter is still open."
    # Almost every line has no triple quote in it. Asking that once is a string
    # search; asking it per character through a generator cost 13% of a scan.
    if not inside and (chr(34) * 3) not in line and (chr(39) * 3) not in line:
        return [], ""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(line)
    if inside:
        end = line.find(inside)
        if end == -1:
            return [(0, n)], inside
        spans.append((0, end + 3))
        i = end + 3
    while i < n:
        opener = next((q for q in _TRIPLE if line.startswith(q, i)), "")
        if not opener:
            i += 1
            continue
        # A docstring opens a statement. `KEY = """-----BEGIN RSA PRIVATE
        # KEY-----` opens a value, and a private key pasted into one is
        # exactly what this scanner is for. Anything before the delimiter
        # other than indentation means this is a string, not documentation.
        if line[:i].strip():
            return spans, inside
        end = line.find(opener, i + 3)
        if end == -1:
            spans.append((i, n))
            return spans, opener
        spans.append((i, end + 3))
        i = end + 3
    return spans, ""


def _comment_spans(line: str, ext: str, inside_block: bool) -> tuple[list[tuple[int, int]], bool]:
    """Where the comments are on this line, and whether the next line continues one.

    Deciding comment-or-code for a whole line is what made `marker = "/*"` in
    Python silence every call beneath it, and made the text of
    `x = 1  # rsa.generate_private_key(...)` count as a use. Both were found by an
    external retest of 0.11.0. A quote-aware walk fixes both directions at once:
    a marker inside a string opens nothing, and a match after a marker is comment
    text rather than code.

    String contents stay code on purpose. A cipher suite or an algorithm name in a
    string literal is usually the configuration itself, and calling it a comment
    would lose the very lines a configuration scan is for.
    """
    slash, hash_, dash = ext in _SLASH_COMMENT_EXT, ext in _HASH_COMMENT_EXT, ext in _DASH_COMMENT_EXT
    spans: list[tuple[int, int]] = []
    n, i, quote = len(line), 0, ""
    if inside_block:
        end = line.find("*/")
        if end == -1:
            return [(0, n)], True
        spans.append((0, end + 2))
        i = end + 2
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
            i += 1
            continue
        if c in "\"'":
            quote = c
            i += 1
            continue
        if slash and line.startswith("//", i):
            spans.append((i, n))
            return spans, False
        if slash and line.startswith("/*", i):
            end = line.find("*/", i + 2)
            if end == -1:
                spans.append((i, n))
                return spans, True
            spans.append((i, end + 2))
            i = end + 2
            continue
        if hash_ and c == "#":
            spans.append((i, n))
            return spans, False
        if dash and line.startswith("--", i):
            spans.append((i, n))
            return spans, False
        i += 1
    return spans, False


def _in_spans(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


def _code_only(line: str, spans: list[tuple[int, int]]) -> str:
    """The line with its comments blanked out, so a search cannot read them.

    Blanked rather than removed: positions have to keep meaning for the caller.
    """
    if not spans:
        return line
    chars = list(line)
    for start, end in spans:
        for i in range(start, min(end, len(chars))):
            chars[i] = " "
    return "".join(chars)


# A sentence in a string is read the way a comment is: `"supports Ed25519 and ML-KEM"` is
# help text, not a configuration, and it was a finding (ZA-OPRAVYANE row 132). A string is
# a sentence when it has three or more words, two of them lower-case words, and one of them
# a word only prose uses. "openssl genrsa -out key.pem 2048" has no such word and stays code.
_STRING_LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"|' r"'(?:[^'\\\n]|\\.)*'")
_PROSE_WORDS = {"a", "an", "the", "and", "or", "is", "are", "was", "were", "be", "not",
                "of", "for", "with", "from", "to", "in", "on", "by", "this", "that", "it",
                "supports", "support", "uses", "use", "using", "vs"}


def _prose_spans(code: str) -> list[tuple[int, int]]:
    "String literals on this line whose text is a sentence."
    spans: list[tuple[int, int]] = []
    for m in _STRING_LITERAL.finditer(code):
        words = m.group(0)[1:-1].split()
        lower = [w for w in words if w.isalpha() and w.islower()]
        if len(words) >= 3 and len(lower) >= 2 and _PROSE_WORDS & set(lower):
            spans.append((m.start(), m.end()))
    return spans


def _evidence_kind(line: str, inside_block_comment: bool, code: str | None = None) -> str:
    """The kind of evidence the CODE on this line carries.

    `code` is the line with comments blanked out; when it is given, the shape of
    the line is judged from the code alone, so a comment cannot turn an
    assignment into a call or the other way round.
    """
    stripped = (line if code is None else code).strip()
    if _C_DIRECTIVE.match(line):
        return "declaration"
    if inside_block_comment or _COMMENT_LINE.match(line):
        return "comment"
    if not stripped:
        return "comment"
    if _IMPORT_LINE.match(line):
        return "import"
    if _CALL_SHAPE.search(stripped):
        return "call"
    if "=" in stripped or ":" in stripped:
        return "declaration"
    return "reference"


# A ban is not a use. This scanner already refused to count `!MD5` in a cipher
# list and `-SSLv3` in an SSLProtocol line; a negative corpus written for this
# release found the same idea in a dozen shapes that were all counted as uses --
# an SSH directive removing an algorithm with a minus, a policy file listing what
# is forbidden, jdk.tls.disabledAlgorithms, a lint rule whose purpose is to
# forbid the pattern it quotes, a BANNED_CIPHERS set.
#
# Two triggers, both narrow. The line has to say denial, or the token itself has
# to be removed with a leading - or !. "enabledAlgorithms" must stay a use, so
# the words are matched whole and the negative forms are listed rather than
# guessed at.
#
# `weak` and `insecure` were here and are not any more. They describe a risk, not
# a prohibition: `weak_key = rsa.generate_private_key(key_size=1024)` is the very
# thing an inventory exists to find, and naming the variable honestly made this
# scanner drop it. An external retest of 0.11.0 found it, and a rule that hides
# cryptography is the same defect as a rule that invents it.
# The word is matched case-insensitively and the boundary after it is not: a
# camelCase identifier keeps the word whole (blockedAlgorithms, rejectedSuites),
# while a lower-case letter after it means a different word. Compiling the whole
# pattern with IGNORECASE made [a-z] match "A" and broke exactly that.
_DENIAL_WORDS = re.compile(
    r"(?<![A-Za-z])"
    r"(?i:disabled|disallow(?:ed)?|banned|blocked|blocklist|blacklist|"
    r"forbidden|prohibited|denied|deny|reject(?:ed)?|excluded|unsupported|"
    r"not[-_ ]?allowed|must[-_ ]?not|no[-_ ]?longer|removed)"
    r"(?![a-z])")
# Where a leading - or ! strikes an entry out rather than opening a command-line
# flag. `openssl req -newkey rsa:2048` is a use; `HostKeyAlgorithms -ssh-rsa` is a
# ban, and only the directive tells them apart.
_ALGORITHM_LIST_LINE = re.compile(
    r"(?<![A-Za-z])(?:HostKeyAlgorithms|KexAlgorithms|PubkeyAcceptedAlgorithms|"
    r"PubkeyAcceptedKeyTypes|HostbasedAcceptedAlgorithms|CASignatureAlgorithms|"
    r"Ciphers|MACs|SSLCipherSuite|SSLProtocol|ssl_ciphers|ssl_protocols|"
    r"cipher[-_]?(?:list|suites?)|\w*[Aa]lgorithms)\s*[:=]?\s", re.IGNORECASE)


# A block a condition opens -- `if (err === 'ERR_UNSUPPORTED') {`, `} catch
# (UnsupportedAlgorithmError) {`, `except UnsupportedAlgorithm:` -- is the code that runs
# in that case, not a list of what is banned. Row 54 (0.34.0) stopped such a block from
# turning calls into bans; a declaration inside it (`const curve = 'prime256v1'`) was still
# one (ZA-OPRAVYANE row 90).
_CONDITION_OPENER = re.compile(
    r"^\s*\}?\s*(?:if|else|elif|elsif|catch|except|rescue|try|finally|switch|case|when|"
    r"while|for|unless)\b")
# A test that a call is rejected: everything in its block is attempted in order to fail,
# calls included (row 91, certbot crypto_util_test.py:236).
_REJECTION_TEST = re.compile(r"\b(?:pytest\.raises|assertRaises(?:Regex)?|assertThrows)\s*\(")


def _opens_a_denial_block(line: str) -> bool:
    """`forbiddenAlgorithms:` on its own line, with the names indented below it.

    A configuration file writes a ban as a block far more often than as a list on
    one line, and a line-by-line reader sees the names without the word that
    governs them.
    """
    stripped = line.rstrip()
    return bool(stripped.endswith((":", "= [", "=[", "{", "(", "["))
                and _DENIAL_WORDS.search(stripped)
                and not _CONDITION_OPENER.match(stripped))


def _is_banned_here(line: str, position: int, in_denial_block: bool = False,
                    code: str | None = None) -> bool:
    """Whether the algorithm at this position is being forbidden rather than used.

    `code` is the line with its comments blanked out. A denial word in a comment
    describes the code; it does not govern it. `key = generate(1024)  # weak key,
    kept for compatibility` is a use, and reading the comment made it a ban.
    """
    searchable = line if code is None else code
    if in_denial_block or _DENIAL_WORDS.search(searchable):
        return True
    # Work in entries, not characters. A hyphen inside a name belongs to it --
    # ssh-rsa, ecdsa-sha2-nistp256, aes256-sha256-modp2048 -- and strikes an entry
    # out only when it opens one. So find the entry containing this position and
    # ask whether that entry begins with - or !.
    # A TLS group setting is a list too: `Groups = DEFAULT:-X25519MLKEM768` removes the
    # hybrid. The same test the TLS group rule asks, so the two cannot disagree
    # (ZA-OPRAVYANE row 56).
    if not (_ALGORITHM_LIST_LINE.search(line) or _group_setting(line)):
        return False
    start = position
    while start > 0 and line[start - 1] not in ",;:=([{ \t\"'":
        start -= 1
    return line[start:start + 1] in {"-", "!"}


def _families_named(findings: list[dict[str, Any]]) -> set[str]:
    return {f["algorithm"] for f in findings}


def _families_in_use(findings: list[dict[str, Any]]) -> set[str]:
    """Families with evidence that is neither a comment nor a ban."""
    return {f["algorithm"] for f in findings
            if f.get("evidence_kind") not in {"comment", "ban"}}


# A Go function signature names the types it takes and returns; it calls nothing. `func
# demo(pub *rsa.PublicKey) {` was a `call`, and 9 of 0.36.0's 32 rows off Cryben's reference
# were such lines, one above the call they introduce (qrp-pokazateli 02-tochnost). Only a
# signature whose line opens no body with code in it: `func f() { rsa.Sign(...) }` calls.
_GO_SIGNATURE = re.compile(r"^\s*func\s*(?:\([^)]*\)\s*)?\w+\s*(?:\[[^\]]*\]\s*)?\(")
_GO_BODY_CODE = re.compile(r"\{\s*\S")
# Families one call and one type of the same library name differently: ecdsa.PublicKey in
# the signature, elliptic.P256() in the body.
_FAMILY_GROUP = {"ECDSA": "EC", "ECDH": "EC", "3DES": "DES", "EdDSA": "Ed25519",
                 "Ed448": "Ed25519"}
_SIGNATURE_REACH = 2


def _drop_signatures_covered_by_a_call(findings: list[dict[str, Any]],
                                       signature_lines: set[int]) -> list[dict[str, Any]]:
    """A Go signature is not a second row when a call of the same family group follows
    within two lines (the reach measured on Cryben: -8 rows off the reference, none on it)."""
    if not signature_lines:
        return findings
    calls = [(f["line"], _FAMILY_GROUP.get(f["algorithm"], f["algorithm"]))
             for f in findings if f.get("evidence_kind") == "call"]
    return [f for f in findings
            if not (f["line"] in signature_lines and f.get("evidence_kind") == "reference"
                    and any(0 < line - f["line"] <= _SIGNATURE_REACH
                            and group == _FAMILY_GROUP.get(f["algorithm"], f["algorithm"])
                            for line, group in calls))]


def _drop_imports_covered_by_a_call(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """An import is not a second row when the call it enables is in the file.

    Measured on Cryben: 20 of 24 rows the reference did not place were import
    lines within two lines of the call. An import on its own is kept -- a module
    in the build is evidence, and dropping it would trade a duplicate for a miss.
    """
    called = {f["algorithm"] for f in findings if f.get("evidence_kind") == "call"}
    return [f for f in findings
            if not (f.get("evidence_kind") == "import" and f["algorithm"] in called)]


# Which module implements the algorithm, where a line names it unambiguously. For a
# FIPS reader the module is the question -- validation belongs to a module, not to an
# algorithm -- and until 0.28.0 `@noble/post-quantum` and Go's `crypto/mlkem` gave
# identical findings (Jesone Sam, 6 Oct 2026). What is named is the API: a fork that
# keeps it reads the same. Nothing here says anything about CMVP validation. A header
# such as <openssl/evp.h> is shared by OpenSSL, BoringSSL and LibreSSL, so it names no
# one; only identifiers one of them alone carries are listed.
PROVIDER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("@noble/post-quantum", re.compile(r"@noble/post-quantum")),
    ("Go standard library", re.compile(r"[\"'`]crypto/(?:mlkem|internal/fips140/mlkem)[\"'`]")),
    ("Cloudflare CIRCL", re.compile(r"github\.com/cloudflare/circl/(?:kem|sign|dh|pke)/")),
    ("liboqs", re.compile(
        r"\bOQS_(?:KEM|SIG)_|\boqs\s*(?:\.|::)\s*(?:KeyEncapsulation|Signature|kem|sig)\b")),
    ("pqcrypto", re.compile(
        r"\bpqcrypto(?:\.(?:kem|sign)\b|[-_](?:kyber|mlkem|dilithium|mldsa|falcon|"
        r"sphincsplus|hqc|classicmceliece|frodo))", re.IGNORECASE)),
    ("PQClean", re.compile(r"\bPQCLEAN_[A-Z0-9]+_")),
    ("pq-crystals reference", re.compile(r"\bpqcrystals_(?:kyber|dilithium)")),
    ("Bouncy Castle", re.compile(
        r"\b[Oo]rg\.[Bb]ouncy[Cc]astle\.|getInstance\([^)\n]*,\s*\"BC(?:PQC)?\"\s*\)")),
    ("BoringSSL", re.compile(
        r"\b(?:MLKEM(?:768|1024)|MLDSA(?:44|65|87)|KYBER)_(?:generate_key|encap|decap|"
        r"public_from_private|parse_public_key|marshal_public_key|private_key_from_seed|"
        r"sign|verify)\b")),
    ("OpenSSL 3", re.compile(
        r"\bEVP_PKEY_Q_keygen\b|\bEVP_PKEY_CTX_new_from_name\b|"
        r"\bEVP_(?:KEM|SIGNATURE|KEYMGMT)_fetch\b")),
    # Python's cryptography, by its own module path (ZA-OPRAVYANE row 35).
    ("pyca/cryptography", re.compile(r"\b(?:from|import)\s+cryptography\.hazmat\b")),
]

# The manifest package a provider is installed as, so a version pinned for it can be
# named beside it (row 24a/35). The Go standard library and OpenSSL are not packages
# in a manifest, and are not here.
PROVIDER_PACKAGES = {
    "pyca/cryptography": ("pypi", "cryptography"),
    "Cloudflare CIRCL": ("go", "github.com/cloudflare/circl"),
    "pqcrypto": ("pypi", "pqcrypto"),
}


def _package_key(ecosystem: str, name: str) -> tuple[str, str]:
    return (ecosystem, re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name)


def _join_pins(items: list[dict[str, Any]],
               pins: list[tuple[str, str, str, str, int]]) -> None:
    """The version pinned for a provider's package, from the nearest manifest above the
    file that uses it. Two pins that disagree there, or none, give nothing."""
    by_package: dict[tuple[str, str], list[tuple[str, str, str, str]]] = {}
    for ecosystem, package, version, path, line in pins:
        by_package.setdefault(_package_key(ecosystem, package), []).append(
            (posixpath.dirname(path), package, version, f"{path}:{line}"))
    for item in items:
        package = PROVIDER_PACKAGES.get(item.get("provider", ""))
        if not package:
            continue
        here = posixpath.dirname(item["path"])
        above = [p for p in by_package.get(_package_key(*package), [])
                 if p[0] == "" or here == p[0] or here.startswith(p[0] + "/")]
        if not above:
            continue
        deepest = max(len(p[0]) for p in above)
        nearest = [p for p in above if len(p[0]) == deepest]
        if len({p[2] for p in nearest}) != 1:
            continue
        _, name, version, pinned_in = nearest[0]
        item["provider_pin"] = {"package": name, "version": version, "pinned_in": pinned_in}


def _join_fips(items: list[dict[str, Any]], fips: list[dict[str, Any]]) -> None:
    """Name the FIPS activation beside every finding whose provider is OpenSSL 3."""
    where = [f"{f['path']}:{f['line']}" for f in fips
             if f["activation"] in {"loads_fips_provider", "fips_default_property"}]
    if not where:
        return
    for item in items:
        if item.get("provider") == "OpenSSL 3":
            item["fips_provider_configured_in"] = where


def _attach_providers(findings: list[dict[str, Any]], lines: list[str]) -> None:
    """Name the provider on each finding of a family whose module this file names.

    Collected before imports covered by a call are dropped: the import is usually the
    only line that names the module (`import "crypto/mlkem"`, then `mlkem.Generate...`),
    and dropping it first left the call with nothing to say. A line that names a
    provider itself gets that one; otherwise the file's, if it names exactly one for
    the family. Two in one file and none on the line: absent, not guessed. Comments
    and bans neither give nor get a provider.
    """
    def on(line_no: int) -> list[str]:
        text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
        return [name for name, pattern in PROVIDER_PATTERNS if pattern.search(text)]

    used = [f for f in findings if f.get("evidence_kind") not in {"comment", "ban"}]
    in_file: dict[str, set[str]] = {}
    for f in used:
        in_file.setdefault(f["algorithm"], set()).update(on(f["line"]))
    for f in used:
        own = on(f["line"])
        names = own if own else sorted(in_file.get(f["algorithm"], ()))
        if len(names) == 1:
            f["provider"] = names[0]


_IDENTIFIER_END = re.compile(r"\w*")
# The patterns after row 131's MAC and KDF names: rows 136-143 and the list's tail.
_NAMES_A_PIECE = frozenset(f[2] for f in ALGORITHM_PATTERNS[
    max(i for i, f in enumerate(ALGORITHM_PATTERNS) if components.MAC_OR_KDF_NOTE in f[1]) + 1:])


def scan_source_file(path: Path, rel_path: str,
                     lines: list[str] | None = None,
                     cipher_exclusions: bool = False) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    ext = path.suffix.lower()
    inside_block = False
    inside_doc = ""
    denial_block_indent: int | None = None
    denial_block_calls = False
    signature_lines: set[int] = set()
    for line_no, line in enumerate(lines, start=1):
        was_inside = inside_block or bool(inside_doc)
        spans, inside_block = _comment_spans(line, ext, inside_block)
        if ext in _DOCSTRING_EXT:
            doc_spans, inside_doc = _docstring_spans(line, inside_doc)
            spans = spans + doc_spans
        code = _code_only(line, spans)
        kind = _evidence_kind(line, was_inside, code)
        if (kind == "call" and ext == ".go" and _GO_SIGNATURE.match(code)
                and not _GO_BODY_CODE.search(code)):
            kind = "reference"
            signature_lines.add(line_no)
        indent = len(line) - len(line.lstrip())
        if denial_block_indent is not None and line.strip() and indent <= denial_block_indent:
            denial_block_indent = None
        # The block governs list entries and declarations, never a call. `if (err.code
        # === 'ERR_UNSUPPORTED') {` opened one, and the classical fallback generated
        # inside it read as a ban (ZA-OPRAVYANE row 54).
        in_denial = denial_block_indent is not None and (kind != "call" or denial_block_calls)
        if _opens_a_denial_block(code):
            denial_block_indent = indent
            denial_block_calls = bool(_REJECTION_TEST.search(code))
        # One line, one finding per algorithm. Several patterns can carry the same
        # name -- ECDSA is matched both by its own name and by secp256k1, X448 by
        # its upper and lower case forms -- and counting each pattern separately
        # inflates the headline number by however many ways the line could be
        # spotted, which is not a property of the code being scanned.
        seen_on_line: set[str] = set()
        prose = _prose_spans(code) if ('"' in code or "'" in code) else []
        # The finding a row 136-143 pattern made, with where it matched (see components below).
        by_pattern: dict[str, tuple[dict[str, Any], list[tuple[int, int]]]] = {}
        experimental: list[tuple[int, int]] = []
        blobs = _blob_spans(line)
        searched = _masked(line, blobs)
        lowered = searched.lower() if searched.isascii() else None
        candidates = _candidate_patterns(lowered)
        for algorithm, description, pattern, literals in candidates:
            if algorithm in seen_on_line:
                continue
            # "ML-KEM (Kyber)": the line names the standard and gives its old name.
            if description == KYBER_BY_NAME_ONLY and "ML-KEM" in seen_on_line:
                continue
            if lowered is not None and literals and not any(s in lowered for s in literals):
                continue
            # Every match on the line, not the first: a cipher string can both ban
            # and allow the same family -- "ALL:!ECDH:ECDHE-RSA-AES256" -- and
            # judging the line by its first match would throw the real use away
            # along with the exclusion.
            matches = [m for m in pattern.finditer(searched) if not _in_blob(m.start(), blobs)]
            if description == EXPERIMENTAL_SSH_MLDSA:
                experimental = [(m.start(), m.end()) for m in matches]
            elif algorithm == "ML-DSA":
                # The experimental key type's own "mldsa" is not a second, standard key.
                matches = [m for m in matches
                           if not any(s <= m.start() < e for s, e in experimental)]
            if not matches:
                continue
            if cipher_exclusions and all(_is_excluded(line, m.start()) for m in matches):
                continue
            seen_on_line.add(algorithm)
            # Per match, not per line: a hardened configuration bans one algorithm
            # and enables another on the same line, and reading the whole line as a
            # ban would hide the live one.
            banned = all(_is_banned_here(line, m.start(), in_denial, code) for m in matches)
            # Position decides, not the line. A match that sits inside a comment is
            # comment evidence even where the code around it is a call, and a match
            # in the code is not a comment merely because the line ends in one.
            in_comment = all(_in_spans(m.start(), spans) or _in_spans(m.start(), prose)
                             for m in matches)
            if banned:
                evidence = "ban"
            elif in_comment:
                evidence = "comment"
            else:
                evidence = kind
            item = {
                "path": rel_path,
                "line": line_no,
                "algorithm": algorithm,
                "description": description,
                "excerpt": line.strip()[:200],
                "evidence_kind": evidence,
                # Named, not judged -- see TEST_PATH_RULE. A fixture's RSA is real RSA.
                "in_test_code": in_test_code(rel_path),
            }
            size = key_size_on_line(line) if algorithm == "RSA" else None
            if size:
                item["key_size"] = size
            if description in DNSSEC_CURVES:
                item["curve"], item["key_size"] = DNSSEC_CURVES[description]
            findings.append(item)
            if pattern in _NAMES_A_PIECE:
                by_pattern[algorithm] = (item, [(m.start(), m.end()) for m in matches])
        for family, pos in scan_openssl3_names(line):
            if family in seen_on_line or _in_blob(pos, blobs):
                continue
            seen_on_line.add(family)
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": f"{family} named in an OpenSSL 3 fetch or keygen call",
                "excerpt": line.strip()[:200],
                "evidence_kind": "ban" if _is_banned_here(line, pos, in_denial) else kind,
            })

        for family, pos, name in scan_cose_algorithms(line):
            if family in seen_on_line or _in_blob(pos, blobs):
                continue
            seen_on_line.add(family)
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": f"{family} named by the COSE algorithm identifier {name}",
                "excerpt": line.strip()[:200],
                "evidence_kind": "comment" if _in_spans(pos, spans) else kind,
                "in_test_code": in_test_code(rel_path),
            })
        for family, pos, name in scan_jca_names(line):
            if family in seen_on_line or _in_blob(pos, blobs) or _in_spans(pos, spans):
                continue
            seen_on_line.add(family)
            said = (" (XDH, which generates X25519 unless initialised for X448)"
                    if name.upper() == "XDH" else f" ({name})")
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": f"{family} named in a JCA getInstance call{said}",
                "excerpt": line.strip()[:200],
                "evidence_kind": "ban" if _is_banned_here(line, pos, in_denial, code) else kind,
                "in_test_code": in_test_code(rel_path),
            })

        # Names that stand for a configuration of several algorithms: an OPC UA
        # SecurityPolicy and an AWS load-balancer TLS policy. Each policy's families come
        # from its own table, with the policy named in the evidence.
        named_by_policy = (
            [(fam, pos, opcua.describe(policy)[2]) for policy, pos in opcua.scan(line)
             for fam in opcua.describe(policy)[0]]
            + [(fam, pos, aws_tls.describe(policy)) for policy, pos in aws_tls.scan(line)
               for fam in aws_tls.families(policy)])
        # FortiOS names additional key exchanges by number; configuration only.
        if cipher_exclusions:
            named_by_policy += [(fam, pos, f"{fam} named by FortiOS additional key exchange id")
                                for fam, pos in ike.fortios_addke(line)]
        for family, pos, said in named_by_policy:
            if family in seen_on_line or _in_blob(pos, blobs):
                continue
            seen_on_line.add(family)
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": said,
                "excerpt": line.strip()[:200],
                "evidence_kind": ("comment" if _in_spans(pos, spans) else kind),
                "in_test_code": in_test_code(rel_path),
            })
        # A classical group offered in a TLS group setting is a use of its family, as
        # evidence.tls_groups already says. Lowercase `x448` -- OpenSSL's group name --
        # reached tls_groups and never became a finding, because the X448 rule is
        # case-sensitive to keep Bitcoin's `x448` service flag out (ZA-OPRAVYANE row 83).
        # Not a second family where the line already named the curve (prime256v1 is EC).
        for group in scan_tls_groups(line):
            family = group["family"]
            if family in seen_on_line or (family == "ECDH" and "EC" in seen_on_line):
                continue
            seen_on_line.add(family)
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": f"{family} offered as the TLS group {group['group']}",
                "excerpt": line.strip()[:200],
                "evidence_kind": kind,
                "in_test_code": in_test_code(rel_path),
            })
        # DNSSEC algorithm numbers, in the shape of a DNSKEY, DS or RRSIG record.
        for family, pos, said, curve in dnssec.scan_records(line):
            if family in seen_on_line or _in_blob(pos, blobs):
                continue
            seen_on_line.add(family)
            item = {
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": said,
                "excerpt": line.strip()[:200],
                "evidence_kind": ("comment" if _in_spans(pos, spans) else kind),
                "in_test_code": in_test_code(rel_path),
            }
            if curve in ("P-256", "P-384"):
                item["curve"], item["key_size"] = curve, int(curve[2:])
            findings.append(item)

        # Suite names appear in configuration and in code alike: OpenSSL's headers
        # define them as C constants. The `!` exclusion only means anything in a
        # cipher list, and _is_excluded already requires it.
        for family, pos in scan_cipher_suites(line):
            if family in seen_on_line or _is_excluded(line, pos) or _in_blob(pos, blobs):
                continue
            seen_on_line.add(family)
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": f"{family} named in a cipher suite",
                "excerpt": line.strip()[:200],
                "evidence_kind": "ban" if _is_banned_here(line, pos, in_denial) else kind,
            })
        # A suite whose OpenSSL name carries no key-exchange word is RSA key exchange
        # (AES256-SHA is TLS_RSA_WITH_AES_256_CBC_SHA); see assets.STATIC_RSA_SUITES.
        for suite, pos in static_rsa_positions(line):
            if "RSA" in seen_on_line or _in_blob(pos, blobs) or _in_spans(pos, spans):
                continue
            seen_on_line.add("RSA")
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": "RSA",
                "description": f"RSA key exchange named by the cipher suite {suite}",
                "excerpt": line.strip()[:200],
                "evidence_kind": "ban" if _is_banned_here(line, pos, in_denial) else kind,
                "in_test_code": in_test_code(rel_path),
            })
        # The algorithm as a component of a library's own name: GNUTLS_SIGN_DSA_SHA256,
        # d2i_DSAPublicKey, CKK_RSA, "sha1WithRSAEncryption"; and its OID as a number
        # (ZA-OPRAVYANE rows 132-135; see components.py and oids.py).
        for family, pos, said in components.scan(searched) + oids.scan(searched):
            if _in_blob(pos, blobs):
                continue
            # Rows 136-143 name a piece; rows 131-135 read the identifier whole. Where the
            # piece lies inside it -- curve448 in wc_curve448_make_key, SHA_1 in
            # CKM_SHA_1_HMAC_GENERAL -- the finding stays, with this description, which
            # names the identifier and the MAC or KDF use. The rules before row 131 keep
            # theirs (merge of rows 131-143).
            if family in by_pattern:
                end = _IDENTIFIER_END.match(searched, pos).end()
                item, spans_found = by_pattern[family]
                if all(pos <= a and b <= end for a, b in spans_found):
                    item["description"] = said
                    del by_pattern[family]
                continue
            if family in seen_on_line:
                continue
            seen_on_line.add(family)
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": family,
                "description": said,
                "excerpt": line.strip()[:200],
                "evidence_kind": ("ban" if _is_banned_here(line, pos, in_denial, code) else
                                  "comment" if _in_spans(pos, spans) or _in_spans(pos, prose)
                                  else kind),
                "in_test_code": in_test_code(rel_path),
            })
        if cipher_exclusions and "PPK" not in seen_on_line and PPK_CONFIG_ASSIGN.search(line):
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": "PPK",
                "description": "RFC 8784 postquantum preshared key",
                "excerpt": line.strip()[:200],
            })
    _attach_providers(findings, lines)
    return _drop_signatures_covered_by_a_call(_drop_imports_covered_by_a_call(findings),
                                              signature_lines)


_NOT_A_SETTING = ("#", ";", "//", "--", "/*", "*", "<!--")


def _policy_assets(line: str) -> list[dict[str, Any]]:
    """An OPC UA SecurityPolicy or an AWS TLS policy named on this line, as a configured
    protocol: what it allows and, for OPC UA, the standing the profile database gives it."""
    if line.lstrip().startswith(_NOT_A_SETTING):
        return []
    out: list[dict[str, Any]] = []
    for policy, _pos in opcua.scan(line):
        _families, status, said = opcua.describe(policy)
        out.append({"protocol": "opcua", "version": None, "security_policy": policy,
                    "policy_status": status, "deprecated": status == "deprecated",
                    "basis": "configured_protocol", "description": said})
    for policy, _pos in aws_tls.scan(line):
        out.append(aws_tls.asset(policy))
    return out


def scan_embedded_keys(rel_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """PEM private-key headers in any text file. A key pasted into source code is
    as exposed as one in a Terraform variable."""
    return [
        {"path": rel_path, "line": line_no,
         "description": "Embedded private key material", "excerpt": line.strip()[:200]}
        for line_no, line in enumerate(lines, start=1)
        if _is_embedded_key(lines, line_no - 1)
    ]


def _merge(into: list[dict[str, Any]], extra: list[dict[str, Any]],
           already: list[dict[str, Any]] | None = None) -> None:
    """Append findings not already reported for the same file, line and algorithm.
    A config line such as `algorithm: ECDSA` is matched by both rule sets; it is
    one occurrence, not two."""
    seen = {(f["path"], f["line"], f["algorithm"]) for f in into + (already or [])}
    for f in extra:
        key = (f["path"], f["line"], f["algorithm"])
        if key not in seen:
            seen.add(key)
            into.append(f)


def _link_signing_keys(ci_findings: list[dict[str, Any]],
                       key_files: dict[str, list[str]]) -> None:
    """Join each signing step to the key it names, where the scan read that file.

    The path is read as the step writes it, from the root of the tree and from the
    script's own directory. A path the step names that is not in the tree is said to be
    absent; a path written with a variable is left alone."""
    for step in ci_findings:
        # The first value that is not a flag: in `openssl cms -sign -in m -signer c
        # -inkey k` the bare -sign takes no argument, and the word after it is `-in`.
        values = [m.group(1) or m.group(2)
                  for m in _SIGNING_KEY_ARG.finditer(step.get("excerpt", ""))]
        written = next((v.strip("\"'") for v in values if not v.startswith("-")), "")
        if not written or "$" in written or "{" in written or "%" in written:
            continue
        here = posixpath.dirname(step["path"])
        candidates = [posixpath.normpath(written),
                      posixpath.normpath(posixpath.join(here, written))]
        found = next((c for c in candidates if c in key_files), None)
        if found:
            step["signing_key"] = {"path": found, "in_tree": True,
                                   "algorithms": key_files[found]}
        else:
            step["signing_key"] = {"path": posixpath.normpath(written), "in_tree": False}


def scan_ci_file(path: Path, rel_path: str,
                 lines: list[str] | None = None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        for command_type, pattern in SIGNING_COMMAND_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "path": rel_path,
                    "line": line_no,
                    "command_type": command_type,
                    "excerpt": line.strip()[:200],
                })
    return findings


def scan_iac_file(path: Path, rel_path: str,
                  lines: list[str] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Returns (algorithm_findings, embedded_key_findings) for a Terraform/Kubernetes IaC file."""
    algorithm_findings: list[dict[str, Any]] = []
    embedded_key_findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    for line_no, line in enumerate(lines, start=1):
        for algorithm, description, pattern in IAC_ALGORITHM_PATTERNS:
            if pattern.search(line):
                algorithm_findings.append({
                    "path": rel_path,
                    "line": line_no,
                    "algorithm": algorithm,
                    "description": description,
                    "excerpt": line.strip()[:200],
                })
        if _is_embedded_key(lines, line_no - 1):
            embedded_key_findings.append({
                "path": rel_path,
                "line": line_no,
                "description": "Embedded private key material",
                "excerpt": line.strip()[:200],
            })
    return algorithm_findings, embedded_key_findings


# Who owns a place, as the repository's CODEOWNERS says (ZA-OPRAVYANE row 94, Dhiraj S.,
# 23.10.2026: "one CBOM, many owners ... the device teams own their rows"). GitHub reads the
# first of .github/CODEOWNERS, CODEOWNERS, docs/CODEOWNERS; the last matching line wins; the
# patterns follow most of gitignore's rules (GitHub Docs, "About code owners", read
# 23.10.2026). GitLab's .gitlab/CODEOWNERS is read last; its [Section] headers are skipped.
# An owner is put on each place -- an occurrence, not a component -- with the line that
# said it: an assumption from that file, not a fact about who runs the code.
CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS",
                        ".gitlab/CODEOWNERS")


def _codeowners_pattern(pattern: str) -> re.Pattern:
    """A CODEOWNERS pattern as a regex over a file's path from the root.

    gitignore's rules: a slash at the start or in the middle anchors the pattern at the
    root, otherwise it matches at any depth; a trailing slash matches a directory and
    everything beneath it; `*` stays within one path segment and `**` crosses them. A
    pattern that names a directory owns what is beneath it, except where its last
    segment is a wildcard: GitHub's own example says `docs/*` matches
    docs/getting-started.md and not docs/build-app/troubleshooting.md.
    """
    directory = pattern.endswith("/")
    body = pattern.strip("/")
    anchored = pattern.startswith("/") or "/" in body
    out, i = "", 0
    while i < len(body):
        if body.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif body.startswith("/**", i) and i + 3 == len(body):
            out, i = out + "/.*", i + 3
        elif body[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif body[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(body[i]), i + 1
    last = body.rsplit("/", 1)[-1]
    tail = "/.*" if directory else ("" if ("*" in last or "?" in last) else "(?:/.*)?")
    return re.compile(("^" if anchored else "^(?:.*/)?") + out + tail + "$")


def _read_codeowners(path: str, lines: list[str]) -> list[tuple[re.Pattern, list[str], str]]:
    rules: list[tuple[re.Pattern, list[str], str]] = []
    for number, line in enumerate(lines, 1):
        text = line.split(" #", 1)[0].strip()
        if not text or text.startswith(("#", "[", "^[")):
            continue
        pattern, *owners = text.split()
        rules.append((_codeowners_pattern(pattern), owners, f"{path}:{number}"))
    return rules


def _attach_owners(items: list[dict[str, Any]],
                   rules: list[tuple[re.Pattern, list[str], str]]) -> None:
    """The owners of each item's path by the last matching CODEOWNERS line. A matching line
    that names no owner leaves the place unowned, as GitHub reads it."""
    for item in items:
        path = item.get("path")
        if not isinstance(path, str):
            continue
        match = next((rule for rule in reversed(rules) if rule[0].match(path)), None)
        if match and match[1]:
            item["owners"] = list(match[1])
            item["owners_source"] = match[2]


def _sizes_by_algorithm(findings: list[dict[str, Any]]) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for f in findings:
        if isinstance(f.get("key_size"), int):
            out.setdefault(f["algorithm"], []).append(f["key_size"])
    return out


def scan_repo(repo_path: Path, exclude: Path | None = None) -> dict[str, Any]:
    """`exclude` is a single path left out of the scan and named in the scope.

    The one caller that needs it is the CLI writing its own result inside the
    directory it just scanned: the second run then reads the first run's output,
    reports the findings quoted in it, and produces a different corpus digest for
    an unchanged tree. An independent analysis ran exactly that and saw one file
    become two. Excluding the same path on every run makes the runs comparable
    again, and the scope says the file was left out rather than not noticed.
    """
    source_findings: list[dict[str, Any]] = []
    ci_findings: list[dict[str, Any]] = []
    iac_findings: list[dict[str, Any]] = []
    embedded_key_findings: list[dict[str, Any]] = []
    files_scanned = {"source": 0, "ci_config": 0, "iac": 0, "config": 0, "certificate": 0}

    unreadable: list[str] = []
    # Claimed file types that were opened and gave up nothing nameable.
    undecoded: list[str] = []
    # What this run actually read, and what it deliberately did not. A commit does
    # not identify either: two subdirectories of one commit are different corpora,
    # and a git-ignored file the scan reads leaves the tree reporting clean. So the
    # identity of the corpus is a digest of its contents -- an external audit of
    # 0.9.0 found all three ways the commit alone got this wrong.
    content_parts: list[str] = []
    # Assets present without an algorithm being written down. Separate from
    # the findings above because everything downstream keys on `algorithm`,
    # and these deliberately have none.
    protocol_findings: list[dict[str, Any]] = []
    dependency_findings: list[dict[str, Any]] = []
    # Classical TLS groups offered on their own beside the rest; see assets.scan_tls_groups.
    tls_group_findings: list[dict[str, Any]] = []
    # RSA key exchange enabled in a cipher-suite setting; see assets.scan_static_rsa_kex.
    static_rsa_findings: list[dict[str, Any]] = []
    # Hybrid groups in a TLS group setting, and the TLS server images the tree pins, so
    # the two can be put side by side; see assets.library_support.
    hybrid_places: list[tuple[str, int, str]] = []
    pinned_images: list[dict[str, Any]] = []
    # The same for SSH: classical KexAlgorithms offered beside a hybrid; see assets.scan_ssh_kex.
    ssh_kex_findings: list[dict[str, Any]] = []
    # EC public keys whose private scalar is small enough to read off; see
    # certificates.small_scalar_keys.
    weak_key_findings: list[dict[str, Any]] = []
    # Key and certificate files read, by path, with the families found in each, so a
    # signing step can be joined to the key it names (_link_signing_keys).
    key_files: dict[str, list[str]] = {}
    # OpenSSL's FIPS provider brought in by an openssl.cnf; see assets.scan_openssl_fips.
    fips_findings: list[dict[str, Any]] = []
    # Packages pinned to one version: (ecosystem, package, version, manifest, line).
    pins: list[tuple[str, str, str, str, int]] = []
    # The denominator. files_scanned says how much was read; on its own it does not
    # say how much there was. A file skipped because the tool does not claim its
    # type is not a failure, but leaving it uncounted turns coverage into a number
    # with no base -- which is the thing this scanner exists to refuse.
    files_present = 0
    skipped_kinds: dict[str, int] = {}
    skipped_files: list[str] = []
    present_kinds: dict[str, int] = {}
    excluded_dir_counts: dict[str, int] = {}

    walk_problems: list[tuple[str, str]] = []
    unreadable_dirs: list[str] = []
    left_out: list[str] = []
    # Every file actually read, by path. A count says how much was read; only the
    # names let a later run tell a file that was fixed from a file that is gone.
    files_read: list[str] = []
    # CODEOWNERS files read, by location (see CODEOWNERS_LOCATIONS).
    codeowners: dict[str, list[str]] = {}
    resolved_exclude = None
    if exclude is not None:
        try:
            resolved_exclude = Path(exclude).expanduser().resolve()
        except OSError:
            resolved_exclude = None
    for path in iter_repo_files(repo_path, excluded_dir_counts, walk_problems):
        if resolved_exclude is not None:
            try:
                if path.resolve() == resolved_exclude:
                    left_out.append(str(path.relative_to(repo_path)))
                    continue
            except (OSError, ValueError):
                pass
        files_present += 1
        # The composition of the denominator, not just its size. A coverage figure
        # is a property of the tool crossed with what the corpus is made of: the
        # same scanner over a tree of Go and over a tree of Ruby reports different
        # numbers with nothing in the scanner changing. Size makes a figure
        # reproducible; composition is what makes it interpretable.
        kind = path.suffix.lower() or "(no extension)"
        present_kinds[kind] = present_kinds.get(kind, 0) + 1
        rel_path = display_path(path.relative_to(repo_path).as_posix())
        is_ci = is_ci_config_file(path, repo_path)
        # Every comparison is lowercased, and the reason is a defect this line
        # produced. OpenSSL carries thirteen files with upper-case extensions --
        # twelve .H and one .PL -- which failed a case-sensitive `in` against a
        # lower-case set, were skipped, and were then reported under
        # `path.suffix.lower()` as .h and .pl: types this tool does claim. So the
        # declared boundary and the real one differed, the count said the tool
        # does not claim these, and the lower-casing in the report concealed the
        # case-sensitivity in the match.
        claimed = (is_ci or rel_path in CODEOWNERS_LOCATIONS
                   or path.suffix.lower() in IAC_EXTENSIONS
                   or path.suffix.lower() in SOURCE_EXTENSIONS
                   or path.suffix.lower() in {".yaml", ".yml"} or is_config_file(path)
                   or is_certificate_file(path) or is_manifest(path))
        # `.xml` and `.json5` are read only when they name an OPC UA SecurityPolicy: a
        # .NET `*.Config.xml` and an open62541 `*.json5` are where those stacks declare
        # theirs, and every other XML stays the declared boundary it was. Read once,
        # here, and the same bytes are used below.
        sniffed = None
        if not claimed and path.suffix.lower() in opcua.SNIFF_EXTENSIONS:
            sniffed = _read_file(path, repo_path)
            claimed = sniffed is not None and opcua.SNIFF_MARKER in sniffed[0]
        # Only a file no declared type claims is peeked at for key material; a .py or
        # a .tf that happens to contain a PEM block stays source and infrastructure.
        peeked_key = False if claimed else looks_like_key_file(path)
        if not (claimed or peeked_key):
            kind = path.suffix.lower() or "(no extension)"
            skipped_kinds[kind] = skipped_kinds.get(kind, 0) + 1
            skipped_files.append(rel_path)
            # Not read, so not hashed: its size is what is known about it without
            # opening a file this tool has declared it does not claim.
            try:
                size = path.stat().st_size
            except OSError:
                size = -1
            content_parts.append(f"{rel_path}\0skipped:{size}")
            continue

        # Read once, here: classification and scanning must see the same content, and a
        # file that cannot be read has to leave a mark rather than pass as scanned-clean.
        read = sniffed if sniffed is not None else _read_file(path, repo_path)
        if read is None:
            unreadable.append(rel_path)
            content_parts.append(f"{rel_path}\0unread")
            continue
        raw, lines = read
        # The digest is over the BYTES this read returned. Over the decoded text it
        # was not identity at all: `decode(errors="ignore")` drops what it cannot
        # read, so two files differing exactly where the scanner looks -- an object
        # identifier inside a DER blob -- produced the same digest while producing
        # different findings. No extra I/O; these are the bytes already in hand.
        content_parts.append(
            rel_path + "\0" + hashlib.sha256(raw).hexdigest())
        files_read.append(rel_path)

        for number, text_line in enumerate(lines, 1):
            for asset in scan_protocols(text_line):
                asset["path"] = rel_path
                asset["line"] = number
                asset["excerpt"] = text_line.strip()[:200]
                protocol_findings.append(asset)
            for group in scan_tls_groups(text_line):
                group["path"] = rel_path
                group["line"] = number
                group["in_test_code"] = in_test_code(rel_path)
                tls_group_findings.append(group)
            hybrid_places.extend((rel_path, number, g) for g in scan_hybrid_groups(text_line))
            for item in scan_static_rsa_kex(text_line):
                item["path"] = rel_path
                item["line"] = number
                item["in_test_code"] = in_test_code(rel_path)
                static_rsa_findings.append(item)
            for kex in scan_ssh_kex(text_line):
                kex["path"] = rel_path
                kex["line"] = number
                kex["in_test_code"] = in_test_code(rel_path)
                ssh_kex_findings.append(kex)
            for asset in _policy_assets(text_line):
                asset.update(path=rel_path, line=number, excerpt=text_line.strip()[:200])
                protocol_findings.append(asset)
            if not text_line.lstrip().startswith(_NOT_A_SETTING):
                for asset in dnssec.unnamed_records(text_line):
                    asset.update(path=rel_path, line=number, excerpt=text_line.strip()[:200])
                    protocol_findings.append(asset)
        # A load-balancer listener that serves HTTPS or TLS and names no policy gets
        # the provider's: said as a default, with the reason, on the resource.
        for number in aws_tls.listeners_without_policy(path.suffix.lower(), lines):
            excerpt = lines[number - 1].strip()[:200]
            for family in aws_tls.families(aws_tls.DEFAULT_POLICY):
                iac_findings.append({
                    "path": rel_path, "line": number, "algorithm": family,
                    "description": aws_tls.describe(aws_tls.DEFAULT_POLICY, default=True),
                    "excerpt": excerpt, "evidence_kind": "default",
                    "basis": "provider_default",
                    "in_test_code": in_test_code(rel_path),
                })
            protocol_findings.append({**aws_tls.asset(aws_tls.DEFAULT_POLICY, default=True),
                                      "path": rel_path, "line": number, "excerpt": excerpt})
        if path.suffix.lower() in {".yaml", ".yml"}:
            pinned_images.extend(image_pins(rel_path, lines))
        if is_manifest(path):
            dependency_findings.extend(scan_manifest(path, rel_path, lines))
            pins.extend((eco, pkg, ver, rel_path, n)
                        for eco, pkg, ver, n in pinned_versions(path, lines))

        if rel_path in CODEOWNERS_LOCATIONS:
            # Read for who owns what, not matched for algorithms: its paths name
            # directories (`/crypto/rsa/`), not uses.
            files_scanned["config"] += 1
            codeowners[rel_path] = lines
        elif path.name in LOCKFILES:
            # A lockfile is read for its packages (dependency_findings, above), by its
            # structure. Its text is package names, versions and hashes: matching it as
            # source made `ecdsa-sig-formatter` an "ECDSA usage" beside the dependencies row
            # that already says "declared, not observed" (ZA-OPRAVYANE row 88).
            files_scanned["config"] += 1
        elif is_certificate_file(path) or peeked_key:
            # Certificates and keys are read as bytes, not lines: a .der carries no
            # lines at all, and a .pem that fails to decode must still be counted.
            files_scanned["certificate"] += 1
            algo_findings, key_findings = scan_certificate_file(path, rel_path, raw)
            source_findings.extend(algo_findings)
            key_files[rel_path] = sorted({f["algorithm"] for f in algo_findings})
            embedded_key_findings.extend(key_findings)
            for weak in small_scalar_keys(rel_path, raw):
                weak["in_test_code"] = in_test_code(rel_path)
                weak_key_findings.append(weak)
            if is_undecoded(algo_findings, key_findings):
                undecoded.append(rel_path)
        elif is_ci:
            files_scanned["ci_config"] += 1
            ci_findings.extend(scan_ci_file(path, rel_path, lines))
            # A pipeline also names algorithms (`openssl req -newkey rsa:2048`).
            source_findings.extend(
                scan_source_file(path, rel_path, lines, cipher_exclusions=True))
        elif is_iac_file(path, repo_path, lines):
            files_scanned["iac"] += 1
            algo_findings, key_findings = scan_iac_file(path, rel_path, lines)
            # Terraform and manifests also carry Ed25519 keys, ML-DSA key specs and
            # embedded TLS configuration; the two IaC rules alone missed them.
            _merge(algo_findings,
                   scan_source_file(path, rel_path, lines, cipher_exclusions=True))
            iac_findings.extend(algo_findings)
            embedded_key_findings.extend(key_findings)
        elif path.suffix.lower() in SOURCE_EXTENSIONS:
            files_scanned["source"] += 1
            source_findings.extend(scan_source_file(path, rel_path, lines))
            embedded_key_findings.extend(scan_embedded_keys(rel_path, lines))
            # A release script signs the same way a pipeline does, and the pipeline
            # often only calls it (ZA-OPRAVYANE row 34).
            if path.suffix.lower() == ".sh":
                ci_findings.extend(scan_ci_file(path, rel_path, lines))
        else:
            # Configuration: the extensions above, and any YAML that is not a
            # manifest. This branch exists so that nothing can be opened and then
            # dropped: reaching here used to fall off the end of the loop, leaving
            # a file that was read, counted nowhere, and listed nowhere -- which is
            # the one thing this scanner is not allowed to do.
            #
            # Both pattern sets run, because a config file carries both shapes: a
            # cipher list reads like source, a key algorithm declaration reads like
            # infrastructure.
            files_scanned["config"] += 1
            src = scan_source_file(path, rel_path, lines, cipher_exclusions=True)
            source_findings.extend(src)
            # An IKE configuration carrying a post-quantum algorithm: name its
            # fragmentation setting (see ike.py).
            post_quantum: dict[str, int] = {}
            for item in src:
                if (item["algorithm"] in _PQC_SCHEMES
                        and item.get("evidence_kind") not in {"comment", "ban"}):
                    post_quantum.setdefault(item["algorithm"], item["line"])
            for asset in ike.scan(path.name, lines, post_quantum):
                asset["path"] = rel_path
                protocol_findings.append(asset)
            if path.suffix.lower() == ".cnf":
                fips_findings.extend(scan_openssl_fips(rel_path, lines))
            # HAProxy listeners and unverified backends (HAProxy, nginx): see
            # assets.scan_tls_listeners.
            protocol_findings.extend(scan_tls_listeners(rel_path, lines))
            # The DNS UDP size budget a BIND configuration sets (see dnssec.py).
            for asset in dnssec.udp_sizes(lines):
                asset["path"] = rel_path
                protocol_findings.append(asset)
            algo_findings, key_findings = scan_iac_file(path, rel_path, lines)
            _merge(iac_findings, algo_findings, already=src)
            embedded_key_findings.extend(key_findings)

    # Entries the walk could see but not read count as present and unreadable, so the
    # invariant still holds. Directories it could not enter have an unknown number of
    # files in them; they are listed separately and the scan cannot claim to account
    # for every file.
    symlinks: list[dict[str, str]] = []
    for kind, rel in walk_problems:
        if kind == "file":
            files_present += 1
            present_kinds["(unreadable entry)"] = present_kinds.get("(unreadable entry)", 0) + 1
            unreadable.append(rel)
        elif kind in {"symlink", "symlink_dir"}:
            # A linked file is one of the files present -- it was seen -- and it was
            # not read, so it keeps the identity present = scanned + unreadable +
            # skipped + links. A linked directory holds an unknown number of files,
            # exactly like one that could not be entered, so it is not counted.
            is_dir = kind == "symlink_dir"
            if not is_dir:
                files_present += 1
                present_kinds["(symlink)"] = present_kinds.get("(symlink)", 0) + 1
            symlinks.append({
                "path": rel + ("/" if is_dir else ""),
                "kind": "directory" if is_dir else "file",
                "target": _link_target(repo_path, rel),
                "reason": "symlink_not_followed",
            })
        else:
            unreadable_dirs.append(rel + "/")
        content_parts.append(f"{rel}\0{kind}")

    _link_signing_keys(ci_findings, key_files)
    owners_file = next((p for p in CODEOWNERS_LOCATIONS if p in codeowners), None)
    if owners_file:
        _attach_owners(
            source_findings + ci_findings + iac_findings + embedded_key_findings
            + protocol_findings + dependency_findings + tls_group_findings
            + static_rsa_findings + ssh_kex_findings + weak_key_findings,
            _read_codeowners(owners_file, codeowners[owners_file]))
    _join_pins(source_findings + iac_findings, pins)
    _join_fips(source_findings + iac_findings, fips_findings)
    return {
        "files_scanned": files_scanned,
        "files_read": sorted(files_read),
        # The CODEOWNERS file the owners on the evidence come from, or None.
        "codeowners": ({"path": owners_file,
                        "meaning": "owners on evidence items are this file's last matching "
                                   "line for the item's path: an assumption, not a fact"}
                       if owners_file else None),
        # Directories that could not be entered or listed; their files are unknown.
        "unreadable_directories": sorted(set(unreadable_dirs)),
        # Seen, not followed. Where the target sits is stated; the target path
        # itself is only given when it is inside the scanned directory, because
        # printing an outside path leaks the same thing reading it would.
        "symlinks_not_followed": sorted(symlinks, key=lambda entry: entry["path"]),
        # One value standing for everything above: the files read and their content,
        # the files not read and their size, and the entries skipped with the reason.
        # Two runs with the same digest read the same corpus, whatever it is called
        # and wherever it sits.
        "corpus_digest": "sha256:" + hashlib.sha256(
            "\n".join(sorted(content_parts)).encode("utf-8", "surrogatepass")).hexdigest(),
        # Files found under the path, excluding the vendored and build directories in
        # EXCLUDED_DIRS. present = scanned + unreadable + skipped, always.
        "files_present": files_present,
        "files_present_by_extension": present_kinds,
        # Not read because this tool does not claim the file type, counted by
        # extension. Not a gap in the scan -- a boundary of it, stated rather than
        # left for the reader to assume away.
        "files_left_out": left_out,
        # The same files by name. A count alone is not an accounting: a reader
        # given only "379 by extension" cannot ask about any one of them.
        "files_skipped": sorted(skipped_files),
        "files_skipped_by_type": dict(
            sorted(skipped_kinds.items(), key=lambda kv: kv[1], reverse=True)
        ),
        # Attempted and NOT read. files_scanned counts only files actually read, so
        # "0 findings" can be checked against a denominator instead of trusted.
        "unreadable_files": unreadable,
        "claimed_but_not_decoded": undecoded,
        "protocol_findings": protocol_findings,
        "dependency_findings": dependency_findings,
        "tls_group_findings": tls_group_findings,
        "static_rsa_kex_findings": static_rsa_findings,
        "library_support_findings": library_support(pinned_images, hybrid_places, files_read),
        "ssh_kex_findings": ssh_kex_findings,
        "weak_key_findings": weak_key_findings,
        "fips_provider_findings": fips_findings,
        # Files removed by EXCLUDED_DIRS before files_present counted anything,
        # by the directory name that removed them. Counted so the denominator
        # can state what it left out instead of leaving it in the source.
        "files_excluded_by_dir": dict(
            sorted(excluded_dir_counts.items(), key=lambda kv: kv[1], reverse=True)
        ),
        "source_code_findings": source_findings,
        "ci_pipeline_findings": ci_findings,
        "iac_findings": iac_findings,
        "embedded_key_findings": embedded_key_findings,
        # A family named only in comments is not a family the code uses. It stays
        # in the evidence, marked as a comment, because a comment saying "we must
        # drop ECDSA" is worth reading -- but it does not put ECDSA in the
        # inventory or make the verdict quantum-vulnerable. Measured: the nearest
        # rival strips comments before matching, and this scanner's precision on
        # an independent corpus was 0.542 against its 0.93.
        "detected_algorithms": sorted(_families_in_use(source_findings + iac_findings)),
        # Named, and named apart: what the repository talks about or forbids but
        # does not do. A comment and a ban are different facts and both belong
        # here rather than in the inventory.
        # Test code, counted apart and never dropped. The rule is a path convention,
        # so it travels with the numbers it produced -- a reader who disagrees with the
        # rule can see exactly what it caught. Measured on certbot: 33 of 42
        # scanner-vs-classifier disagreements sat here, and no external corpus can
        # settle whether a fixture is an asset, because both are pure fixtures.
        "test_code": {
            "rule": TEST_PATH_RULE,
            "meaning": "whether the finding sits in test code; named, not excluded",
            "findings_in_test_code": sum(
                1 for f in source_findings + iac_findings if f.get("in_test_code")),
            "findings_in_other_code": sum(
                1 for f in source_findings + iac_findings if not f.get("in_test_code")),
        },
        "named_but_not_used": sorted(
            _families_named(source_findings + iac_findings)
            - _families_in_use(source_findings + iac_findings)),
        # The smallest size seen for a family, so a weak key anywhere is visible. A
        # size is a property of the key, not of the name, and without it every RSA
        # reads the same whether it is 1024 or 4096 bits.
        #
        # Measured over usable evidence only, the same filter the inventory uses.
        # An external retest of 0.11.0 found a file whose comment mentioned an old
        # 1024-bit example above a real 4096-bit key: the family was correctly kept
        # out of the comment's reach and the size was not, so the scan reported a
        # weak key that did not exist. Evidence excluded from the finding cannot be
        # allowed back in to grade it.
        "algorithm_key_sizes": {
            alg: min(sizes)
            for alg, sizes in _sizes_by_algorithm(
                [f for f in source_findings + iac_findings
                 if f.get("evidence_kind") not in {"comment", "ban"}]).items()
        },
        # Every size seen, not only the smallest. The minimum above answers "is
        # anything weak here"; this answers "which sizes are in use", and they are
        # different questions. The second one became the operational one when
        # RSA-896 was factored on a data-centre fleet: an auditor asking where
        # RSA-1024 still runs cannot be answered by a figure that reports the
        # minimum, nor by a family name with no size at all.
        #
        # Same filter as above, for the same reason: a size that was excluded from
        # the finding cannot come back in to describe it.
        "algorithm_key_sizes_observed": {
            alg: sorted(set(sizes))
            for alg, sizes in _sizes_by_algorithm(
                [f for f in source_findings + iac_findings
                 if f.get("evidence_kind") not in {"comment", "ban"}]).items()
        },
    }
