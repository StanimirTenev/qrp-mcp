"""Detection patterns for classical crypto usage and CI signing commands."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

from .assets import is_manifest, scan_manifest, scan_protocols
from .certificates import (is_certificate_file, is_undecoded, looks_like_key_file,
                           scan_certificate_file)

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
                     ".hcl", ".json"}

# The same files that carry no extension at all.
CONFIG_FILENAMES = {"sshd_config", "ssh_config", "ssl.conf", "krb5.conf",
                    # The JDK's own policy file: it names algorithms, and
                    # jdk.tls.disabledAlgorithms is where a Java estate records
                    # what it has switched off.
                    "java.security", "java.policy",
                    # Build files list the algorithm sources a tree compiles.
                    "Makefile", "makefile", "GNUmakefile", "CMakeLists.txt",
                    # SSH key inventories: the key type is named on every line.
                    "known_hosts", "authorized_keys"}

# (algorithm, description, compiled regex matched against a single source line)
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
        r"\bgenerateKeyPair(?:Sync)?\(\s*[\"']rsa[\"']|"
        r"\bcreate(?:Sign|Verify)\(\s*[\"'](?:RSA-)?SHA\d+[\"']|"
        r"\bcreate(?:Sign|Verify)\(\s*[\"']RSA[-\w]*[\"']|"
        r"\bRsaPrivateKey\b|\bRsaPublicKey\b|"
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
        r"\bEVP_PKEY_RSA\b|\bEVP_RSA_gen\b|\bPEM_read_\w*RSA\w*|\bd2i_RSA\w*|"
        # .NET / PowerShell: a Windows estate keeps its certificate handling here.
        r"\bRSACryptoServiceProvider\b|\bRSACng\b|\bRSAOpenSsl\b|\bRSA\.Create\b|"
        r"\bRSACertificateExtensions\b|\bGetRSAPublicKey\b|\bGetRSAPrivateKey\b|"
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
        r"(?<![A-Za-z-])dsa\.(?:GenerateKey|GenerateParameters|Sign|Verify)\b|"
        r"OpenSSL::PKey::DSA\b|\w*withDSA\b|\bDsa::generate\b|\bDSA\.generate\b|"
        r"\bCKM_DSA_\w+|"
        r"KeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']|openssl\s+dsaparam|"
        r"\bDSA_new\b|\bDSA_generate_key\w*|\bEVP_PKEY_DSA\b|"
        r"\bDSACryptoServiceProvider\b|\bDSACng\b|"
        r"(?<![A-Za-z])ssh-dss(?![A-Za-z])",
        re.IGNORECASE,
    )),
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
        # Ruby, the Rust openssl crate, and BouncyCastle -- the vocabulary a rival
        # reads and this scanner did not. Fix #9 of the September comparison.
        r"\bdh\.compute_key\b|\bDh::generate_params\b|\bDh::from_params\b|"
        r"\bDHBasicAgreement\b|\bDHKeyPairGenerator\b|\bDHParametersGenerator\b|"
        # IKE modp groups: modp2048 is group 14, and Shor breaks it like any
        # finite-field Diffie-Hellman.
        r"(?<![A-Za-z])modp(?:1024|1536|2048|3072|4096|6144|8192)(?![0-9])",
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
        r"\bMD5(?:Init|Update|Final|Transform)\b|<md5\.h>|\bmd5\.(?:New|Sum)\b",
        re.IGNORECASE,
    )),
    ("SHA1", "SHA-1 usage", re.compile(
        r"hashlib\.sha1|crypto/sha1|MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']|"
        r"createHash\(\s*[\"']sha1[\"']|openssl\s+dgst\s+-sha1|"
        r"\bSHA1_Init\b|\bSHA1_Update\b|\bEVP_sha1\b|"
        r"\bSHA1CryptoServiceProvider\b|\bSHA1Managed\b|\bSHA1\.Create\b|"
        r"hashes\.SHA1\s*\(|hashlib\.new\(\s*[\"']sha-?1[\"']|"
        r"\bSHA1(?:Init|Update|Final|Transform)\b|<sha1\.h>|\bsha1\.(?:New|Sum)\b",
        re.IGNORECASE,
    )),
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
    ("RSA", "RSA named as a JOSE/JWT algorithm", re.compile(
        r"[\"'](?:RS|PS)(?:256|384|512)[\"']|"
        r"\bSigningMethod(?:RS|PS)(?:256|384|512)\b|\bAlgorithm::(?:RS|PS)(?:256|384|512)\b|"
        r"[\"']?RSA-OAEP(?:-(?:256|384|512))?[\"']?|[\"']RSA1_5[\"']",
    )),
    ("ECDSA", "ECDSA named as a JOSE/JWT algorithm", re.compile(
        r"[\"']ES(?:256|384|512)K?[\"']|"
        r"\bSigningMethodES(?:256|384|512)\b|\bAlgorithm::ES(?:256|384|512)\b",
    )),
    ("3DES", "3DES (triple DES) usage", re.compile(
        # No word boundaries: the real spellings are glued into identifiers
        # (OPT_3DES_WRAP, OIDEncryptionAlgorithmDESEDE3CBC, NewTripleDESCipher).
        r"3DES|DES[-_]?EDE3?|TripleDES|EVP_des_ede3\w*",
        re.IGNORECASE,
    )),
    ("DES", "DES usage", re.compile(
        # Single DES only: the triple-DES spellings have their own rule above, and
        # the EVP_des_ede* family (two- and three-key) must not fall in here.
        r"crypto/des\b|\bDES_set_key\w*|\bDES_ecb_encrypt\b|"
        r"\bEVP_des_(?!ede)\w+|\bDESCryptoServiceProvider\b|\bdes\.NewCipher\b", re.IGNORECASE,
    )),
    # Blockchain / wallet signing. These map onto the same classical primitives -- a
    # secp256k1 signature is ECDSA, and Shor breaks it like any other elliptic curve.
    ("ECDSA", "secp256k1 (ECDSA) usage", re.compile(
        r"secp256k1|\bbtcec\b|bitcoinjs-lib|\bECPair\b|"
        r"\becrecover\s*\(|ECDSA\.recover|\bethers\b|\bweb3\b|"
        r"eth_sign|personal_sign|signTypedData",
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
        r"(?<![A-Za-z])x25519|(?<![A-Za-z])curve25519", re.IGNORECASE,
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
        # .NET's elliptic-curve Diffie-Hellman; it was filed under finite-field DH.
        r"\bECDiffieHellman(?:Cng|OpenSsl)?\b",
        re.IGNORECASE,
    )),
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
        r"\bed25519\b|tweetnacl|\bnacl\.sign\b|@solana/web3\.js|solana_program::|"
        r"sodium_crypto_sign|\bEd25519(?:Signer|KeyPairGenerator)\b",
        re.IGNORECASE,
    )),
    ("Schnorr", "Schnorr signature usage", re.compile(
        r"\bschnorr\b|\bbip340\b|\btaproot\b", re.IGNORECASE,
    )),
    ("BLS", "BLS signature usage", re.compile(
        r"bls12[-_]?381|\bblst\b|@chainsafe/bls|\bbls_sig\b", re.IGNORECASE,
    )),
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
    ("ML-KEM", "ML-KEM (Kyber) usage", re.compile(
        r"(?<![A-Za-z])ml[-_]?kem|(?<![A-Za-z])kyber(?![A-Za-z])|pqcrystals[-_]?kyber|crypto_kem_kyber", re.IGNORECASE,
    )),
    ("ML-DSA", "ML-DSA (Dilithium) usage", re.compile(
        r"(?<![A-Za-z])ml[-_]?dsa|(?<![A-Za-z])dilithium|pqcrystals[-_]?dilithium", re.IGNORECASE,
    )),
    ("SLH-DSA", "SLH-DSA (SPHINCS+) usage", re.compile(
        r"(?<![A-Za-z])slh[-_]?dsa|(?<![A-Za-z])sphincs", re.IGNORECASE,
    )),
    ("Falcon", "Falcon (FN-DSA) usage", re.compile(
        r"(?<![A-Za-z])falcon[-_]?(512|1024)|(?<![A-Za-z])fn[-_]?dsa", re.IGNORECASE,
    )),
    ("Classic McEliece", "Classic McEliece usage", re.compile(
        r"(?<![A-Za-z])classic[-_ ]?mceliece|(?<![A-Za-z])mceliece", re.IGNORECASE,
    )),
    # A trailing guard as well as a leading one: "ntrunc" (n truncated) is a
    # variable in Bitcoin Core and matched 22 times. The real parameter sets are
    # spelled ntruhps2048509 / ntruhrss701 / ntru_prime, so they are named rather
    # than left to a boundary that cannot tell them from an ordinary word.
    ("NTRU", "NTRU usage", re.compile(
        r"(?<![A-Za-z])ntru(?:hps|hrss|prime|[-_\d]|(?![A-Za-z]))|"
        r"(?<![A-Za-z])sntrup\d+",
        re.IGNORECASE,
    )),
    ("BIKE", "BIKE usage", re.compile(r"(?<![A-Za-z])bike[-_]?l[135]", re.IGNORECASE)),
    ("HQC", "HQC usage", re.compile(r"(?<![A-Za-z])hqc[-_]?(128|192|256)", re.IGNORECASE)),
    ("XMSS", "XMSS usage", re.compile(r"(?<![A-Za-z])xmss", re.IGNORECASE)),
    # Stateful hash-based, SP 800-208. CNSA 2.0 requires LMS or XMSS for firmware
    # and code signing, so a firmware pipeline that had complied scanned as empty.
    ("HSS/LMS", "LMS/HSS stateful signature usage", re.compile(
        r"(?<![A-Za-z])lms[-_]?sha|(?<![A-Za-z])hss[-_/]?lms|(?<![A-Za-z])lms[-_]?(sha256|shake)|"
        r"(?<![A-Za-z])hsslms|lms_sha256_m\d+_h\d+",
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
    ("UOV", "UOV usage", re.compile(r"(?<![A-Za-z])uov[-_]?(i|ip|iii|v|s|pkc)", re.IGNORECASE)),
    ("MAYO", "MAYO usage", re.compile(r"(?<![A-Za-z])mayo[-_]?[1235]", re.IGNORECASE)),
    ("CROSS", "CROSS usage (dropped by NIST)", re.compile(
        r"(?<![A-Za-z])cross[-_]?r?[-_]?sdp", re.IGNORECASE,
    )),
    ("FrodoKEM", "FrodoKEM usage", re.compile(
        r"(?<![A-Za-z])frodokem|(?<![A-Za-z])frodo[-_]?(640|976|1344)", re.IGNORECASE,
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
]

# (command_type, compiled regex) for signing commands found in CI/build configs.
SIGNING_COMMAND_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("gpg_sign", re.compile(r"\bgpg\s+(--detach-sign|--sign|-s)\b")),
    ("openssl_sign", re.compile(r"\bopenssl\s+(dgst|smime|cms)\b.*-sign\b")),
    ("cosign_sign", re.compile(r"\bcosign\s+sign\b")),
    ("signtool_sign", re.compile(r"\bsigntool\s+sign\b", re.IGNORECASE)),
    ("jarsigner", re.compile(r"\bjarsigner\b")),
    ("codesign", re.compile(r"\bcodesign\b")),
]

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
}
# A line is read as a cipher list only when it carries a suite-shaped token: at least
# three dash-joined parts, or an IANA TLS_ name. "rsa-2048" is not a suite.
_SUITE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:TLS_[A-Z0-9_]+|[A-Za-z0-9]+(?:-[A-Za-z0-9]+){2,})(?![A-Za-z0-9])")


# What makes a dash-joined token a cipher suite rather than an ordinary hyphenated
# string: it names a bulk cipher AND a mode or MAC. Anything looser produced real
# false positives on real trees: "ML-DSA-65" read as DSA, "slh-dsa-sha2-128s" read as
# DSA, and a French translation ("Remplacer-par-des-frais") read as DES.
_SUITE_CIPHER = ("AES", "CAMELLIA", "CHACHA", "SEED", "IDEA", "RC4", "DES", "3DES", "NULL")
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
    "EC": "EC", "ECDSA": "ECDSA", "ECDH": "ECDH", "SM2": "EC",
    "ED25519": "Ed25519", "ED448": "Ed448", "X25519": "X25519", "X448": "X448",
    "DSA": "DSA", "DH": "DH", "DHX": "DH",
    "ML-KEM": "ML-KEM", "ML-KEM-512": "ML-KEM", "ML-KEM-768": "ML-KEM", "ML-KEM-1024": "ML-KEM",
    "ML-DSA": "ML-DSA", "ML-DSA-44": "ML-DSA", "ML-DSA-65": "ML-DSA", "ML-DSA-87": "ML-DSA",
    "SLH-DSA": "SLH-DSA", "LMS": "HSS/LMS", "XMSS": "XMSS",
    "SHA1": "SHA1", "SHA-1": "SHA1", "MD5": "MD5",
    "DES-EDE3-CBC": "3DES", "DES-EDE3": "3DES", "DES-CBC": "DES", "RC4": "RC4",
}


def scan_openssl3_names(line: str) -> list[tuple[str, int]]:
    """Families named as a string argument to an OpenSSL 3 fetch or keygen call."""
    out: list[tuple[str, int]] = []
    for m in _FETCH_CALL.finditer(line):
        family = _FETCH_NAME_FAMILY.get(m.group(1).upper())
        if family:
            out.append((family, m.start()))
    return out


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
        looks_like_suite = text.upper().startswith("TLS_") or (
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
        out.extend((family, pos) for family in families)
    return out


# --- key sizes named on the same line as the algorithm ---
_KEY_SIZE = re.compile(
    r"key_size\s*=\s*(\d{3,5})|(?<![A-Za-z])bits\s*=\s*(\d{3,5})|"
    r"(?<![A-Za-z])rsa[:\-_](\d{3,5})(?![0-9])|\bRSA_(\d{3,5})\b|"
    r"GenerateKey\([^)]*?(\d{3,5})\s*\)|"
    r"\bRSA_generate_key(?:_ex)?\(\s*[^,]*,\s*(\d{3,5})|"
    r"\bgenrsa\b[^\n]*?(\d{3,5})|"
    r"EVP_PKEY_Q_keygen\([^)]*?(\d{3,5})\s*\)",
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
    return path.suffix.lower() in CONFIG_EXTENSIONS or path.name in CONFIG_FILENAMES


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


def _block_comment_state(line: str, inside: bool) -> bool:
    """Whether the NEXT line is inside a /* */ block."""
    if inside:
        return "*/" not in line
    opened = line.rfind("/*")
    return opened != -1 and "*/" not in line[opened:]


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


def _opens_a_denial_block(line: str) -> bool:
    """`forbiddenAlgorithms:` on its own line, with the names indented below it.

    A configuration file writes a ban as a block far more often than as a list on
    one line, and a line-by-line reader sees the names without the word that
    governs them.
    """
    stripped = line.rstrip()
    return bool(stripped.endswith((":", "= [", "=[", "{", "(", "["))
                and _DENIAL_WORDS.search(stripped))


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
    if not _ALGORITHM_LIST_LINE.search(line):
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


def _drop_imports_covered_by_a_call(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """An import is not a second row when the call it enables is in the file.

    Measured on Cryben: 20 of 24 rows the reference did not place were import
    lines within two lines of the call. An import on its own is kept -- a module
    in the build is evidence, and dropping it would trade a duplicate for a miss.
    """
    called = {f["algorithm"] for f in findings if f.get("evidence_kind") == "call"}
    return [f for f in findings
            if not (f.get("evidence_kind") == "import" and f["algorithm"] in called)]


def scan_source_file(path: Path, rel_path: str,
                     lines: list[str] | None = None,
                     cipher_exclusions: bool = False) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = (_read_lines(path) or []) if lines is None else lines
    ext = path.suffix.lower()
    inside_block = False
    inside_doc = ""
    denial_block_indent: int | None = None
    for line_no, line in enumerate(lines, start=1):
        was_inside = inside_block or bool(inside_doc)
        spans, inside_block = _comment_spans(line, ext, inside_block)
        if ext in _DOCSTRING_EXT:
            doc_spans, inside_doc = _docstring_spans(line, inside_doc)
            spans = spans + doc_spans
        code = _code_only(line, spans)
        kind = _evidence_kind(line, was_inside, code)
        indent = len(line) - len(line.lstrip())
        if denial_block_indent is not None and line.strip() and indent <= denial_block_indent:
            denial_block_indent = None
        in_denial = denial_block_indent is not None
        if _opens_a_denial_block(code):
            denial_block_indent = indent
        # One line, one finding per algorithm. Several patterns can carry the same
        # name -- ECDSA is matched both by its own name and by secp256k1, X448 by
        # its upper and lower case forms -- and counting each pattern separately
        # inflates the headline number by however many ways the line could be
        # spotted, which is not a property of the code being scanned.
        seen_on_line: set[str] = set()
        blobs = _blob_spans(line)
        for algorithm, description, pattern in ALGORITHM_PATTERNS:
            if algorithm in seen_on_line:
                continue
            # Every match on the line, not the first: a cipher string can both ban
            # and allow the same family -- "ALL:!ECDH:ECDHE-RSA-AES256" -- and
            # judging the line by its first match would throw the real use away
            # along with the exclusion.
            matches = [m for m in pattern.finditer(line) if not _in_blob(m.start(), blobs)]
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
            in_comment = all(_in_spans(m.start(), spans) for m in matches)
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
            }
            size = key_size_on_line(line) if algorithm == "RSA" else None
            if size:
                item["key_size"] = size
            findings.append(item)
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
        if cipher_exclusions and "PPK" not in seen_on_line and PPK_CONFIG_ASSIGN.search(line):
            findings.append({
                "path": rel_path,
                "line": line_no,
                "algorithm": "PPK",
                "description": "RFC 8784 postquantum preshared key",
                "excerpt": line.strip()[:200],
            })
    return _drop_imports_covered_by_a_call(findings)


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
    # The denominator. files_scanned says how much was read; on its own it does not
    # say how much there was. A file skipped because the tool does not claim its
    # type is not a failure, but leaving it uncounted turns coverage into a number
    # with no base -- which is the thing this scanner exists to refuse.
    files_present = 0
    skipped_kinds: dict[str, int] = {}
    present_kinds: dict[str, int] = {}
    excluded_dir_counts: dict[str, int] = {}

    walk_problems: list[tuple[str, str]] = []
    unreadable_dirs: list[str] = []
    left_out: list[str] = []
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
        claimed = (is_ci or path.suffix.lower() in IAC_EXTENSIONS
                   or path.suffix.lower() in SOURCE_EXTENSIONS
                   or path.suffix.lower() in {".yaml", ".yml"} or is_config_file(path)
                   or is_certificate_file(path) or is_manifest(path))
        # Only a file no declared type claims is peeked at for key material; a .py or
        # a .tf that happens to contain a PEM block stays source and infrastructure.
        peeked_key = False if claimed else looks_like_key_file(path)
        if not (claimed or peeked_key):
            kind = path.suffix.lower() or "(no extension)"
            skipped_kinds[kind] = skipped_kinds.get(kind, 0) + 1
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
        read = _read_file(path, repo_path)
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

        for number, text_line in enumerate(lines, 1):
            for asset in scan_protocols(text_line):
                asset["path"] = rel_path
                asset["line"] = number
                asset["excerpt"] = text_line.strip()[:200]
                protocol_findings.append(asset)
        if is_manifest(path):
            dependency_findings.extend(scan_manifest(path, rel_path, lines))

        if is_certificate_file(path) or peeked_key:
            # Certificates and keys are read as bytes, not lines: a .der carries no
            # lines at all, and a .pem that fails to decode must still be counted.
            files_scanned["certificate"] += 1
            algo_findings, key_findings = scan_certificate_file(path, rel_path, raw)
            source_findings.extend(algo_findings)
            embedded_key_findings.extend(key_findings)
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

    return {
        "files_scanned": files_scanned,
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
        "files_skipped_by_type": dict(
            sorted(skipped_kinds.items(), key=lambda kv: kv[1], reverse=True)
        ),
        # Attempted and NOT read. files_scanned counts only files actually read, so
        # "0 findings" can be checked against a denominator instead of trusted.
        "unreadable_files": unreadable,
        "claimed_but_not_decoded": undecoded,
        "protocol_findings": protocol_findings,
        "dependency_findings": dependency_findings,
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
    }
