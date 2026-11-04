# What it looks at

[Back to the README](../README.md) · [CHANGELOG](../CHANGELOG.md)

## Tools

| Tool | What it does |
| --- | --- |
| `scan_repo(path, level, profile)` | Scans a directory's source, CI/CD configs and infrastructure-as-code; returns findings, a summary, and the coverage block below |
| `export_cbom(path, level)` | The same reading as a CycloneDX 1.6 CBOM, with the coverage block inside it |
| `compare_coverage(first, second)` | Whether two scans produced numbers that can be compared at all |
| `prove_closure(before, after)` | Which findings a change actually closed, from two saved scans of one tree — only if the two runs can be compared for it |
| `list_algorithms()` | The algorithm families the server recognises and how each is classified |

## What it looks at

**Chain and wallet code** — `secp256k1`, `ecrecover`, ethers, web3, bitcoinjs, `ECPair`,
`btcec`, tweetnacl, `@solana/web3.js`, `solana_program`, `bls12-381`, blst, `@chainsafe/bls`,
BIP340/Taproot Schnorr. Solidity (`.sol`), Rust (`.rs`), Move and Cairo are scanned alongside
Python, Go, Java, Kotlin, Scala, Groovy, JS/TS, Ruby, PHP, C/C++/C# — headers included — PowerShell,
Perl and shell.

**Classical crypto anywhere else** — RSA, DSA, DH, ECDSA and elliptic-curve usage, plus MD5,
SHA-1, RC4 and DES/3DES. Not only through library calls: the names the protocols themselves use
(`ssh-rsa`, `rsa-sha2-512`, `ssh-dss`, key types such as `rsa-2048` and `RSA_4096`), the modern
OpenSSL 3 form where the algorithm is a string argument (`EVP_PKEY_Q_keygen(libctx, propq,
"RSA", bits)`, the `EVP_*_fetch` calls), and the hash idioms people actually write
(`hashes.MD5()`, `hashlib.new('md5')`, `MD5Init`, `<sha1.h>`, Go `sha1.Sum`). Since 0.26.0 also the
classes a key is loaded through (`jose.JWKRSA.load(...)`, `jose.ComparableRSAKey(...)`) and the
signature OIDs of Python's `cryptography` (`SignatureAlgorithmOID.RSA_WITH_SHA1`): certbot creates
its ACME account key as `jose.JWKRSA(...)`, and that line, with 28 more like it, was no finding.

Since 0.27.0 also RSA without padding -- `RSA_private_encrypt`, `RSA_public_decrypt`,
`RSA_padding_add_none`, `RSA_NO_PADDING`, the raw oracle the 2026 forgery of 1024-bit signatures
needs (ePrint 2026/2131); until then the four were found only when something else on the line
named RSA. And the type and enum vocabularies of the libraries that carry the algorithm in a name:
Java's `RSAPublicKeySpec`, `DSAPrivateKey`, `DSAParams`; auth0's `Algorithm.RSA256`; the WebCrypto
and JOSE names `"RSASSA-PKCS1-v1_5"` and `"RSA-PSS"`; Mbed TLS's `mbedtls_rsa_*` and
`MBEDTLS_PK_RSA`; `OPENSSL_KEYTYPE_RSA`, `TPM_ALG_RSA*`, `x509.DSAWithSHA256`, `KeyType.RSA`;
Go's `*rsa.PublicKey`; .NET's `RSASignaturePadding.Pss`; and a JWK's `"kty": "RSA"`. These are
case-sensitive: `rsaKey` is a variable, `RSAKey` is a type.

From 0.32.0 also OpenSSL's RSA signing calls — `RSA_sign`, `RSA_verify`, their
`_ASN1_OCTET_STRING` forms, `RSA_verify_PKCS1_PSS(_mgf1)`, `RSA_padding_add/check_PKCS1_PSS`,
`_PKCS1_type_1`, `_X931` and `RSA_PKCS1_PSS_PADDING` (names from `include/openssl/rsa.h`), with
role `signature`. A secure-boot verifier is often one `RSA_verify` against a key fused at
manufacture, and that line scanned as nothing (raised by Ken Camp).

**DNSSEC** (from 0.32.0, raised by Georgi Ivanov). The algorithm a zone is signed with, by its
IANA mnemonic as BIND (`dnssec-policy … algorithm rsasha256 2048`, `dnssec-keygen -a RSASHA256 -b
2048`), Knot (`algorithm: rsasha512`) and PowerDNS (`default-ksk-algorithm=rsasha1-nsec3-sha1`)
write it: `RSAMD5`, `RSASHA1`, `RSASHA1-NSEC3-SHA1`, `RSASHA256`, `RSASHA512` → RSA, with the size
where the line gives one; `DSA-NSEC3-SHA1` → DSA; `ECDSAP256SHA256`, `ECDSAP384SHA384` → ECDSA with
`curve` P-256 / P-384; `ED25519`, `ED448`, `MLDSA44` by their own rules. And by number (IANA
DNSSEC Algorithm Numbers, read 22 Oct 2026), only in the shape of a record — `DNSKEY`/`CDNSKEY`
`flags 3 alg`, `DS`/`CDS` `tag alg digest-type digest`, `RRSIG type alg`, and BIND's
`static-key`/`initial-key`/`static-ds`/`initial-ds` trust anchors: 1, 5, 7, 8, 10 RSA; 2 DH;
3, 6 DSA; 13, 14 ECDSA with the curve; 15 Ed25519; 16 Ed448; 17 SM2; 18 ML-DSA. A bare `8`
is a number, not RSA. ECC-GOST (12, 23) is GOST R 34.10 from 0.36.0 (before, it was left unnamed). `.zone` files are
read. Not read: PowerDNS's `ecdsa256`/`ecdsa384` as DNSSEC names — they are found as ECDSA by the
ordinary rule, without a curve, because the same word is a variable name in OpenSSH; a bare `DSA`
(algorithm 3) as a mnemonic; the `.private` files `dnssec-keygen` writes; zone files saved under
other names (`db.example`).

Where they came from, and what they did. An independent labeller read 34,967 chunks of
185 public repositories; 45 of them were set aside before labelling and not read while the rules
were written. Chunks where the labeller sees an algorithm named in the text and the scanner reports
nothing of that family: **1,068 → 967 (-9%) on the 140 the rules were written from, 167 → 155 (-7%)
on the 45 they had never seen.** The two move together, so the rules carry over rather than fit;
both are modest, because most of what remains is a bare word or a name without an operation, which
this tool does not count on purpose. The labeller is a model, not ground truth: these are counts of
disagreement, not recall.

**Cipher suites, decomposed** — `ECDHE-RSA-AES128-GCM-SHA256` is ECDH *and* RSA, and
`DHE-DSS-…` and `DES-CBC3-SHA` name families that reading the suite as one word never sees.
IANA `TLS_*` names are read the same way. A banned component is not a use: `!MD5` and `!3DES`
in a cipher list are exclusions, and they are treated as such.

**Protocols and dependencies, counted without inventing an algorithm** — a pinned TLS version
(`MinVersion: tls.VersionTLS12`, `ssl_protocols`, `SslProtocols.Tls12`, `SSL3_VERSION`), an SSH
transport line, and a cryptographic library declared in `package.json`, `go.mod`,
`requirements.txt`, `Cargo.toml`, `pom.xml` or a `Gemfile`. These are real facts about a
repository and they are reported — in their own buckets, never in `detected_algorithms`. Each
carries a `basis`: `configured_protocol` or `declared_dependency`, never `observed_call`, because
an installed library is not a line of code that calls it. A version is not a verdict either:
TLSv1.0 is marked deprecated, and quantum vulnerability is not claimed from a version number,
since TLS 1.3 is vulnerable over X25519 and is not over X25519MLKEM768. `-SSLv3` in an
`SSLProtocol` line is a ban, and is recorded as one. Manifests are parsed structurally, so a
library named in a comment is not a dependency.

**Key sizes** — a size named on the line (`key_size=1024`, `rsa:1024`, `genrsa 1024`,
`GenerateKey(..., 1024)`, `-newkey rsa:3072`, `ssh-keygen -b 4096`, `rsa-key-size = 4096`,
`KeyPairGenerator.initialize(2048)`; for DSA and DH `key_size=`/`bits=`) travels with the family,
and only a size a modulus can have — `CKM_RSA_9796` is ISO/IEC 9796 padding, not a 9796-bit key —
so a weak RSA key is reported as weak rather
than as one more RSA. `algorithm_key_sizes` holds the **smallest** size seen per family — the
figure that answers *is anything weak here* — and `algorithm_key_sizes_observed` holds **every**
size seen, which is a different question and became the operational one when RSA-896 was factored
on a data-centre fleet: *where is RSA-1024 still in use?*

The size reaches the CBOM as one algorithm component **per observed size, curve or parameter
set** — `RSA-2048` apart from `RSA-4096`, `ECDSA-P-256` apart from `ECDSA-P-384`, `ML-KEM-768`
apart from `ML-KEM-1024` — each with its own occurrences and the number in
`cryptoProperties.algorithmProperties.parameterSetIdentifier`, the field whose own examples in the
schema are a key length and a digest length. The family's own component (`RSA`) holds only the
sightings that name no size, and is **not emitted** when there are none; a certificate's key, a
hybrid's half and a self-signed certificate's signature then point at the sized component. A
family whose name fixes the number carries it (MD5 128, SHA-1 160, SHA-224 224, DES 56,
X25519/Ed25519 256, X448 448, Ed448 456 — the key sizes a parsed key gets), and so does a TLS group
or SSH key exchange offered alone (`prime256v1` 256, `diffie-hellman-group14-sha256` 2048). Nothing
else gets a number: `rsa-sha2-256` names a hash, not a modulus, and a sizeless sighting stays
sizeless rather than inheriting a size seen elsewhere in the tree.

**Hybrids and composites** — the RFC 10024 TLS groups `X25519MLKEM768`,
`SecP256r1MLKEM768` and `SecP384r1MLKEM1024`, OpenSSH 10's default `mlkem768x25519-sha256`,
and the composite certificate algorithms of draft-ietf-lamps-pq-composite-sigs such as
`id-MLDSA44-RSA2048-PSS-SHA256`. A hybrid holds if either half holds, so the post-quantum
scheme leads — and the classical half is carried in `also_present` rather than dropped, since
it is the component Shor breaks.

**Post-quantum schemes, by family** — ML-KEM, ML-DSA, SLH-DSA, Falcon (FN-DSA), NTRU,
Classic McEliece, BIKE, HQC, FrodoKEM, XMSS, and the stateful LMS/HSS of SP 800-208 that
CNSA 2.0 requires for firmware signing. The nine schemes NIST advanced to its third
additional-signatures round in May 2026 — FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA,
SQIsign, UOV — are recognised, the eight other than HAWK as candidates and HAWK as withdrawn
(below), and CROSS as dropped from that process.

Each carries the mathematical family it rests on (structured or unstructured lattice,
code-based, hash-based, isogeny-based, multivariate, symmetric-based) and where it stands:
standardised, selected, candidate, superseded, research, withdrawn, eliminated or broken. SIKE is reported
as broken and HAWK as withdrawn rather than counted as quantum-resistant — "post-quantum" is a
category, not an assessment.

**Only a published standard is `pqc_ready`.** A selected or candidate scheme — HQC, Falcon
(FIPS 206 not yet listed as published here), Classic McEliece, BIKE, FrodoKEM, NTRU including
OpenSSH's `sntrup761`, and the additional-signature candidates — is `pqc_pre_standard`: found,
post-quantum, and not counted as ready, because an implementation of today's specification need
not match the standard when it comes (FIPS 203's own 2023 draft differs from the final text).
Until 0.28.0 these counted as `pqc_ready`; raised in public by Bill Buchanan about HQC.

**Round-3 Kyber is not ML-KEM.** FIPS 203, Appendix C: ML-KEM uses a different Fujisaki-Okamoto
variant from the round-3 submission, and the two do not interoperate. Until 0.28.0 every Kyber
spelling was reported as standardised ML-KEM (raised by Mehrdad Daei). Now the identifiers round-3
code carries — `pqcrystals_kyber…`, `crypto_kem_…kyber…`, `PQCLEAN_KYBER…`, `pqcrypto.kem.kyber…`
and the `pqcrypto-kyber` crate, `OQS_KEM_alg_kyber_…`, CIRCL's `kem/kyber`, `pqc_kyber`, and the
draft hybrids such as `X25519Kyber768Draft00` — are family `Kyber`, status `superseded`,
`pqc_pre_standard`. **The word `kyber` alone** is reported the same way: it is the round-3 name
and also an old name people still use for ML-KEM, the line does not say which, and claiming a
standard for code that may not interoperate with it is the worse error. A line that names ML-KEM
as well (`ML-KEM (Kyber)`) resolves the old name and is ML-KEM only. Whether code that says
`pqcrystals_kyber` was updated to FIPS 203 under the old name is not visible from the name, and the
finding says so.

**OpenSSH's experimental ML-DSA key is not the one that replaced it.** OpenSSH 10.4 shipped a
composite of ML-DSA-44 and Ed25519 as an experiment, as `ssh-mldsa44-ed25519@openssh.com`; 10.6
enabled the scheme without the suffix, and its release notes say keys generated with the
experimental support must be regenerated and/or removed. Until 0.30.0 both read as ML-DSA,
`pqc_ready`. Now the suffixed type — in a key or certificate file, or named in configuration such as
`HostKeyAlgorithms` — is family `ML-DSA-44-Ed25519 experimental`, status `superseded`,
`pqc_pre_standard`, and the ML-DSA rule does not count it a second time. The unsuffixed composite
stays ML-DSA and now names its classical half: `also_present: ["Ed25519"]`. Whether a given server
still accepts an experimental key is not visible from the file. On OpenSSH's own tree, four test
keys under `regress/` still carry the experimental type while the source uses the new name.

**The summary does not reassure past a broken scheme.** `summary.pqc_readiness` is one of
`broken_pqc_present` (a broken, withdrawn or eliminated post-quantum scheme is present — first,
whatever sits beside it), `hybrid_partial`, `hybrid_pre_standard` (classical beside post-quantum
schemes none of which is standardised), `mechanism_protected`, `classical_only`,
`pqc_pre_standard`, `pqc_ready` (every post-quantum scheme found is standardised and nothing
classical is), `no_quantum_vulnerable_detected`, `not_established` (one of the reassuring values,
withheld because the scan did not read or determine everything — from 0.34.0) or `unknown`. Until 0.28.0 a file holding only
SIKE read `no_quantum_vulnerable_detected` (raised by Larisa Ghazaryan). `pqc_pre_standard_count`
and `broken_pqc_count` sit beside `pqc_ready_count`, and `list_algorithms` answers with the same
classification a scan gives. From 0.35.0 `summary.by_role` gives the same value for key
establishment and for signatures apart, with the families in each (`none_found` for a part with
none).

**Which module implements it, where the file says.** Validation belongs to a module, not to an
algorithm, and `@noble/post-quantum` and Go's `crypto/mlkem` used to give identical findings
(raised by Jesone Sam). Now a line that uses a family carries `provider` when the file names the
module unambiguously — `@noble/post-quantum`, the Go standard library (`"crypto/mlkem"`),
Cloudflare CIRCL, liboqs, pqcrypto, PQClean, the pq-crystals reference code, Bouncy Castle,
BoringSSL (`MLKEM768_…`, `MLDSA65_…`, `KYBER_…`) and OpenSSL 3 (`EVP_PKEY_Q_keygen`,
`EVP_PKEY_CTX_new_from_name`, `EVP_KEM_fetch`…) — and each finding lists its `providers`. The
module is usually named on the import line and used on another, so a call line takes the module
its file imports for that family; two modules in one file and none on the line leave it absent.
An unknown provider is **absent, never guessed**: a header such as `<openssl/evp.h>` is shared by
OpenSSL, BoringSSL and LibreSSL and names no one. What is named is the API, not the build — a fork
that keeps the API reads the same — and **nothing here claims CMVP or FIPS 140-3 validation**.

From 0.32.0 (raised by Paul J. Lilly, extending a point Solahuddin Shamsuddin made): Python's
`cryptography` is a provider too (`pyca/cryptography`, by `from cryptography.hazmat…`), and **a
version pinned in a manifest is joined to the provider whose package it is**: `cryptography==44.0.0`
in requirements.txt gives every line that imports it `provider_pin: {"package": "cryptography",
"version": "44.0.0", "pinned_in": "requirements.txt:1"}`, and the finding `provider_pins`. Read
from `requirements.txt` (`==` only) and `go.mod`, from the nearest manifest above the file, for
pyca/cryptography, Cloudflare CIRCL and pqcrypto. A range (`>=42`) is a request, not a version, and
gives nothing; two pins that disagree at the same level give nothing. `pyproject.toml`, `Pipfile`
and the lockfiles are not read for this. "Pinned" is what the manifest asks for, not what is
installed.

And **OpenSSL's FIPS provider, activated in `openssl.cnf`**, is `evidence.fips_provider`, one item
per line that brings it in, from OpenSSL's `config(5)` and `fips_module(7)`: `.include
…/fipsmodule.cnf`, `fips = <section>` in the section `providers =` names (when that section's
`activate` is yes/on/true/1, or the section is in the included file), and `default_properties =
fips=yes` or the deprecated `fips_mode = yes`. Each says "FIPS provider activated in
openssl.cnf:8 … Activated in configuration, not validated". Every finding whose provider is
OpenSSL 3 then carries `fips_provider_configured_in` — the same ML-KEM line read "OpenSSL 3"
whether it ran through the FIPS provider or the default one. Which process loads which
configuration file is not in the files, and is not claimed; neither is validation.

**Isogeny key exchange in no standardisation process: MIKE, CSIDH, CTIDH.** Until this release
code doing either read as having no post-quantum cryptography at all (raised by John Preuß
Mattsson). Matched by the implementations' own identifiers — MIKE's `mike_keypair(` /
`mike_exchange(`, `MIKE_BUILD_TYPE` and the other CMake options, its six primes (`p308_633` …),
the `mike_rs` crate, `from mike.mike import`, `tensor-MIKE/mike_*`; CSIDH/CTIDH as `csidh`,
`ctidh`, `highctidh`, `secsidh`, CIRCL's `dh/csidh` — and reported with status **`research`**,
`pqc_pre_standard`: not ready, and not broken. The SIKE attack does not carry over (it needs the
torsion-point images MIKE and CSIDH do not publish). CSIDH-512 is below its claimed level against
quantum attack (Peikert; Bonnetain–Schrottenloher), which the finding says — a cost estimate, not
a classical break. **The word `mike` alone never matches**: it is a person, the MkDocs versioning
tool on PyPI, and MIKEY (RFC 3830); `import mike` cannot be told apart from MkDocs and is not read
as MIKE either. Through the classifier API `MIKE` matches only as the whole value.

**Merkle Tree Certificates are named, never counted as post-quantum.** The three OIDs IANA
assigned on 28 Sep 2026 (`1.3.6.1.5.5.7.6.67`, `.1.38`, `.25.3`), Cloudflare's experimental arc
`1.3.6.1.4.1.44363.47` (in dotted and Go integer-list form), the draft's ASN.1 names
(`id-alg-mtcProof`, `MTCProof`, `MTCLogEntry`, `MerkleTreeCertEntry` …) and the BoringSSL and
Chrome identifiers (`X509_V_FLAG_USE_MTC_DRAFT_PLANTS_05`, `NID_alg_mtcProof_draft`,
`MTCAnchor`, `kVerifyMTCs`, `verify-mtcs`) give family `MTC`, classification `unknown`. They live
in CA, TLS-library and browser code, not in an origin's configuration, and a hit means "this
code issues or verifies MTCs" — the authentication rests on the CA's and the cosigners' signature
algorithms, and the leaf keeps an ordinary key (ECDSA-P256 in Cloudflare's experiment). So it
is neither `pqc_ready` nor a mechanism, and stays out of `pqc_readiness`. Trust Anchor IDs
(`TLSEXT_TYPE_trust_anchors`, `0xca34`) are a prerequisite, not MTC, and are not matched; nor is
`merkle` alone. Raised by Delta Li.

**Certificates and keys** — `.pem`, `.der`, `.crt`, `.cer`, `.cert`, `.csr`, `.key`, `.pub`,
`.p12`, `.pfx`, and from 0.35.0 the Java keystores `.jks` and `.keystore`. Algorithms are resolved from the object identifiers inside the DER and from
PEM labels and OpenSSH key types, and private key material is reported separately. This does
not parse X.509: it matches the object identifiers already in the classifier against the bytes.
A file that is not a certificate but contains an identifier's bytes **is** reported, and the
finding says so — "observed in the file; the file was not decoded as a certificate". An earlier
version of this paragraph promised that a malformed certificate yields nothing; an independent
analysis put a valid RSA identifier into arbitrary bytes and got a finding, which is what the
code measures. For a certificate register — issuer, validity, the device — this tool is the wrong
instrument and says so: that data comes from a structural parser or an external inventory.

From 0.32.0 an EC key's **curve is named** from its named-curve identifier — P-256
(`1.2.840.10045.3.1.7`), P-384 (`1.3.132.0.34`), P-521 (`1.3.132.0.35`) from RFC 5480 §2.1.1.1,
secp256k1 (`1.3.132.0.10`) from SEC 2 v2.0 — as `curve` and `key_size` on the EC finding. Before,
the curve identifier was swallowed by `id-ecPublicKey`, and a P-384 key read as "EC".

From 0.33.0 an RSA key's **size** is read the same way, from its public key: the modulus in a
SubjectPublicKeyInfo whose algorithm is `rsaEncryption` (RFC 3279 §2.3.1, RFC 8017 A.1.1) and in
an `RSA PUBLIC KEY` block, as `key_size` on the RSA finding, so it reaches `algorithm_key_sizes`
and the CBOM. Before, a certificate's RSA key was named and never sized. An issuer's RSA
signature on a certificate whose own key is EC gets no size — the issuer's key is not in it — and
a private key is not read for its size. On certbot the smallest RSA size becomes 512 bits (test
certificates in `acme/…/testdata`, checked with `openssl x509 -text`); on OpenSSH nothing moves.

And **a private key recoverable from its public key is a finding of its own**, under
`evidence.weak_keys` ("private key recoverable"), with the curve and the scalar: every
uncompressed EC public point the scan can locate is compared with k·G for every k ≤ 256. The
eight keys in a post of 22 Oct 2026 all had k < 256, one of them 4·G on P-384, and before this
release that certificate scanned exactly like one with a random key (raised by Bill Buchanan;
the check is Israr Ahmed's). Where the point is located, without parsing X.509: a DER BIT STRING
`00 04 X Y` of the key's curve size (SubjectPublicKeyInfo in a certificate, a public key, SEC 1
`EC PRIVATE KEY`, PKCS#8) and OpenSSH's `nistp256/384/521` encoding (a `.pub` line, an
`openssh-key-v1` private key file). P-256, P-384, P-521 and secp256k1; curve parameters from SEC 2
v2.0, agreeing with RFC 5903 §3. **Not checked**: compressed points, keys inside encrypted
containers (PKCS#12, encrypted PEM), other curves (brainpool, Ed25519 and X25519 keys), points
quoted in source code or in a `known_hosts`/`authorized_keys` line read as configuration, and any
scalar above 256 — the bound is the finding's, and a key with scalar 257 is not reported.
From 0.40.0 the bound is said where the check ran, found or not (row 154): `weak_key_check`
gives `bound: 256`, the number of EC public keys compared and "checked up to 256", and the CBOM
carries `qrp:weak_key_check:bound`. Where no EC public key was read it is `null`.
Debian's weak OpenSSL keys and ROCA are a different family of weak key and are not checked. The
table is built once per curve (four curves: 39 ms) and a key costs a lookup: on OpenSSH's 130 key
and certificate files the check took 3 ms. In the CBOM each weak key is a
`related-crypto-material` component, `EC key on P-384 with private scalar 4`.

**Configuration** — `nginx.conf`, `sshd_config`, `openssl.cnf`, `swanctl.conf`, `.ini`,
`.toml`, `.properties`, `.hcl`, `.json`, and any YAML that is not a manifest. This is where a TLS or SSH hybrid
group is chosen: `X25519MLKEM768` and `mlkem768x25519-sha256` are almost never strings in code.
IKE proposal syntax is read here too — `ecp384` is NIST P-384, `modp2048` is group 14.
From 0.32.0 also `.zone` files, and the DNS size budget of a BIND configuration: `max-udp-size`
(the largest UDP response BIND sends) and `edns-udp-size` (the buffer it advertises for responses
it receives) are protocol assets with `protocol: "dns"`, `udp_setting` and `udp_size`. Both
default to 1232 bytes (BIND 9 ARM); a file with a `dnssec-policy` that does not set
`max-udp-size` gets that default as an asset with `default_applied: true`, at the
`dnssec-policy` line.

**OPC UA SecurityPolicies.** Each of the 30 SecurityPolicy URIs in the OPC Foundation profile
database (UACore 1.05, read 7 Oct 2026) names the algorithms it rests on — RSA, ECDSA+ECDH,
Ed25519/X25519, Ed448/X448 or RSA with finite-field DH; SHA-1 for Basic128Rsa15 and Basic256 —
and no post-quantum one exists. A URI (`http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256`)
or a stack's own identifier — .NET `SecurityPolicies.X`, open62541 `UA_SecurityPolicy_X(` /
`UA_ServerConfig_addSecurityPolicyX(`, asyncua `SecurityPolicyType.X_Sign…` and
`set_security_string("X,…`, Milo/node-opcua `SecurityPolicy.X`, gopcua `SecurityPolicyURIX`,
Node-RED `"secpol"` — gives those families, and the policy itself as a protocol asset
(`protocol: "opcua"`) with `policy_status` and `deprecated`: ten are `Deprecated` in the database
(Basic128Rsa15, Basic256, the six un-suffixed ECC policies and two interim names). For the six ECC
ones the .NET stack disagrees (`IsDeprecated = false`) and the asset says so; a policy without the
attribute is "not marked deprecated", not "released". Stack-only names (`Https`, `Basic192` …) are
named with no algorithm claimed. A bare `Basic256Sha256` or `None` never matches. **`.xml` and
`.json5` are read only when the file contains a SecurityPolicy URI** — a .NET `*.Config.xml`, an
open62541 `*.json5` — and declared as `claimed_types.config_when_naming_opcua_security_policy`;
every other XML stays `type_not_claimed`, so coverage on trees without OPC UA does not move.
Raised by Ogochukwu Friday Ikwuogu.

**AWS load-balancer TLS policies, and the one you get by writing none.** An `ELBSecurityPolicy-…`
name — Terraform `ssl_policy`, CloudFormation `SslPolicy`, CDK `elbv2.SslPolicy.X` — is read
against the 45 policies on AWS's ALB and NLB pages: every one offers classical (EC)DHE (`ECDH`),
the 13 `…PQ-2025-09` ones add hybrid ML-KEM, and those with RSA key-transport suites name `RSA`;
the policy is a protocol asset with `allows_versions`, `post_quantum` and `deprecated` (TLS 1.0 or
1.1 allowed). **A Terraform `aws_lb_listener`/`aws_alb_listener` or a CloudFormation
`AWS::ElasticLoadBalancingV2::Listener` that serves HTTPS or TLS and names no policy gets
`ELBSecurityPolicy-2016-08`**, AWS's documented default for the CLI, CloudFormation, the CDK and
the API (Terraform sends none) — TLS 1.0–1.2, RSA key transport, no post-quantum group — with
`default_applied: "default applied because ssl_policy is absent"`, `basis: provider_default` and
evidence kind `default`. The console default is a PQ policy; that difference is the point (raised
by Vladimir Mikhalev, whose probe — explicit `2016-08`, and no `ssl_policy` — gave 0 findings
both ways until this release). Only a top-level `protocol` counts: the `redirect { protocol =
"HTTPS" }` inside an HTTP listener does not make it an HTTPS listener, and `ssl_policy = var.x` is
not absent. An unknown name, and CDK `LEGACY` (on neither AWS page), claim no algorithm; from
0.38.0 an unknown `ELBSecurityPolicy-*` name set as a listener's policy is named as a TLS asset
with `policy_known: false`, so the listener does not drop out.

**IKEv2 fragmentation, where the configuration carries post-quantum.** An ML-DSA signature lands
in IKE_AUTH, and draft-ietf-ipsecme-ikev2-pqc-auth makes RFC 7383 fragmentation a MUST for it;
RFC 9370 puts additional key exchanges in IKE_INTERMEDIATE so they can be fragmented. So where a
strongSwan, Libreswan, Cisco, FortiOS, Junos or OpenBSD iked configuration carries a post-quantum
family, a protocol asset (`protocol: "ike"`) names `fragmentation` — `enabled`, `disabled`, the
value as written, or `not_found` in the files read — and `fragmentation_default` as each product
documents it: strongSwan yes since 5.5.1, Libreswan yes (5.4), FortiOS enable (7.6.6), Junos
enabled, iked `nofragmentation`. A file rarely carries the version, so a default is said as
documented, never as what the box does. **Cisco's is "default not confirmed"**: IOS XE and ASA
document opposite defaults and the platform is not in the file. FortiOS's numeric `set addkeN 36`
is read as ML-KEM (35–37), and 1080–1094 as Kyber, FrodoKEM, BIKE and HQC. Raised by Saqib Ahmad.

**Quantum-resistant mechanisms, not only algorithms** — RFC 8784 mixes a postquantum preshared
key into IKEv2 key derivation, so a tunnel resists a quantum adversary with no post-quantum
algorithm present. A scanner matching algorithm names cannot see that by construction, and
would report a protected deployment as `classical_only`. PPK is matched by the directives that
switch it on and classified as `quantum_resistant_mechanism` — deliberately not `pqc_ready`,
because a preshared key is not ML-KEM. Whether it holds depends on the entropy of the key and
on out-of-band distribution, neither of which is visible in a file, and the finding says so.

**CI/CD pipelines** — signing commands such as `gpg --sign`, `cosign sign`, `signtool`,
`jarsigner`, `codesign`. From 0.32.0 also Secure Boot, kernel-module and IMA/EVM signing, each
from its own manual: `sbsign`, `pesign -s`/`--sign`, `kmodsign`, `evmctl sign`/`ima_sign`/
`sign_hash` and the kernel's `scripts/sign-file`; and signing commands in any `.sh` file, not
only in the pipeline files — a pipeline often only calls the release script. A step that names
its key (`openssl dgst -sign KEY`, `-inkey KEY`, `--key KEY`, signtool's `/f FILE`, the key
argument of `kmodsign` and `sign-file`) carries `signing_key`: the path, `in_tree` — whether the
scan read a key or certificate file there, from the tree's root or the script's directory — and
the families it found in it. A path written with a variable is left alone. In the CBOM the steps
are still only counted. Raised by Ken Camp. Whether a trust anchor can be rotated in the field is
not in any file and is not inferred: that is the platform owner's statement.

**Infrastructure as code** — Terraform and Kubernetes key algorithms, and private key material
committed by mistake.

**Build files, includes, test recipes and key inventories** — `Makefile`, `CMakeLists.txt`,
`.in`, `.cmake` (a build file enumerates which algorithms a tree implements at all), `.inc`
(the assembly and C fragments of implementations — OpenSSL keeps its ML-DSA there), `.t` (Perl
test recipes: tests are code, and skipping them quietly is exactly what this tool argues
against), and `known_hosts` / `authorized_keys`, where the key type is named on every line.

**Not read, on purpose** — documentation: `.txt`, `.md`, `.pod`, `.rst`. Measured across five
real repositories, reading them would have added more than 11,000 "findings" from help texts
and changelogs. An algorithm mentioned in prose is not a deployment. The boundary is pinned by
a test, so it is a declared scope rather than a silent skip — the same standard this tool asks
of others. Binaries and images are not read either.

**Accidents of the alphabet are not findings** — a match inside a long hexadecimal or base64
run does not count. A NIST test vector in OpenSSH spells `ed448` inside its message bytes.

Real run against [OpenZeppelin's contracts](https://github.com/OpenZeppelin/openzeppelin-contracts)
(711 files, about five seconds):

```json
{
  "detected_algorithms": ["ECDSA", "RSA"],
  "summary": {
    "quantum_vulnerable_count": 2,
    "pqc_ready_count": 0,
    "highest_severity": "high",
    "pqc_readiness": "classical_only"
  }
}
```

### Very long lines

A test-vector line can carry tens of thousands of hex digits. Until 0.25.0 every pattern searched
through such a run before the match was thrown away as sitting inside a blob, and the cost grew
with the square of the run's length: one 9,272-digit ML-DSA vector took 2.8 s for the 48 patterns,
and a scan of BoringSSL (12,921 lines over 2,000 characters) did not finish. Now the inside of a
blob is blanked before searching — positions and the blob's edge characters stay — and BoringSSL
takes 18 minutes. On nine corpora (certbot, OpenSSH, Vault, OpenSSL, curl, Mbed TLS, wolfSSL,
s2n-tls, rustls) every piece of evidence is identical before and after.
