# Changelog

What changed in each version of qrp-mcp, newest first. Each entry says what was wrong, how it
was found, and what is not claimed. Changes before 0.33.0 are described where the behaviour
is, in the [docs](docs/) ("From 0.28.0 ..."); the tag of every version is on GitHub.

## 0.43.0

**`qrp-mcp control PATH --seed N`: a control planted into your own tree.** The tree is copied
to a temporary directory; 9 styles of cryptographic use (direct calls, aliased names, names
built from pieces, calls split over lines, shell commands in strings, cert-manager, Terraform,
Java properties, UTF-16 without a BOM) and 7 kinds of line that name an algorithm without using
it (switched-off flags, deny lists, log strings, variable names, comments, a JWKS key label, an
sshd_config removal list) are planted for RSA, ECDSA and Ed25519 in each language present; the
copy is scanned with the same instrument and every planted line is scored. The same seed on the
same tree plants the same lines (`plan_sha256`). The MCP tool is `run_self_seeded_control`, and
`scan --control-seed N` (and `cbom`) carries the block as `coverage.claims.self_seeded_control`;
every other scan carries `ran: false`. The figure is **robustness on known patterns** for this
version: the denominator is what was planted, and it says nothing about what the tree contains.
So `claims.control.held` stays `false` and nothing in the block feeds the CBOM's
`compositions[].aggregate`, both pinned by a test. The block's shape is published in
[docs/control.md](docs/control.md). The harness is the one written for the measurement of
04.11.2026, moved into the package; on its seven trees it reproduces that round's 0.42.0
results item for item.

On those seven trees at seed 1: planted uses not found 28 of 189 (0.42.0) -> 26 of 189;
decoys reported as a use 50 of 126 -> 23 of 126; rows at `high` on planted lines 100 on uses
and 3 on decoys -> 103 and 0. The rows below were corrected against five of the decoy classes,
so those classes no longer measure the rules independently ([measurement](docs/measurement.md)).

Each row below was reproduced as a failing test before the fix, and each fix was reverted once
to see its test fail.

- **An OpenSSH list that begins with `-` removes every name on it** (row 420).
  `HostKeyAlgorithms -ssh-rsa,ssh-dss` gave a ban for `ssh-rsa` and a DSA reference for
  `ssh-dss`; `KexAlgorithms -diffie-hellman-group14-sha1,...` a DH reference with size 2048.
  sshd_config(5) and kex_assemble_names: the prefix governs the list. `+` and `^` still offer.
  A test that said the opposite (`-ssh-dss,rsa-sha2-512` keeps RSA live) is corrected.
- **A family named only in an assigned variable's name is an identifier** (row 421), for ECDSA
  and Ed25519 as it was for RSA: `ecdsa_fallback_count = 0` was a declaration at medium. Code
  only: a Terraform or config key (`ecdsa_curve = "P256"`) is the setting, and a switch name
  (`CONFIG_ECDSA=y`) stays a declaration of the use. Still counted as named, at low.
- **A switch set off is a ban in Rust, TypeScript, PHP, Java and Go** (row 422):
  `const ECDSA_ENABLED: bool = false;`, `static final boolean ... = false;`,
  `$ecdsaEnabled = false;`, `const ecdsaEnabled = false`, and `= 0`.
- **A string handed to a log or print call is text** (row 423): Rust `log::info!("Ed25519 ...")`
  and TypeScript ``console.info(`ECDSA ...`)`` were calls at high. A call nested inside the log
  call is still a call.
- **A bare name on its own line in a split call** (row 424): `generateKeyPairSync(\n 'rsa',` and
  `getInstance(\n "RSA");` were silent; read as the joined call, at the string's line.
- **.NET and Go lockfiles** (rows 425-428): `*.deps.json` (`libraries` of type `package`),
  `packages.lock.json` and `packages.<project>.lock.json`, `go.sum` (module lines; a
  `/go.mod`-only line hashes a go.mod consulted while resolving, and is not a dependency) and
  `vendor/modules.txt`, the one file under `vendor/` that is read. Formats from their owners'
  documentation, quoted in the test. Vault: 13 more files read (its `go.sum` files), 21 more
  dependency rows.
- **A file hash that survives a line-ending change** (row 429): one commit checked out with CRLF
  and with LF gave different `evidence_file_sha256` for every file. The result now carries
  `evidence_file_sha256_crlf_as_lf` beside it, and each CBOM evidence file
  `qrp:sha256_crlf_as_lf`. The raw digest is unchanged.
- **The CBOM's identity does not depend on the path** (row 430): `serialNumber` is a UUIDv5 over
  the commit pin, the instrument and the findings, not the target path; `metadata.component` is
  named by the directory's own name, with the commit as its `version`. Two byte-identical trees
  at two paths now share it. Not changed: `qrp:coverage:corpus:target` still carries the path as
  given.
- **`expired` is relative to `--as-of`** (row 431), which no longer needs `--mandate`. Without it,
  SOURCE_DATE_EPOCH, else the scan's date at 00:00 UTC (`expired_basis: "scan date"`, was the
  clock, `"scan time"`), so two scans of one tree on one day carry the same certificate rows.
- **A git link checked out as a text file is counted as the link is** (row 432). With
  `core.symlinks=false` (Windows' default) git writes a link as a file holding its target; certbot's
  12 `cert.pem` links were PEM files that did not decode, and its coverage read 68.0 % on Linux
  and 71.2 % on Windows. An index entry of mode 120000 is now listed in `symlinks_not_followed`
  with `checked_out_as_text` and its target, whatever the checkout wrote.

Positive controls, against 0.42.0: OpenSSH and certbot read the same files and give the same
findings; Vault reads 13 more (5,434 of 9,281, its `go.sum` files) with the same findings.
Families are the same in all three. 41 OpenSSH rows (`sshkey_ecdsa_funcs = {`, `SSHFP_KEY_ECDSA
= 3`) moved from declaration to identifier, and one certbot and two Vault log lines to comment.
Not claimed: any change to how much of a tree's own cryptography is found.

## 0.42.0

**From 0.42.0** (core rows of the fix list; the file formats follow below). Each was
reproduced as a failing test before the fix, and each fix was reverted once to see its test fail.

- **A file read only in part is not called read.** The verdict said "This scan read every one of
  the N files" beside a certificate block that did not parse or a device configuration read by
  its words. It now says "This scan opened every one of the N files it was given; K of them were
  read only in part or gave nothing it could decode, each named with a reason" (and "; of those
  read, K ..." after "read X of Y"). A FortiOS backup (`#config-version=`), a Cisco IOS
  configuration (`crypto ikev2|isakmp|ipsec|map`) and a Junos configuration (`[edit security
  ike|ipsec]`) are named in `examined_partly` with the reason `grammar_not_parsed`.
  `coverage_pct` is not changed: it is a reading claim, and the file was read.
  Decision (Stanimir, 04.11.2026): partly read is counted separately. `coverage.scope` carries
  `read_in_part` and `read_in_full_pct` beside `coverage_pct`, the verdict names both, and the
  CBOM and SARIF carry them; `--min-coverage` still measures files opened.
- **PEM inside any text file.** A certificate in a FortiOS `set certificate "..."`, a C# raw or
  verbatim string, a Go raw string, or source concatenated with `+` is parsed, as JSON and YAML
  already were; a block that does not parse is named in `examined_partly`. A private-key block
  whose body is not a key says `key_unread` (medium), never "key material parsed".
- **`weak_key` is `null` when no size was read** for a family with a size table (RSA, DSA, DH,
  the EC families), with "not established" in the reason. It was `false`: "not weak" about a key
  whose size the scan never saw. `weak_count` and severity are unchanged.
- **Sizes read from the key-generation argument**: Node and WebCrypto `modulusLength`, PHP
  `private_key_bits`, Ruby `PKey::RSA|DSA|DH.new|generate(N)`, pycryptodome `generate(N)`,
  OpenSSL 3 `EVP_RSA_gen`, `EVP_PKEY_Q_keygen`, `set_rsa_keygen_bits`, Java
  `RSAKeyGenParameterSpec`, Rust `Rsa::generate` and `RsaPrivateKey::new`, wolfSSL
  `wc_MakeRsaKey`, IKE `modpN` (the smallest group offered on the line), and an RSA JWK's `n`
  (a `kid` label names nothing), .NET `RSA.Create(N)`, `RSACryptoServiceProvider(N)`,
  `RSACng(N)`, `DSA.Create(N)`, and PowerShell `New-SelfSignedCertificate -KeyLength N`. Not
  yet: a size on another line than the family.
- **Windows names that gave nothing**: a CNG identifier string as `BCryptOpenAlgorithmProvider`'s
  algorithm (`L"MD5"`, `TEXT("RSA")`); the digest of `New-SelfSignedCertificate -HashAlgorithm`,
  `signtool sign /fd|/td`, `certutil -hashfile FILE ALG` and `makecert -a` (SHA-1, MD5);
  `new Rfc2898DeriveBytes(...)` without a `HashAlgorithmName`, which defaults to SHA-1;
  `CipherMode.ECB` and `EncryptEcb`/`DecryptEcb` on an object named for AES. A SignTool step's
  `/fd` is its `digest_algorithm`, and a `.ps1`/`.psm1` script's signing steps are listed as a
  `.sh` script's were.
- **Static RSA key exchange in cipher lists set from code**: `SSL_CTX_set_cipher_list`,
  `SSL_CTX_set_strict_cipher_list`, `wolfSSL_CTX_set_cipher_list`, Java
  `SSLParameters.setCipherSuites`, Node's `ciphers:` option and Ruby's `ctx.ciphers =` are cipher
  settings, as Python's `set_ciphers` already was; `AES128-SHA` there is `static_rsa_kex`.
- **A TLS method function pins its version**: OpenSSL `TLSv1_method()` / `TLSv1_1_client_method()`
  / `SSLv3_method()`, Node `secureProtocol: 'TLSv1_method'`, wolfSSL `wolfTLSv1_client_method()`
  are `protocols` rows, deprecated where the version is. `TLS_method` and `SSLv23_method` pin
  nothing. Also: PyNaCl `nacl.bindings.crypto_sign_keypair()` is Ed25519, and Ruby
  `OpenSSL::PKey::DH.new|generate(N)` is DH with its size.
- **A linked directory that points into the scanned tree** no longer stops the verdict from
  accounting for every file: the walk entered its target under its own name, and the verdict
  says so ("alias/ points into the scanned tree (real/), which was walked"). A link outside the
  root still does.
- **Misread names**: `signtool sign /f codesign.pfx` is one SignTool step, not also Apple's
  `codesign` (the command is now the word followed by an option); a variable named
  `implicitSha1 = ...` is an `identifier`, not a SHA-1 call.
- **Switched off is not a use**: `echo "USE_ML_KEM_768=false" >> ...`, a SCHANNEL key with
  `"Enabled"=dword:00000000`, `Disable-TlsCipherSuite`, `Disable-TlsEccCurve` are bans, and no
  longer raise readiness.
- **Round-3 schemes by their libraries' names** are their own families, `superseded`: Bouncy
  Castle's `crystals.dilithium` classes ("Dilithium round 3") and liboqs's `OQS_SIG_alg_sphincs_*`
  ("SPHINCS+ round 3"). They were ML-DSA and SLH-DSA, `pqc_ready`.
- **A suppression can expire.** `qrp:ignore-next-line RSA until=2027-06-30 owner=j.doe <reason>`:
  `until=` and `owner=` may stand anywhere after the family. Through that day the marker
  suppresses and the suppression carries both; after it the occurrence is back in `evidence` and
  the marker is in `markers_not_applied` with "expired on <date>" (a SARIF notification on its
  line). A `until=` that is not a date does not apply. A reason that calls itself temporary
  ("temporary", "for now", "interim") with no date still applies and is listed in
  `markers_flagged`: it cannot expire. The date is compared with the day the scan runs.
- **Closure: a family that stays in the file is changed, not closed.** A verifier that keeps an
  Ed25519 branch beside the new ML-DSA one was "2 closed" with Ed25519 [2, 2] per family. An
  occurrence that left a file in which the second run finds its family again is now paired with
  that occurrence under `changed`, and the statement ends with the families not down to 0.
- **Crypto libraries a Dockerfile installs** with `apt-get|apt install`, `apk add` or
  `dnf|yum|microdnf install` (OpenSSL/libssl, GnuTLS, NSS, libsodium) are `dependencies` with
  `basis: os_package`, and the version apt or apk pins with `=`. Declared, not observed. They
  were read and gave nothing.
- **Misreads**: `createECDH('secp256k1')` is ECDH, not ECDSA; camelCase `RsaSha256` is not a
  DNSSEC algorithm; UTF-16 is read with or without a byte-order mark (Cyrillic comments, a PEM
  saved by PowerShell `Out-File`).

**From 0.42.0 (file types and grammars)**, rows 225–228, 303–306, 308, 309, 311, 313, 332, 334–337,
340, 342, 346–349, 352 and 386–388 of the fix list. Each format's settings and values are quoted
from its vendor's documentation in the test that pins it, and each fix was reverted once to see
that test fail.

- **Types that were "type not claimed" and are now read.** `.bash`/`.zsh`/`.ksh`, `.bat`/`.cmd`,
  `.mk`, Visual Basic `.vb` and F# `.fs`/`.fsx`, PowerShell data `.psd1`; `.reg` exports (UTF-16
  with a BOM included); certreq `.inf`, MSBuild `.vcxproj`/`.props`/`.targets`, WiX `.wxs`;
  `web.config`, `app.config`, `machine.config`, `applicationHost.config` and their transforms (by
  name: not every `.config`); Postfix `main.cf`/`master.cf`; ESP-IDF `sdkconfig*`; Helm `.tpl`
  and `.gotmpl`; `openid-configuration`; Gradle scripts of any name, `.gemspec`, `.podspec` and
  SwiftPM `Package.resolved` as manifests. Scripts and MSBuild files are read for signing
  commands as `.sh` was. Limits: VB's `'` and batch `::` comments are not told from code.
- **Formats read from their bytes or structure.** `.snk` strong-name keys (CryptoAPI RSA1/RSA2
  BLOB: RSA and its size); OpenPGP keys in `.asc`/`.gpg`/`.pgp`/`KEYS` (RFC 9580 key packets:
  family, size from the first MPI, curve from its OID, secret keys as key material); Apple
  `.plist`, XML or binary (ATS `NSAllowsArbitraryLoads`, `*MinimumTLSVersion`, DER keys and
  certificates in values); WireGuard (each section is X25519, fixed by the protocol; whether a
  peer sets a PresharedKey is said; the PrivateKey is key material); BIND `K*.key`/`K*.private`,
  `dsset-*`, `db.*` and a `.db` that starts like a zone file (an RSA DNSKEY's size from its RFC
  3110 key field). A file in one of these formats that does not parse is listed as not decoded.
- **TLS versions in more spellings**: Ingress-NGINX `ssl-protocols`, Istio `TLSV1_0`, Traefik
  `VersionTLS10`, Dovecot `ssl_min_protocol`, OpenVPN `tls-version-min 1.0`, Kafka and ZooKeeper
  `ssl.enabled(.)protocols`/`ssl.protocol`, MySQL `tls_version`, Postfix `smtpd_tls_protocols`
  (with `!` and `>=`), FortiOS `tlsv1-1`/`tls1-1`/`TLSv1-1`, Vault `"tls10"`.
- **IKE key exchange groups by number** (IANA IKEv2 Transform Type 4): FortiOS `set dhgrp`, Cisco
  IOS XE `group` in a `crypto ikev2 proposal`, Junos `dh-group groupN` and PFS `keys groupN` —
  each group a row with its family and size. IKE authentication by signature: Cisco `rsa-sig`,
  Junos `authentication-method rsa-/dsa-/ecdsa-signatures-NNN`.
- **Settings that switch protection off**, each a TLS place and its own CBOM component, never an
  algorithm use: Vault `tls_disable` and Helm `global.tlsDisable`, .NET
  `DontEnableSchUseStrongCrypto=true`, FortiOS `strong-crypto disable` and
  `ssl-static-key-ciphers enable` (static RSA key exchange), Kafka's empty
  `ssl.endpoint.identification.algorithm` and ZooKeeper `ssl.hostnameVerification=false`.
- **FortiOS firmware defaults.** A backup omits settings at their default. Where a section it
  carries omits `ssl-static-key-ciphers`, the SSL VPN `ssl-min/max-proto-ver`, or a phase1 entry
  omits `dhgrp`, the FortiOS 7.6.4 CLI reference's default is applied (`basis: firmware_default`,
  with the URL and the quoted row, beside the backup's own firmware version). Defaults the
  reference says "may differ between models" (`strong-crypto`, `ssl-min-proto-version`,
  `admin-https-ssl-versions`) and every other omitted setting are listed as not evaluated.
- **Names that were not in the vocabulary**: phpseclib's `RSA::createKey(N)` (with its size) and
  its `\phpseclib3\Crypt\RSA|DSA|DH|EC` classes; EC J-PAKE (RFC 8236; Mbed TLS `ecjpake`,
  `CONFIG_MBEDTLS_ECJPAKE_C`); Caddy `key_type`; PostgreSQL `password_encryption = md5` and a
  `pg_hba.conf` `md5` method; OpenVPN `auth SHA1` and `dh <file>`.

**After the merge** (rows that touched the TLS rules of both parts). Each was reproduced as a
failing test, each fix reverted once to see its test fail, and each meaning is quoted from the
vendor's documentation in the test.

- **TLS versions set from code**: .NET `SecurityProtocolType.Ssl3|Tls|Tls11` (C# and PowerShell
  `[Net.SecurityProtocolType]::Tls`), Java `setEnabledProtocols`, `SSLParameters.setProtocols` and
  the `jdk.tls.client|server.protocols` properties, Ruby `ssl_version = :TLSv1`, the Rust openssl
  crate's `SslVersion::TLS1_x`/`SSL3`, rustls `version::TLS12|TLS13` and mbedTLS
  `MBEDTLS_SSL_VERSION_TLS1_x` are `protocols` rows, deprecated where the version is (rows 378,
  406, 409, 411).
- **Static RSA key exchange and classical groups in more configurations** (rows 339, 343): a YAML
  list under Envoy's `cipher_suites`/`ecdh_curves`, Istio's and Traefik's `cipherSuites` and
  Traefik's `curvePreferences` is read item by item with its key; Ingress-NGINX `ssl-ciphers` and
  `ssl-ecdh-curve`, Dovecot `ssl_cipher_list` and `ssl_curve_list`, MySQL `ssl_cipher` and Kafka
  `ssl.cipher.suites` are cipher or group settings. `AES128-SHA` there is `static_rsa_kex`, and
  `P-256`, `CurveP256` or `X25519` is a classical group offered on its own. Limit: in a YAML list
  the hybrid and the classical group sit on different lines, so `fallback_beside_hybrid` does not
  pair them. F5 BIG-IP's `P256` is not read (its syntax was not checked against F5's documents).
- **`java.security` disabled-algorithm lists are bans on every line** (row 222).
  `jdk.tls.disabledAlgorithms` and `jdk.certpath.disabledAlgorithms` continue over lines ending
  in `\`, as the JDK's own file writes them; only the first line holds the word "disabled", so
  `MD5withRSA`, `3DES_EDE_CBC` and `ECDH` on the lines after it were read as uses. Every line of
  the two properties is now a ban, the TLS versions the TLS list names are banned `protocols` rows,
  and `java.security.<anything>` (an alternate file applied with `-Djava.security.properties`) is
  read by name. Not done: `-D...=${VAR}` as a choice made outside the files.
- **TLS group constants** (row 419): mbedTLS `MBEDTLS_SSL_IANA_TLS_GROUP_*`, wolfSSL
  `WOLFSSL_ECC_*`, BoringSSL `SSL_GROUP_*` and rustls `kx_group::*` name TLS groups; a classical
  one is a `tls_groups` row, and beside a hybrid on its line it is the hybrid's fallback. A
  `#define` or enum line defines the name and is not read. `wolfSSL_CTX_set_groups_list`'s string
  is not read.
- **strongSwan's `ecp256-ke1_mlkem768` is one hybrid** with both halves (P-256 and ML-KEM-768), an
  RFC 9370 additional key exchange (row 345). In the CBOM the hybrid depends on its ML-KEM-768 half only:
  the IKE row for `ecp256` is family EC, not ECDH, so the classical half is not linked to it. `ssh-mldsa44-ed25519` (row 353) is not added: the
  SSH ML-DSA draft names only `ssh-mldsa-44`, `-65` and `-87`.
- **A device configuration read in part says what was read and what was not** (rows 229, 333,
  re-checked after the formats rows). FortiOS `set dhgrp` and three firmware defaults, Cisco IOS XE
  `group` in a `crypto ikev2 proposal` and Junos `dh-group` are read now, so "group numbers ... are
  not parsed" was no longer true. The files stay `grammar_not_parsed` (which proposal a tunnel
  uses is still not parsed), and each `examined_partly` entry carries `read` and `not_read`.

On the corpus of 185 public repositories (disagreement with a model, never recall or precision),
against 0.41.0: on the 140 training repositories the scanner is silent on 395 chunks where the
labeller sees a named algorithm (404 before) and reports on 261 where the labeller does not (244
before); on the 45 held out, silent on 71 (71 before) and reporting on 42 (40 before). All 19 more of the second kind are
certificates in source strings, now decoded (row 301): the labeller reads the text, and the RSA
or ECDSA key inside a base64 block is not named in it. The regression script exits 1 on that
rise; each of the 19 was checked to be a line of a certificate block before release.

## 0.41.0

**From 0.41.0**, a batch of the fix list (rows 160, 196, 200–206, 208–211, and six rows from a
comparison with another scanner on Hyperledger Fabric). Most were places where the output said more
than the scan had seen. Each was reproduced as a failing test before the fix, and each fix was
reverted once to see its test fail.

- **An unread certificate is not an absent one** (row 200). nginx naming its certificate and key
  at paths outside the tree (`ssl_certificate /etc/...`) left `by_role.signature` at `none_found`.
  The places are now in `tls_termination.authentication_not_read` (nginx `ssl_certificate[_key]`,
  Apache `SSLCertificate[Key]File`, HAProxy `crt`), and the signature part reads
  `not_established` with the reason. A named file whose name is among the files read counts as read.
- **The headline shows the split** (row 200). Beside `pqc_readiness`, `summary.readiness_by_role`
  gives the key-establishment and signature values and `roles_differ`. The headline word itself is
  unchanged.
- **The `--mandate nist-ir-8547` gate counts 2030** (row 160). It counted the disallowance
  (2035-12-31) while `next_deadline` said 2030-12-31; it now counts the deprecation
  (`gate_counts: deprecated_after`). ⚠️ This changes exit codes: from November 2026, with
  `--lead-months 50` or more, a run that passed now exits 1.
- **A gate over files not read is not a pass** (row 204). Where it would pass while files went
  unread (a `.jar`, a `.so`), `gate` reads `not_established` and `gate_not_established_because`
  gives the count. The exit code of that case stays 0, as for a pass; a fail is still a fail.
  **`--min-coverage PERCENT`** (with `--mandate`) makes it a failure: when fewer than PERCENT of the
  files present were read (`coverage.scope.coverage_pct`), the gate is `fail`, exit 1, and
  `gate_failed_because` says how many files were not read. Without the flag nothing changes. It is
  a command-line option only (not in `.qrp.toml`, and the MCP tools have no gate).
- **A switch set off is not a use** (rows 203, 196). `USE_RSA = False` and Kconfig
  `CONFIG_ECDSA=n` are bans now, as `!MD5` is; switched on they are uses as before. A list named
  LEGACY (`LEGACY_ALGS = ["RSA-PSS", "DSA"]`) is an identifier row: low, not counted in the
  headline or `by_role`.
- **AWS KMS `RSAES_OAEP_SHA_1|256` is a key spec** (row 208), as `KeySpec.RSA_2048` was: RSA key
  transport beside an ML-KEM key no longer leaves key establishment reading `pqc_ready`.
- **The parameter set against the profile** (row 210). Under `--profile au-ism` (and `us-cnsa2`),
  an ML-KEM or ML-DSA finding whose parameter set the document limits carries
  `profile_parameter_sets` with the document's words (ML-KEM-768: "will not be approved beyond
  2030"), on the finding and on its part in `by_role`. Under `--mandate cnsa-2.0` such an
  occurrence gets the status `parameter_set_not_in_mandate`, with no deadline; the gate is not
  moved by it. The classification stays `pqc_ready`.
- **The size and use beside the algorithm** (rows 201, 205, 209, 211, 196). In a Terraform or
  configuration block: Vault `key_bits`, Azure Key Vault `key_size` and `key_opts`, AWS KMS
  `customer_master_key_spec = "RSA_3072"` and `key_usage`, a Vault root or intermediate CA (whose
  key signs); on the line: `CONFIG_..._RSA_LEN=2048`, `"rsa2048"`. Fabric CA's
  `keyrequest: algo/size` and cfssl's `"key": {"algo", "size"}` give the family and the size (ECDSA
  256/384/521 as P-256/P-384/P-521). An INI section header now ends a block.
- **Hyperledger Fabric's BCCSP** gives ECDSA and its curve: `Default: SW` with `Security: 256|384`
  is P-256 or P-384 (Fabric `bccsp/sw`, v2.5.9); `Default: PKCS11` the same with `key_held: hsm`.
- **PEM inside JSON and YAML is parsed**: a certificate in a JSON string (`\n` escapes, as in a
  Fabric connection profile) or an indented YAML block scalar is a row at its BEGIN line, a key's
  family joins its embedded-key row, and a block that does not parse is listed with its reason.
- **The CBOM primitive of RSA and EC follows the role**: all signature → `signature`; all key
  establishment → `key-agree` for EC, `pke` for RSA; undetermined or mixed, EC is `unknown`
  (it was `pke`) and RSA stays `pke`.
- **IBM MQ `.mqsc` is read** (row 202): a channel's `SSLCIPH(TLS_RSA_WITH_...)` gives RSA key
  establishment. An empty `SSLCIPH` (a channel without TLS) is not detected.
- **`bind ssl ...` is not an HAProxy listener** (row 206): NetScaler-style `bind ssl profile` lines
  read as "TLS is terminated here (HAProxy ...)". The algorithms on them are found as before;
  `ns.conf` itself (front end and back end, its curve names) is not read.

⚠️ What is not claimed: no detection figure in this README was re-measured.

## 0.40.1

**From 0.40.1**, on Windows a file reached through a link swapped in after the walk is refused
when it lies outside the scanned tree (row 150, the last three tests). Windows has no `dir_fd` and
no `O_NOFOLLOW`, so the open still follows the link; the opened handle is then asked where it ended
up (`GetFinalPathNameByHandleW`) and the file is named in `unreadable_files` instead of read. A link
that stays inside the tree is read as before. Run on Windows (Python 3.12): the whole suite passes,
and with the check removed exactly these tests fail. Nothing changes on Linux or macOS, and no
detection figure moves.

## 0.40.0

**From 0.40.0**, a batch of the fix list (rows 99, 107, 109–112, 115, 117, 129, 150, 152, 154). Each
was reproduced as a failing test before the fix, and each fix was reverted once to see its test fail.

- **`scan` masks quoted lines by default** (row 152), on stdout, in `--out` and in `--format sarif`,
  as `cbom` has since 0.16.0. The file a client sends for a report is exactly `scan --out`, and it
  carried whole lines unless the command said otherwise. `--level full` (or a level in `.qrp.toml`)
  still gives the whole line. What is found does not change, only how a line is quoted.
- **A classical fallback beside a hybrid is marked** (row 99). `X25519MLKEM768:X25519` and
  `X25519MLKEM768` read the same; now the finding carries `fallback_beside_hybrid`, the summary
  `by_role.key_establishment.fallback_beside_hybrid`, and the CBOM `qrp:fallback_beside_hybrid`.
  X25519 counts as classical in both cases, as before.
- **A pinned image whose support is not established does not headline a hybrid** (row 117), when
  every use of the post-quantum family is such a place; a Dockerfile `FROM` is now a pin too
  (row 110), named beside the groups and joined to nothing, since it mounts nothing.
- **Commented settings are not settings** (row 107): `# ssl_protocols TLSv1` no longer makes a
  protocol asset. On OpenSSH and certbot the findings, the families and the verdict are the same
  as in 0.39.0.
- **Libreswan `ppk=` other than `insist` is optional** (row 109), checked against ipsec.conf(5)
  of v3.32, v4.0 and v4.12; Caddyfile `curves` / `protocols` are a TLS place (row 111); TPM 2.0
  names (`TPM2_ALG_RSA`, `tpm2_createek -G rsa`) are found (row 115); an EC family whose every line
  names a curve is a component such as `EC-P-256` in the CBOM (row 129).
- **The weak-key bound is said where the check ran** (row 154): `weak_key_check` gives the bound
  (256), how many keys were checked and "checked up to 256"; `null` when no EC key was read.
- **CODEOWNERS handles are masked** at `masked` and `trimmed` (row 112).
- **Windows** (row 150): a key file without an extension and with CRLF endings was never opened,
  and `files_left_out` used the OS separator; both fixed. Three tests still could not pass there:
  Windows has no `dir_fd` and no `O_NOFOLLOW`, so a link swapped in after the walk was followed
  (closed in 0.40.1, above).

On the corpus of 185 public repositories the disagreement with the labelling model is unchanged in
both splits (A' 404 / 71, B' 244 / 40); that is disagreement with a model, not recall or precision.

## 0.39.0

**From 0.39.0**, rows 179–185 of the fix list: what a reader of the CBOM alone could not get.
Every field below is in the scan JSON and in the CBOM, through `qrp-mcp cbom` and `export_cbom`.

- **DH, DSA and EC below their minimum are weak keys** (row 179, found in our own probe of
  31 Oct 2026). `dh.generate_parameters(key_size=512)` was read as DH-512 and reported
  `weak_key: false`, severity high, beside a critical RSA-1024: the check covered RSA only, and no
  other family's size was parsed. Each family is now held to its own minimum — RSA, DSA and
  finite-field DH 2048 bits, the EC families 224 — and the reason names the table.
- **A JCA size on the `getInstance` line** (row 180). `getInstance("DH"); g.initialize(512);` gave
  DH with no size; that branch now reads `.initialize(N)` for RSA, DSA and DH, as the other rules
  did. A size set on another line is still not read.
- **`undetermined`, said** (row 181). An RSA, DSA, DH or EC occurrence whose line gives no size
  has `key_size: "undetermined"` in the evidence instead of no field; a curve or a parameter set
  already names the size. In the CBOM every RSA, DSA, DH and EC component has `qrp:key_size`:
  the size, `undetermined`, `set by the curve …`, or `several: see qrp:observedKeySizes`.
- **The classical status, with its source** (row 182). `classical_status` on the finding (for its
  smallest size) and `qrp:classical_status` / `qrp:classical_status_source` on each CBOM component
  (for that component's own size): `broken_in_public` at or below 795 bits for RSA, DSA and DH — a
  795-bit RSA modulus was factored and a 795-bit prime-field discrete logarithm computed in public
  (ePrint 2020/697); that key itself was not — `disallowed` below the minimum of NIST SP 800-131A
  Rev. 2 (March 2019), Tables 2, 4 and 5, `acceptable` for RSA at 2048 or more, and
  `meets_minimum_length` for DSA, DH and EC at the minimum, because the scan reads one number:
  len(q), the (L, N) pair, SP 800-56A conformance and whether a curve is a listed one are not
  read. `undetermined` where no size was read. Not on a post-quantum or fixed-size component
  (X25519, Ed25519): SP 800-131A Rev. 2 sets no size for them. Every one of these is still
  quantum-vulnerable; the status is the classical question only.
- **Present, not enabled** (row 183). OpenSSH compiles XMSS only when `WITH_XMSS` is defined, and
  its build files never define it (checked at V_9_9_P1: every XMSS file and the XMSS entries of
  `keyimpls[]` sit under `#ifdef WITH_XMSS`; configure.ac and Makefile.in do not name it). Where a
  tree has preprocessor conditions on `WITH_XMSS` and no other line in any file names the macro,
  the XMSS finding carries `not_enabled` (CBOM: `qrp:not_enabled`), keeps `pqc_ready` — that is
  about the algorithm — and is no longer counted in `pqc_readiness` or `by_role`. On OpenSSH 9.9
  the signature part goes from `hybrid_partial` to `classical_only`. One switch, verified at the
  source; other build switches are not judged.
- **The role reaches the CBOM** (row 184). Until now `role` stopped at the scan JSON, and RSA
  arrived in the CBOM as `primitive: pke` only. `qrp:role` is one value per occurrence, in the
  order of `evidence.occurrences` — `signature`, `key_establishment`, `undetermined`, or `not
  read` — on RSA and EC components; read from one line, with the limits measured under *The role
  of an RSA or EC line*.
- **ML-KEM offered or preferred** (row 185). Where ML-KEM sits in an SSH `KexAlgorithms` list or a
  TLS group setting, the occurrence carries `order` (setting, position, `of`, `first`,
  `preferred`, whose list it is; only the setting's value is read, not the rest of the line) and the finding `negotiation`; in the CBOM, `qrp:negotiation`
  per occurrence. For SSH, RFC 4253 §7.1: the first algorithm on the client's list that the
  server also supports is chosen, so the head of an `sshd_config` list is the server's preference
  and not what a connection uses. `+` (appended to defaults) gives no position. For TLS only the
  position is stated: who decides is the library's setting, not read. Without such a list:
  `seen in code only`. No connection is made.

## 0.38.0

**From 0.38.0**, the fixes promised in public comments and the rows of the fix list since 0.37.0:
- **`--mandate nist-ir-8547` follows the final NIST IR 8547 (October 2026).** Every
  quantum-vulnerable signature and key establishment is deprecated after 2030 and disallowed
  after 2035, whatever its strength; the November 2024 draft spared RSA-3072, P-256 and Ed25519
  the 2030 date. X25519 and X448 get their strength from their names. The classical half of a
  hybrid group on the line that names it (`X25519MLKEM768`) is `composite_allowed` (section
  3.2.1) and not HNDL-exposed; a classical group offered on its own in the same list
  (`X25519MLKEM768:X25519`) keeps its dates. The block names the date the gate counts
  (`gate_counts`, `next_gate_deadline`) beside `next_deadline`, the earliest date of any clause.
  The gate itself still counted the disallowance, as before (until 0.41.0, which counts 2030).
- **A fingerprint of the findings beside the file's digest** (row 178, from Mark McGovern's
  reply): see *Without an agent*. Two scans of one commit now print the same `findings sha256`
  and, as before, different file digests.
- **The pinned version travels** (row 165). A dependency row has `version` where
  the manifest pins one (`cryptography==45.0.4` in requirements.txt or go.mod, a single `==` in
  pyproject.toml or a Pipfile); a range is not a version and gives none. The CBOM `library`
  component carries it as `version`, or `qrp:versions_pinned` with every pin where manifests
  disagree. Which default key exchange a library version brings is not resolved.
- **Python's `ssl.TLSVersion`** (row 166): `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` is a
  protocol row and a TLS place, as pyOpenSSL's `set_min_proto_version` already was.
- **A TLS default is said, not left blank** (rows 164, 167). Where the tree
  configures TLS and no file sets a group or curve, `tls_termination.key_exchange` says the
  library's default applies and is not resolved, with the library versions the manifests pin;
  each TLS protocol asset says `key_exchange: "library default, not resolved"` (in the CBOM,
  `qrp:key_exchange`). Where no key-establishment family was found either, the headline is
  `not_established` with that reason instead of `unknown`, which now means only that nothing was
  found; `by_role.key_establishment` says `not_established` too. The default is not computed from
  the version: OpenSSL 3.5 offers a hybrid first, earlier versions a classical group, and what a
  deployed build does is not in the files.
- **An occurrence nobody owns is said** (row 174, Michael Wegger). With a CODEOWNERS file, each
  occurrence in a path no line covers carries `unowned_by: <that file>`, `codeowners.unowned`
  counts and lists them, and the CBOM occurrence reads `[owners: none per <file>]`. Owners are
  still the file's assumption, not a fact.
- **An AWS TLS policy the table does not hold is named** (row 175, Tokunbo Taiwo). An
  `ELBSecurityPolicy-*` name set as `ssl_policy`/`SslPolicy` that is not in the table is a TLS
  protocol asset with `policy_known: false` and "not determined" versions and groups; the
  listener is a TLS place, and the headline is `not_established` naming the policy. It claims
  no algorithm. Before, the listener dropped out: 0 findings, "read every one of the 1 files".
- **A declaration says where it is imported** (row 157, Caleb Montour, Magpie Projects). A PyPI
  or npm dependency row gets `imported_in` (the first ten `path:line`), `imported_count` and
  `imported`, a sentence the CBOM occurrence carries too; it stays `declared_dependency`, because
  an import does not say which algorithm a call uses. These are read from other files, so they are
  not part of the row's identity in `closure` or a baseline. `dependencies_not_in_table` lists the packages requirements.txt, pyproject.toml, Pipfile
  or package.json declare that the library table does not hold: whether they carry cryptography
  (a provider's SDK doing TLS inside) is not determined. Lockfiles are not listed there.
- **The size beside the algorithm, and a choice made outside the files** (rows 156, 176, Peter
  van Walsem). `algorithm: RSA` with `key_size: 2048` in the same YAML block, or Terraform's
  `algorithm = "RSA"` with `rsa_bits = 4096`, now gives the size. A cryptographic setting whose
  value is read at run time -- `set_ciphers(os.environ[...])`, `JWT_ALGORITHM: ${{ vars.X }}`,
  `$VAR` or `${VAR}` in a file -- is listed in `chosen_outside_files` with the setting and where
  the value comes from (counted in the CBOM as `qrp:chosen_outside_files:count`); no family is
  claimed for it, and what the environment holds is not read. Its quoted line follows `--level`.
- **RSA-OAEP encryption is key establishment** (row 161, Joeri Barbier). pyca's
  `pub.encrypt(k, padding.OAEP(...))` was `role: undetermined`, because the rule's description
  ("signature or padding name") was read as a signature signal beside the line's OAEP; it no
  longer is, so the line is key transport and, under `--mandate`, HNDL-exposed. On the four
  control trees one line moved the other way: paramiko's `padding=padding.PKCS1v15(),` is now
  `undetermined` (PKCS#1 v1.5 pads both encryption and signatures; it was `signature` only by
  that description).
- **A group setting's family comes from its values** (row 172a). `ssl_ecdh_curve MLKEM768;`, a
  post-quantum group alone, reported ECDH because the directive is called `ecdh_curve`, and read
  `hybrid_partial`. On a group setting whose values name no classical elliptic-curve group, ECDH
  is not reported; `secp384r1` and `X25519MLKEM768` keep it.
- **A recoverable key flags its own signature** (row 155). A self-signed certificate whose key is
  `4*G` gave `EC-384` critical and `ECDSA-384` not weak, one key in two rows. Where the
  certificate's self-signature verifies, the signature's family is flagged too, saying it is the
  same key; a certificate signed by another key leaves the issuer's signature as it was.
- **How each occurrence was found reaches the CBOM** (row 149). `qrp:evidence_kind` on a
  component lists, per occurrence and in order, `call`, `declaration`, `import`, `reference`,
  `default` or an asset's basis, as `qrp:confidence` lists the levels; a CycloneDX 1.6 occurrence
  takes no properties of its own.

## 0.37.0

**From 0.37.0**, the work of releases A to E and of round 3 (the commits after `v0.36.0`):

- **For CI.** `qrp-mcp scan PATH --format sarif` writes SARIF 2.1.0; every file not read is a
  notification with its reason. `qrp:ignore <family> <reason>` and
  `qrp:ignore-next-line <family> <reason>` suppress a row, which is listed and counted, never
  dropped; a marker without a family and a reason does not apply and is listed. `--write-baseline`
  / `--baseline` mark rows new or baselined, and the counts are in `coverage.baseline`. A
  `.qrp.toml` (profile, level, exclude, baseline, mandate, lead_months) is read unless
  `--no-config`; the command line wins. `--mandate cnsa-2.0|nist-ir-8547` gives each
  quantum-vulnerable occurrence its dated clause and `hndl_exposed`, and with `--lead-months`
  the run exits 1 when a deadline falls inside the lead time. On Python 3.10 `tomli` is a
  dependency, so `.qrp.toml` is read there too.
- **The document names the code that ran.** `version` is the running code's, and a disagreeing
  installed distribution is said beside it; `instrument.revision` gives the commit or the absence
  of one in words; `dirty` looks at the package directory only. The CBOM is byte-identical across
  two runs over one tree: its timestamp is `SOURCE_DATE_EPOCH`, else the commit time of a clean
  checkout, else absent. Every file the evidence cites carries its SHA-256. An installed wheel
  built from a git checkout names the commit it was built from (`source_commit.basis:
  built_from`, `revision: "<commit> (built from)"`); one built without git still says
  `no_checkout`. Two runs of wheels built from one commit can be compared by `prove_closure`.
- **Reports in the tree are not cryptography.** A CycloneDX document, a qrp-mcp result, a SARIF
  log, a baseline and a `.qrp.toml` are named as report documents and not matched; a CycloneDX
  document another tool wrote is listed as a supplier's declaration, for `--ingest`.
- **The CBOM carries more.** OID, NIST and classical security levels, `cryptoFunctions` and the
  curve on algorithm assets; one component per key size or parameter set, with the key length
  wherever the files give one; a hybrid as a component that depends on its two halves; one
  library component per bom-ref however the manifests spell it; certificates, parsed with
  `cryptography`, as certificate assets with their subject key nested; `non_security_use` on the
  occurrence. From 0.40.0 (row 129) the curve also comes from code: an EC, ECDSA or ECDH row whose
  line names exactly one NIST prime curve (`ec.SECP256R1()`, `prime256v1`, `elliptic.P384()`,
  `secp521r1`) carries `curve`, and its component the field; two curves on one line name none.
- **Every occurrence carries a confidence** (high, medium, low) and its basis, in the scan
  JSON, SARIF (`rank`) and the CBOM; see *How sure the scan is of each occurrence*.
- **Detection.** Algorithm names from the IANA SSH, TLS, JOSE and COSE registries, OpenSSH's
  and OpenSSL's own name lists and PEM labels; a family as a component of an identifier, in a
  file with other cryptography, at low confidence; XML-DSig URIs, pyOpenSSL types, DH-parameter
  calls, key specs, COSE constants and SSH key-exchange messages; Jinja templates, SSH key file
  names, key types in tasks, DH parameters and sshd RSA options in configuration; Rust types and
  variants; cipher strings split at `+`, GnuTLS priorities and C suite tables; curl's crypto API
  by its prefix; OpenSSL's curves API as EC key agreement and `ffdhe*` as DH; dependencies in
  `pyproject.toml` and `Pipfile`, as requested; `crypto-js`; algorithm settings in `.properties`
  joined to `getProperty` (a fallback default is low); key-type values in a key-type context;
  `usedforsecurity=False` as the role `non_security_use`; sops, age and OpenPGP secrets at rest,
  with HNDL; uses reached through an alias, folded literals or another file's constant.
- **Read as what they are.** A Go `func` signature is a type reference; a suite part or key-type
  value in a comment is a comment; libcrux's `DsaXof` and an ML-DSA component are not DSA, a
  KEM's DH is not DH; the JDK's `EdECKey` is EdDSA; a Python test whose docstring says an option
  is removed or disabled is a rejection test, and an expected error message is text; an OpenSSH
  `.cert` and a DER request are not unparsed certificates. ECDSA and EdDSA names are not DSA:
  .NET's `eCDsa`, `testEcDsa256`, `EdDSA25519`; nor is the signature encoding DSA and ECDSA
  share, pyca's `encode_dss_signature`, `DssRawSignatureVerifier`, .NET's `DSASignatureFormat`.
- **Identifier rows never move the headline.** A family whose every use is an identifier row
  stays a finding, marked `identifier_only`, and is not counted in `pqc_readiness` or `by_role`;
  identifier rows set no RSA or EC role. In SARIF an identifier row is a `note`, as a comment
  is, and `--mandate` gives it no clause, so it counts in no block and trips no gate.
- **Speed.** One search per file finds the lines a rule could match; files are read in parallel
  (`QRP_MCP_JOBS`); a compiled line gate, `qrp-mcp-core`, is used when installed
  (`QRP_MCP_CORE=0` turns it off; the answers are the same); the rules' compiled form is cached on
  disk (`QRP_MCP_CACHE=0` turns it off); the MCP SDK and pydantic are no longer imported on the
  scan path. `qrp-mcp-core` installs with qrp-mcp, as a wheel, on CPython for Linux x86_64 and
  aarch64, macOS x86_64 and arm64, and Windows AMD64 and ARM64; elsewhere qrp-mcp is pure Python.
  On an Intel i5-3340M (warm median): with the core, curl takes 1.35 s and OpenSSH 2.20 s, faster
  than qScan 0.12.0 (4.16 s, 2.32 s) and slower than cipherscope 0.3.0, which is compiled (0.94 s,
  1.10 s). Without it, curl takes 3.48 s and OpenSSH 4.02 s: still faster than qScan on curl, and
  slower than qScan on OpenSSH. How it was timed is in *How it is measured*.

⚠️ What is not claimed here: a detection figure. The rules of round 3 were written against corpora
read for that purpose; what they do on code nobody has read is what the final judgement of 0.37.0
measured, and its results are in *How it is measured*.

## 0.36.0

**From 0.36.0**, after a measurement of 23 Oct 2026 that took the names each crypto library
publishes in its own public headers (OpenSSL, BoringSSL, Mbed TLS, wolfSSL, libsodium, liboqs,
NSS, GnuTLS, libgcrypt, libssh2) and from registries and language APIs (JCA/Bouncy Castle, Go,
.NET, Rust, Python, IANA TLS/SSH/DNSSEC/JOSE/COSE), and ran every name through the scanner. Rules
written from examples found the examples; the names below were missed:

- **An algorithm as a whole part of a library identifier.** A name that starts with a prefix the
  library owns is split at `_` and case changes, and each part that names an algorithm reports
  its family: `GNUTLS_SIGN_DSA_SHA256`, `GCRY_MD_SHA1`, `LIBSSH2_HOSTKEY_HASH_MD5`,
  `PSA_WANT_ALG_*`, `OPENSSL_NO_DSA`, `RSA_R_*` error codes, `d2i_DSAPublicKey`,
  `PEM_write_bio_RSAPrivateKey`, `gnutls_pubkey_export_rsa_raw`. Without a prefix only OpenSSL's
  module API counts, and only where it is called or declared (`DSA_free(`, `SHA224_Init(`):
  `DH_STATUS_OK`, `DESCRIPTION` and `rsa_logo_draw` stay silent, and `ML_DSA` is not DSA.
- **OIDs, by name and by number.** `NID_`/`SN_`/`LN_`/`OBJ_`/`SEC_OID_` names, X.509 object names
  as strings (`sha1WithRSAEncryption`, `id-ecPublicKey`), and the well-known dotted OIDs from their
  RFCs (`"1.2.840.113549.1.1.5"` is RSA with SHA-1), also as Go `asn1.ObjectIdentifier{…}`.
- **PKCS#11:** `CKK_*`, `CKM_*` and `CKA_*` name the algorithm (`CKK_RSA`, `CKM_ECMQV_DERIVE`).
- **Cipher suites name what they imply:** OpenSSL's `TLS1_CK_*`/`SSL3_CK_*`, JSSE `SSL_*`, and
  OpenSSL strings such as `DES-CBC-SHA` and `EXP-RC4-MD5` now report the RSA or DH they leave
  unspoken, and the SHA-1 of the record MAC.
- **Headers, C types and classes:** `<openssl/ec.h>`, `<mbedtls/dhm.h>`, `EC_GROUP`, `MD5_CTX`,
  `RC4_KEY`, Bouncy Castle and JCA classes such as `DSASigner`, `ECDHBasicAgreement`,
  `RSAKeyGenParameterSpec`.
- **JCA and Bouncy Castle spellings:** `SHA256WithRSAEncryption`, `SHA256/RSA`,
  `…inP1363Format`, PSS/OAEP/`PKCS1v15()`, ECIES/ECMQV/det-ECDSA, PBE names with their digest
  and cipher, ElGamal.
- **Families that were not in the vocabulary:** GOST R 34.10, SM2 (reported as EC before),
  ElGamal — all quantum-vulnerable; MD2, MD4 and RC2 as weak; HAETAE, SMAUG-T and AIMer as
  candidates, never `pqc_ready`; BIKE, NTRU LPRime, XMSS^MT and LMS/HSS class names.
- **Language qualifiers:** Go `dsa.`, `elliptic.`, `crypto.SHA1`, `x509.DSA`, `ssh.KeyAlgoRSA`;
  Rust `k256::`, rustls and ring constants; .NET Cng types, padding modes and CryptoConfig
  names; pycryptodome `RSA.generate`, python-rsa.
- **Protocol settings:** TLS SignatureScheme `rsa_pss_*`/`rsa_pkcs1_*`; sshd `des-cbc`,
  `hmac-md5`, `curve448`; strongSwan proposals; rare `Groups =` curves; DNSSEC `dsa`, GOST and
  SM2; JOSE/COSE `RS1`, `HPKE-*` and numbers; JWK `"kty":"EC"`.
- **Both halves of a hybrid:** `MLDsa65WithECDsaP256`, `ssh-mldsa87-p384`,
  `KeyExchangeMLKEM768X25519`, `SHA512WITHMLDSA65`.
- **SHA-1 joined to something** (`HmacSHA1`, `SHA1_`, `-SHA1`), never `sha1sum` or a sentence;
  X448 in camelCase, all `efrodokem_*`, the LMS constants of wolfSSL, liboqs and Mbed TLS.

Two policies decided with it. **MD5, SHA-1 or DES used as a MAC, PRF or KDF is reported**, under
the hash or cipher, and its description says the use and that a quantum computer does not break
it: an inventory that drops a use silently is the defect we would name in another tool. **An
algorithm named in prose is not a finding** — in a comment, as before, and now in a sentence
inside a string (`"supports Ed25519 and ML-KEM"`: three or more words, one of them a word
only prose uses); it goes to `named_but_not_used`. A name as
a whole part of an identifier is a finding.

On OpenSSH the files read (740 of 873, 84.77%), the readiness by role and the verdict are the same
as in 0.35.0; the findings grow from 65 to 70 (DES, GOST R 34.10 from the bundled `pkcs11.h`,
RC4, SHA-224, SHA3-224 are new families) and the evidence from 8,016 to 8,659 lines; no family
loses a line. On certbot the files read (832 of 1,250), the findings and the readiness are the
same; the evidence grows from 628 to 656 lines (TSIG `HMAC-SHA1`, `-SHA` suites in server
configs, pyca `ec.EllipticCurve*`). No family loses an evidence line in either. A scan of OpenSSH
took 28 s against 26 s for 0.35.0 on the same machine (one run each).

⚠️ What is not claimed: recall on real code. The rules were written against the measured names;
how much of a real codebase's cryptography is named this way was not measured. Still not seen:
the inside of a certificate (a PEM file is reported, not what signed it) and TPM 2.0 names.

## 0.35.0

**From 0.35.0**, after three probes of 22 and 23 Oct 2026 — a swarm that wrote each library's
own spellings as tests, a corpus probe with the expected inventory written before the scan,
and points raised on LinkedIn — what is read and named grows, and the summary says more:

- **Library spellings, each checked against the library's source.** OpenSSL's `DSA_sign`,
  `DH_compute_key`, `NID_ffdhe*`, `EVP_PKEY_CTX_set_rsa_*`, `RSA_size`, `MD5()`/`SHA1()`,
  `DES_ecb3_encrypt` and the `rsa.h`/`dsa.h`/`dh.h`/`md5.h` headers; Ed25519 glued into an
  identifier (`ED25519_sign`, `EVP_PKEY_ED25519`, `Ed25519PrivateKey`, `ed25519_dalek`,
  `x509.PureEd25519`); libsodium and PyNaCl (`crypto_sign_detached` is Ed25519, `crypto_box_*`,
  `crypto_kx_*`, `crypto_scalarmult*` and `nacl.public` are X25519 — not the
  `crypto_sign_keypair`/`crypto_sign_open` every post-quantum reference implementation also
  exports); JCA names by a table (`KeyFactory`/`KeyAgreement`, `DH`, `XDH` — X25519 unless
  initialised otherwise — `DES`, `DESede`, `ARCFOUR`, `SHA`, BCPQC `Falcon`) and the JCA EC types
  (`ECGenParameterSpec`, `ECPublicKey` …); Node's `'rsa-pss'`/`'dsa'`/`'dh'` key types,
  `crypto.publicEncrypt` and friends, `'des-cbc'`, node-forge `pki.rsa`; .NET `DSA.Create`,
  `DES.Create`, `SHA1/MD5.HashData`, `HashAlgorithmName.SHA1`, `CngAlgorithm.Rsa`;
  pycryptodome (`ECC`, `pkcs1_15`, `pss`, `PKCS1_OAEP`, `DES`, `DES3`, `Hash.MD5/SHA1`), python-rsa
  `newkeys`, paramiko `DSSKey`; wolfCrypt's whole classical API (`wc_*Rsa*`, `wc_ecc_*`,
  `wc_Dh*`, `wc_Md5*`, `wc_Sha*`, `wc_Des3_*`, `wc_falcon_*`) and headers; Mbed TLS `dhm`, `ecp`,
  `md5`, `sha1`, `des`, `des3` and the PSA RSA/DH/ECC key types; Bouncy Castle's `RSAEngine`,
  `DESEngine`, `RC4Engine`, `MD5Digest`, `SHA1Digest`, `FalconSigner`; ring/aws-lc-rs
  `RsaKeyPair` and `RSA_PKCS1_*`, rustls `SignatureScheme::RSA_PSS_*`, RustCrypto `Md5`/`Sha1`,
  `p256::`, `@noble/curves`; strongSwan's `KEY_RSA`, `SIGN_RSA_*`, `ENCRYPT_RSA_*` and `MODP_*`
  (OpenSSH's `KEY_RSA` too); liboqs's HQC by level (`hqc_1`) and UOV as `uov_ov_*`/`OV_*`;
  Falcon's padded variant; X-Wing (ML-KEM-768 + X25519, both halves) and CIRCL's
  `eddilithium2/3` (with their Ed25519/Ed448 halves); the classical half of oqs-provider's
  hybrids (`p384_mlkem768` is ECDH + ML-KEM, `p256_mldsa44` ECDSA + ML-DSA, `rsa3072_*` RSA).
  Three deliberate differences from the probe's expectation: pycryptodome's
  `Crypto.Protocol.DH` takes only ECC keys and is ECDH, not DH; `Crypto.Signature.DSS` signs
  with a DSA or an ECC key, so its import names neither; Go's `tls.CurveP256` is ECDH, as the
  TLS group table already files it.
- **Four lookalikes are not the algorithm.** `LMS_SHARED_SECRET` (not HSS/LMS),
  `personal_signature` (not the `personal_sign` call), Node's `createSign('SHA256')` (the key
  decides; `createSign('RSA-SHA256')` is still RSA) and `ml_dsa.sign` (not DSA).
- **Files that were "no extension" or "type not claimed".** `Dockerfile`, `Dockerfile-*`,
  `*.Dockerfile`, `Containerfile`, `Kconfig*`, a `Caddyfile`, extensionless files under
  `mods-available`/`mods-enabled`/`sites-available`/`sites-enabled` (FreeRADIUS's EAP-TLS module,
  Debian's nginx sites), `.jsx`/`.tsx`, and the Java keystores `.jks`/`.keystore`, whose
  certificates are clear DER. A lockfile is still read for its packages and no longer matched as
  source: `ecdsa-sig-formatter` in a `package-lock.json` was "ECDSA usage".
- **A TLS group offered alone is a finding of its family.** `Groups = x448:mlkem768` put X448 in
  `evidence.tls_groups` and nowhere else, and the summary said `pqc_ready`; `ffdhe2048` likewise
  gives DH.
- **What a PKCS#12 file says in clear.** Its bag encryption (`pbeWithSHAAnd40BitRC2-CBC` → RC2,
  `…3-KeyTripleDES-CBC` → 3DES, the RC4 forms) and its SHA-1 MAC are named from the unencrypted
  wrapper; the file is still `claimed_but_not_decoded`, because the bags were not read. RC2 is a
  new weak family.
- **COSE algorithm identifiers** on a WebAuthn or COSE line (`{"type": "public-key", "alg": -7}`
  is ES256), from IANA's registry. A bare `"alg": -7` stays a number.
- **RFC 8784, two narrowings.** strongSwan's `ppk_required` defaults to `no` (its swanctl.opt),
  so a `ppk_id` without `ppk_required = yes` is an optional PPK and protects nothing; and a family
  is protected only when every use of it sits under a required PPK — EC in a second tunnel
  without one was counted protected by the first. From 0.40.0 the same for Libreswan: only
  `ppk=insist` requires the PPK (ipsec.conf(5): `propose` or `yes`, the default, proposes it),
  so any other value protects nothing.
- **Two shapes of the denial block.** A block a condition opens (`} catch
  (UnsupportedAlgorithmError) {`) is the code that runs then, not a list of banned names, so a
  declaration inside it is a use; a `pytest.raises`/`assertRaises` block whose line says
  "unsupported" is a test that the call inside is rejected, so the call is a ban.
- **Who owns a place.** `.github/CODEOWNERS`, `CODEOWNERS` or `docs/CODEOWNERS` (GitHub's order;
  then `.gitlab/CODEOWNERS`) is read, never matched for algorithms, and every evidence item gets
  `owners` and `owners_source` (`.github/CODEOWNERS:3`) from the last matching line — per place,
  not per component, because one algorithm sits in many teams' code. In the CBOM it is an
  `[owners: … per FILE:N]` tag on the occurrence: the schema has no field for it. It is the
  file's assumption, not a fact about who runs the code; `codeowners` says which file was used.
  From 0.40.0 the handles are masked like a quoted line (`@****/******-****`) at every level
  but `full` (row 112); the file and line they come from stay.
- **Key establishment and signatures apart.** `summary.by_role` gives each its families and its
  own readiness: nginx offering X25519MLKEM768 with an ECDSA certificate is `hybrid_partial` for
  key establishment and `classical_only` for signatures, where the whole read only
  `hybrid_partial`. RSA and EC go where their lines' roles put them and are listed under
  `role_not_determined` where a line's role could not be read; a reassuring part is withheld
  with the whole.
- **de-bsi follows the 2026 documents.** TR-02102-1 2026-01 recommends FrodoKEM-976/1344 and
  Classic McEliece beside ML-KEM, each in hybrid; the BMDS/BMI/BSI Leitlinie of 11 Sep 2026 asks
  for the initial cryptographic inventory by the end of 2026 (§4.3) and high-risk use cases by
  2030. A McEliece or FrodoKEM finding under `de-bsi` keeps NIST's `candidate` and says, in
  `profile_standing`, that the BSI recommends it.
- **A DNSSEC algorithm number with no family is named.** A `DNSKEY 257 3 253` record
  (PRIVATEDNS) was dropped without a word; it is now a protocol asset with `dnssec_algorithm` and
  IANA's mnemonic, no family is invented, and it withholds `pqc_ready` like an unread file.
- **FreeRADIUS's `tls_min_version = "1.0"`** is TLS 1.0, deprecated.
- **SHA-224, SHA3-224 and AES-ECB are seen**, with what NIST SP 800-131A Rev. 3 proposes —
  quoted from its initial public draft of October 2024 and said as a draft (no final revision
  on CSRC on 23 Oct 2026). Their classification is unchanged (hash, symmetric).

On OpenSSH the files read, the coverage (84.77%), the findings, the readiness and the verdict are
the same as in 0.34.0; the evidence gains 865 lines (761 Ed25519 identifiers such as `KEY_ED25519`
and `ed25519_pk`, 85 `KEY_RSA`, 11 DH headers and `DH_compute_key`, 8 more RSA) and loses none.
On certbot 9 more files are read (four Dockerfiles, four nginx `sites-*` files, `CODEOWNERS`):
coverage 65.84% → 66.56%; the findings, the readiness and the 42 TLS places are the same; one
evidence line moves from a call to a ban (`make_key(… key_type='ecdsa')` under
`pytest.raises(… 'Unsupported elliptic curve …')`).

## 0.34.0

**From 0.34.0**, after a systematic probe of 22 Oct 2026 that set the summary beside what the scan
had actually read, and four points raised in public the same day, the output stops being confident
where the evidence beside it was not:

- **`pqc_ready` is withheld past what was not read.** A value that says nothing classical is
  present — `pqc_ready`, `pqc_pre_standard`, `mechanism_protected`,
  `no_quantum_vulnerable_detected` — becomes `not_established` when files in the tree were not
  read (or a directory not entered, a linked directory not followed), or when a private key's
  algorithm was not determined (PKCS#8 embedded in source, an encrypted key file).
  `summary.readiness_not_established` says what it would have read and why not, e.g.
  `"1 of 2 files were not read (50.0% read); see coverage.not_examined"`. A value that warns is
  never withheld. In practice nearly every real repository has a file the scanner does not
  read (a `README.md`, a `LICENSE`), so on a real tree these four values give way to
  `not_established`, with the would-be value beside it. The case: ML-KEM in a module and a `Caddyfile` with `curves x25519`, which was not
  read (it is from 0.35.0, and the same tree now reads `hybrid_partial`); the summary said `pqc_ready` about the one file it had not opened (raised by Chandra
  Devadass). Files removed by the directory exclusions do not withhold it; they are named in the
  verdict instead (below).
- **The verdict names what the directory exclusions removed.** The directories left out before
  anything is counted are `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `vendor`, `dist`,
  `build`, `.tox`, `target`, `.pytest_cache`, `.mypy_cache` and `.ruff_cache`
  (`coverage.instrument.excluded_dirs`). A file under `vendor/` said "read every one of the 3
  files" of a 4-file tree; now the sentence ends "Left out before counting, by directory name: 1
  file in vendor/." `.git` is not named there (raised by Muhammad Atif).
- **A post-quantum family is not counted as ready where the evidence says it does not hold.**
  Where every use is a TLS place that a pinned image cannot negotiate (`evidence.library_support`,
  `not_negotiable`), the finding names the image in `not_negotiable_by` (also
  `qrp:not_negotiable_by` on the CBOM component) and the summary leaves it out of
  `pqc_ready_count` and the readiness. Where every use is test code, the finding carries
  `in_test_code: true` and the same applies; the CBOM already marked it `scope: excluded`. The
  classification is unchanged — ML-KEM is standardised — and test-only classical code still counts
  as vulnerable: the summary does not reassure from what it set aside, and never warns less.
- **What an RFC 8784 PPK protects.** One PPK line made a whole tree `mechanism_protected` with RSA
  signing in another file. The PPK finding now lists `protects`: the families used in the files
  that configure it. `mechanism_protected` needs every quantum-vulnerable family among them;
  otherwise the readiness is what it would be without the mechanism. Per family, not per
  occurrence: EC in the IKE file and EC elsewhere are one family. A PPK whose file says
  `ppk_required = no` (or switches it off) protects nothing and its reason says it is optional.
  ⚠️ strongSwan's default for `ppk_required` is also `no`; a `ppk_id` with no `ppk_required`
  line is not yet read as optional.
- **A recoverable private key raises its finding.** Where `evidence.weak_keys` finds k·G, the
  finding of that family is `weak_key: true`, severity `critical`, with the place in its reason,
  so `weak_count` and `highest_severity` say it too (raised by Sagar A.).
- **A denial block governs names, not calls.** `if (err.code === 'ERR_UNSUPPORTED') {` or
  `except UnsupportedAlgorithm:` opened a "denial block", and the classical fallback generated
  inside it read as a ban. A call is now a use wherever it sits; names listed under
  `forbiddenAlgorithms:` stay bans. A *declaration* in such a block (`curve = 'P-256'`) is still
  read as a ban.
- **A group removed with OpenSSL's `-` is a ban on the algorithm path too.** `Groups =
  DEFAULT:-X25519MLKEM768` switches the hybrid off; ML-KEM was detected from it. The algorithm
  rule now asks the same group-setting test as the TLS group rule.
- **LMS through its API.** wolfSSL `wc_LmsKey_*` (its `lms.h`), hash-sigs'
  `hss_validate_signature` and the other `hss_*` entry points for generating, loading and
  signing, and Bouncy Castle's `LMSSigner`/`HSSSigner` are HSS/LMS (raised by Dhiraj S.). XMSS through
  `wc_XmssKey_*`, `xmss_sign_open` and `XMSSSigner` was already matched and is now pinned.
- **`prove_closure` does not call a skipped file removed.** A key file the second run skipped by
  type was "removed — the file is not in the second tree" while it was there; every path in
  `coverage.not_examined` is now unread, so such an occurrence is `unverifiable`.

- **UTF-16 without a byte-order mark is read as UTF-16.** A `.ps1` saved by a Windows tool as
  UTF-16-LE with no BOM was decoded as UTF-8, gave nothing, and counted as read. One NUL in every
  byte pair, on the same side, over the first 4 KiB now selects UTF-16; text with more than about
  a tenth non-ASCII characters is not recognised this way.
- **Deprecated TLS versions reach the summary.** `summary.deprecated_protocols` lists the
  deprecated versions enabled in the tree (`TLSv1.0`, `TLSv1.1`, `SSLv3` …); a version struck out
  is not listed. `weak_count` still counts keys and algorithms only.
- **The coverage identity has four terms.** A linked file is in `files_present` and in
  `symlinks_not_followed`, not in the other three (below).

Not changed by any of this: what is detected, apart from the LMS names, the two ban rules and
UTF-16 above, and the coverage figures. On OpenSSH the files read, the evidence, the findings, the
summary's readiness and the verdict are the same as in 0.33.0. On certbot the same, but for one
evidence line: `make_key(elliptic_curve="nothere", key_type='ecdsa')` under `with
pytest.raises(…, match='Unsupported elliptic curve…'):` in a test is now a call, not a ban (ECDSA
was found elsewhere anyway); its summary gains `deprecated_protocols`. No file in OpenSSH,
certbot or wolfSSL is UTF-16 without a BOM.

## 0.33.0

**From 0.33.0**, after a local probe of 22 Oct 2026 that put a network scan of three TLS
endpoints beside a scan of the repository that configures them, five things that probe showed
the code scan missing:

- **An HAProxy listener that terminates TLS is a place.** `bind :8443 ssl crt edge.pem` is a
  protocol asset with `basis: configured_listener` and is in `configured_in`, and it names what
  neither its line nor the file's `ssl-default-bind-*` sets — `library_defaults: ["protocol
  versions", "TLS 1.2 cipher list", "TLS 1.3 cipher suites", "groups"]`, as many of them as are
  absent. There HAProxy's and the TLS library's defaults apply, and which they are depends on the
  versions that run, which the file does not say; the one default stated is HAProxy 3.2's own
  manual's (`ssl-min-ver`: "The default value is TLSv1.2"), named as that. The probe's edge
  listener said nothing in 0.32.0 and took TLS 1.2 with 13 suites on the wire.
- **RSA key exchange is named.** OpenSSL calls TLS_RSA_WITH_AES_256_CBC_SHA `AES256-SHA`: no
  word in the name says RSA, so `SSLCipherSuite HIGH:!aNULL:AES256-SHA:DES-CBC3-SHA` gave 3DES and
  nothing else. On a cipher-suite setting the 30 `TLS_RSA_WITH_*` names of `openssl-ciphers(1)`
  (OpenSSL 3.5), the `kRSA` keyword and the IANA spelling are now `evidence.static_rsa_kex` —
  RSA key exchange: no forward secrecy, and a recorded session opens to whoever later recovers
  the server's RSA key — with RSA on the line and a CBOM component `RSA key exchange (static RSA
  cipher suites)`. `ECDHE-RSA-…` stays RSA by authentication only; a suite struck out with `!` or
  `-`, a comment, a C constant and a lower-case strongSwan proposal are not counted. On certbot: 2
  lines (an Apache options file in the integration-test assets and a test vhost).
- **`SSLProtocol all` enables what it does not strike out.** mod_ssl's manual (2.4): `all` is
  `+SSLv3 +TLSv1 +TLSv1.1 +TLSv1.2 +TLSv1.3` with OpenSSL 1.0.1 and later (TLSv1.3 with 1.1.1,
  SSLv3 not where OpenSSL was built with `no-ssl3`). So `SSLProtocol all -SSLv3`, which 0.32.0
  reported only as "SSLv3 is forbidden here", now also gives TLSv1.0 to TLSv1.3, each with
  `included_by: "all"`, the two old ones `deprecated`. Whether the TLS library still allows them
  at run time is not in the line. On certbot: 60 protocol assets more (TLS places 39 → 42).
- **A backend whose certificate is not verified.** HAProxy `verify none` on a `server` or
  `default-server` line, its global `ssl-server-verify none`, and nginx `proxy_ssl_verify off`
  are protocol assets with `peer_verification: "off"` (`basis: configured_verification`): the hop
  is encrypted and not authenticated, and it is the one thing a scan from outside cannot see.
  They are not termination places. `verify` on a `bind` line is the client-certificate check and
  is left alone. ⚠️ nginx's default is also off (ngx_http_proxy_module: "Default:
  proxy_ssl_verify off"); a file without the line is not reported, and that is a boundary.
- **A hybrid group beside the image that has to negotiate it.** `evidence.library_support`: for
  each `image:` line (compose, Kubernetes) naming a TLS server image — nginx, haproxy, httpd,
  traefik, caddy, envoy, openresty — in a tree that configures a hybrid group (the IANA TLS
  Supported Groups names: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, the ML-KEM-512
  drafts, X25519Kyber768Draft00 …), whether that image can negotiate it. `support:
  "not_supported"` only where every step was read at a source: OpenSSL added the three RFC 10024
  hybrids in 3.5.0 (`CHANGES.md`), and `nginx:1.24.0` is docker-nginx's Debian image, `FROM
  debian:bullseye-slim`, whose openssl is 1.1.1w. That is the one image in the table; every other
  one, an `-alpine` tag included, is `"not_established"`, and says so. A compose service is joined
  to the configuration it mounts from the tree (`serves`, `serves_group_places`); without a mount
  the pin and the groups are named side by side, not joined. In the probe the repository set
  X25519MLKEM768 for a service that ops ran on nginx:1.24.0 with a classical hotfix mounted
  instead; nginx refused the repository's configuration. A `Dockerfile` is read from 0.35.0 for
  the algorithms it names; from 0.40.0 its `FROM nginx:1.24.0` is a pin too (named beside the
  groups, joined to nothing: a `FROM` line mounts nothing), and a package pin is not read for this. The
  places and the mounts are not part of the finding's identity in `closure`; in the CBOM it is a
  `container` component. On OpenSSH and certbot: none. From 0.40.0 (row 117), where every use of
  the post-quantum family is a place such a `not_established` image serves, the finding names it
  (`negotiation_not_established_by`) and the headline is `not_established`, with the would-be
  value (`hybrid_partial`) and the image in `readiness_not_established`; ML-KEM used by code
  beside it still counts.

The same probe said that two comments were counted as uses — `# … classical X25519 as fallback.`
above HAProxy's curves line, and `# … hybrid ML-KEM group preferred.` in an nginx file whose
server did not offer ML-KEM on the wire. Reproduced against 0.32.0, that is not so here: both are
`evidence_kind: comment`, outside `detected_algorithms` and the TLS places, and `[comment]` in the
CBOM (a test now pins it).

The statement says the same of authentication: a Merkle Tree Certificate is issued by the CA,
verified by the browser and often served from an edge, so an origin whose files name an ECDSA key
can be served with one — and its own key is still ECDSA, and reported as such. An AWS listener
policy is a TLS terminator in the tree, and counts as a place here.
