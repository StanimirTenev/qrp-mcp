# Changelog

What changed in each version of qrp-mcp, newest first. Each entry says what was wrong, how it
was found, and what is not claimed. Changes before 0.33.0 are described where the behaviour
is, in the [docs](docs/) ("From 0.28.0 ..."); the tag of every version is on GitHub.

## Unreleased (0.54.0)

Detection changes: findings and their fingerprint move.

### Crypto-asset libraries (rows 561-599)

A new family and role, the calls of crypto-asset libraries, Vyper, and two false signals removed.

- **How it was found.** A probe of the crypto-asset world on 25.11.2026: the documentation of each
  wallet, BLS, SNARK, KZG and chain library was saved, one call per line was written from it, and
  0.53.0 was run over the lines (qrp-kachestvo/roy-2026-11-25-kripto). Most calls were read and gave
  nothing, or a row only on the import line; pairing-based cryptography gave nothing anywhere. A
  positive control on OpenZeppelin, lighthouse, bitcoinjs-lib and go-ethereum quoted the same
  gaps in real code. Rows 561-593 of the fix list.
- **`Pairing`, a family with its own role `proof`** (rows 562, 563). zk-SNARKs (Groth16, PLONK
  through snarkjs or gnark), KZG commitments (c-kzg-4844) and the EVM's curve and pairing
  precompiles over BN254 and BLS12-381. A pairing rests on discrete logarithms Shor's algorithm
  computes. `summary.by_role.proof` and `readiness_by_role.proof` appear only where one is found;
  no replacement is named, because a signature scheme does not replace a proof system; CBOM
  primitive `other`. Poseidon, keccak, STARK/FRI and PLONK as a bare word are not read.
- **Calls of a library read in a file that imports it** (`libcalls.py`; rows 561, 568-575, 578,
  579, 581-588, 591-593). go-ethereum `crypto` (row 561: `crypto.GenerateKey()`, `crypto.Sign`),
  ethers v5/v6, viem, web3.js, eth_account, eth_keys, alloy, ethers-rs, tiny-secp256k1, bip32,
  ecpair, bitcoinjs Psbt, rust-secp256k1, python-bitcoinlib, the Solana SDKs, CometBFT, cosmjs,
  tss-lib, blst, herumi, py_ecc, noble bls12-381, FROST, Algorand Falcon, RustCrypto slh-dsa. A call
  counts only under the name the import binds, and a method only on a value the file got from the
  library; the library's curve is given where it has only one.
- **Solidity and Vyper** (rows 564-567). OpenZeppelin's P256/WebAuthn (ECDSA P-256), RSA,
  ECDSA/SignatureChecker (secp256k1) and the using-for `h.recover(sig)` are read. So is the address
  of a precompile `staticcall`, including RIP-7212 P256VERIFY at 0x100. `.sol` comments were read
  as code until now. `.vy` is read, with `ecrecover`, `ecadd` and `ecmul`.
- **Wrong family or status.**
  - libsecp256k1's schnorrsig, extrakeys and musig functions, and FROST over secp256k1, are now
    Schnorr instead of ECDSA (rows 573, 588).
  - `@solana/web3.js` no longer adds ECDSA (row 584).
  - leanSig/hash-sig's generalized XMSS is its own research family, never `pqc_ready`. It was XMSS,
    `standardised` (row 576). This is from its README only, not from a comparison with the XMSS
    specification.
  - pyspx is round-3 SPHINCS+ by its README's words, in both spellings (row 577).
- **A contract function's name is not algorithm evidence** (row 580; an exception to rule 132
  approved by the owner). A 4-byte selector's signature (`"4fb7db3f": "KYBER_PROXY()"`, Kyber
  Network's contracts in go-ethereum's `4byte.json`), an ABI entry's `name` and a Kyber name in
  Solidity are now identifiers. They made go-ethereum's key establishment `hybrid_pre_standard`.
- **Closure catalogue**: 38 pairs and 1,930 sourced spellings. New pairs: apiname in Go, JS, Python,
  Rust and CI; pqc in Go, Python and Rust; sign in Go. Each quote is cut from the saved page and
  checked verbatim, 82 of 82. `KNOWN_OPERATIONS` gains Go's apiname, pqc and sign and Rust's pqc.
  Go stays `closed`. JS and Rust move to `partially_closed`.
- **`web3` and `ethers` as bare words** (row 598). These are no longer ECDSA; only an import plus
  a key or signing call is, read in `libcalls.py`, including a dynamic `await import('ethers')`.
  web3.py's `w3.eth.account` calls are read too. Measured on OWASP Juice Shop c9f9922 against
  5316656: ECDSA rows went from 349 to 8. All 317 rows that hand-reading marked as no cryptography
  are gone: routes, component names, test titles, i18n strings, `formatEther`. The one real key
  derivation, `HDNodeWallet.fromPhrase`, is still read, now on the line of the call.
- **Node's crypto in Juice Shop's tests** (row 599).
  - `crypto.sign(..., { dsaEncoding })` over an EC key is ECDSA. It was DSA, read from the
    option's name; Node: "For DSA and ECDSA, this option specifies the format".
  - A `createECDH` object whose private key is set or read, in a file with no `computeSecret`, is an
    EC key pair. A `createECDH` alone stays ECDH (row 413).
- **`ecosystems.present[].closed_scope`.** Each closed operation now carries the `scope` of its
  catalogue entry. `ecosystems.meaning` says an operation is closed against the libraries its
  catalogue lists, not every library of the ecosystem. Go reads `closed` on that bounded list; JS,
  Python and Rust read `partially_closed`. Findings and the fingerprint do not change.
- **Corpus regression** against 0.53.0, at the last commit. This is disagreement with a model, not
  recall or precision.
  - A' is unchanged in both splits. B' falls: `obuchenie` 264 to 257, `merene` 42 to 34. The gate
    passes.
  - An earlier commit of this release made the gate exit 1: ECDSA B' rose by 10 chunks, all in
    bitcoinjs-lib's tests (`psbt.signInput`, `bip32.fromSeed`, `keyPair.sign`). The owner decided to
    ship 0.54.0 even so. Those ten rows are still there.
  - The cached scans of both versions were also compared repository by repository, because the new
    families are outside the labeller's set. 175 of 185 are unchanged.
  - Two repositories move from `classical_only` to `unknown`: a hardhat template whose only ECDSA
    was the word `ethers` (hardhat helpers, `parseEther`), and a package.json naming "web3". Row 598
    asked for that change.
  - The comparison also found `Kzg` inside base64 in three repositories that are not chain
    projects; that was fixed.
- **Not claimed / not done.**
  - Solidity, Vyper and circom have no ecosystem in the catalogue; their spellings are tested
    apart.
  - Not read:
    - `.circom` (row 590);
    - generic Rust calls through a type parameter (`S::key_gen` in leanSig);
    - the GG20 command-line binaries;
    - `tss.NewParameters(tss.S256(), ...)`;
    - the parameter set from slh-dsa's type.
  - Known limit (row 595): bitcoinjs' Psbt signing calls are ECDSA even for a Taproot input,
    which is Schnorr (BIP-340).
  - Next release: an ecosystem for Solidity, Vyper and circom (row 596); one finding per file for
    `kzg` field names (row 597).
  - On the probe's 237 lines, 164 had no row on 0.53.0 and 13 still have none. Examples: btcec's
    signature `.Verify`, Solana's `tx.sign`, `contract X is EIP712`, leanSig's generic calls,
    the GG20 binaries and circom.
  - Error-message words such as "Not Taproot." are still read as Schnorr (row 589). It is the class
    row 113 left for the owner's decision.
  - A spelling is closed only as far as the saved pages name it. viem's generatePrivateKey,
    c-kzg's Python functions and FROST's `generate_with_dealer` are read by the rules but not
    catalogued.

### Rows 554-560 and 594

Findings and their fingerprint move where these constructs are present.

- **nginx statements on one line (row 558).** `server { listen 443 ssl; ... ssl_certificate ...; }`
  written on one line gave no `tls_listeners` and no `tls_termination.authentication_not_read`;
  over lines it gave both. nginx ends a directive at `;` and a block at its braces, so the
  listeners, the unread certificates, the trust stores, the `*_ssl_verify` switches, TLS upstreams
  and `ssl_verify_client` are now read statement by statement. A row keeps its physical line.
- **A placeholder's default is an overridable place (row 560).** `${SIGNING_ALG:ECDSA-P256}` was a
  finding and no place in `chosen_outside_files`. Spring's `${name:default}` (YAML, .properties,
  `@Value`), the shell's `${p:-w}`, `${p-w}`, `${p:=w}`, `${p=w}` and Compose's `${VAR:-d}`,
  `${VAR-d}` now carry `default`, `default_family` and `overridable: true`, as
  `os.environ.get(NAME, default)` does. `:?`, `?`, `:+`, `+` are no default.
- **gpg key generation (row 557).** `gpg --quick-gen-key ... rsa3072` gave nothing. The algo
  strings of `--quick-generate-key`, `--quick-gen-key` and `--quick-add-key`,
  `--default-new-key-algo`, and the `--generate-key --batch` parameter file (`Key-Type`,
  `Key-Length`, `Key-Curve`) are read, with size and curve. `default`, `future-default`, `-` and
  `pqc` name no family.
- **Android network security configuration (row 556).** An `.xml` whose root is
  `<network-security-config>` is read (any name). A `<pin-set>` is a protocols row
  (`basis: configured_pin`, `pins`, `pin_digest`, `pin_expiration`) that names no family, since a
  pin is a hash of a key that is not in the file. A `<certificates src>` is a `trust_stores` place.
  Every other `.xml` stays unclaimed.
- **ML-KEM with no classical half (row 555).** A pure ML-KEM group (MLKEM512/768/1024) in a TLS
  group setting, and Go's `crypto/mlkem` constructors and `tls.MLKEM1024`, mark the ML-KEM row
  `standalone_pqc: true` with `standalone_basis`. The finding and
  `summary.by_role.key_establishment` list the places, and so does the CBOM
  (`qrp:standalone_pqc`). Said of the line: a hybrid built by hand elsewhere is not read.
- **Where a Python module's cryptography is reached from (row 554).** An occurrence inside a
  module of the tree carries `reached_from`: up to ten places in other files read that import its
  top-level function or class and call it, or the import line where no call is seen. It also
  carries `reached_from_count`, and `reached`, which says the list is static and can be short.
  The CBOM carries it as `qrp:reached_from`. It stays outside closure and baseline identity.
- **A JOSE token with no verified signature (row 594).** These ways of accepting or making an
  Unsecured JWS (`alg: none`), or of reading a token without verifying it, are now a finding of
  the family `JWT-unverified`:
  - PyJWT and python-jose: `verify_signature: False`, `none` in `algorithms`;
  - jsonwebtoken: `none` in `algorithms`, `sign` with `algorithm: 'none'`, `decode`;
  - jose (panva): `UnsecuredJWT`, `decodeJwt`;
  - Nimbus: `Algorithm.NONE`, `PlainJWT`;
  - jjwt: `unsecured()`, `parseUnsecured*`, `Jwts.SIG.NONE`;
  - golang-jwt: `SigningMethodNone`, `UnsafeAllowNoneSignatureType`, `ParseUnverified`;
  - a JWT algorithm setting set to `none`.

  It is classified `deprecated_weak` with severity high, and is not quantum vulnerable: there is
  no signature to break. `none` counts only inside an algorithm setting or argument.

  Two gaps were found by a positive control on OWASP Juice Shop and are now closed:
  - jsonwebtoken and `jws` are read through whatever name the file binds them to: a default,
    namespace or named import, or a require, destructured or not. So are Python's and Go's import
    aliases. This covers `import { decode } from 'jsonwebtoken'`, `jws.decode`, and
    `jws.sign({ header: { alg: 'none' } })`.

  The rule for a decode that a verification follows in the same block (Juice Shop
  `routes/verify.ts:119`, verified six lines below): it is still a row, because the line does read
  the token unverified. The row now carries `verified_after` and says only that. It does not say
  the token is accepted unverified, and the finding's reason says so too. Where every
  `JWT-unverified` row of the tree carries `verified_after` (the owner's decision), the finding is
  `low` with `verified_after_only: true` and is not counted: `weak_count`, `highest_severity` and
  `total_findings` do not move for it, as for a family named only in identifiers. One row without
  `verified_after` keeps the finding high and counted.

  `none` lists and `verify_signature` are read only in a file that imports a JOSE library.
  jose's `decodeJwt` and `UnsecuredJWT` are read only in a JS/TS file that imports `jose`, because
  auth0's java-jwt has its own `decodeJwt`. A decode at the top of a file, or in a block that closes
  on its own line, has no verification "after" it.

  Not covered: a library version that accepts `none` by itself, such as jsonwebtoken 0.4.0 or
  express-jwt 0.1.3. That is a dependency, not a line. Also not covered: the browser library
  jwt-decode.
- **Catalogue.** The one-line nginx spelling is added to tlsend/nginx. The three pure ML-KEM groups
  in tlsgroups/nginx now expect the mark. Five new catalogue files hold one part of an operation
  each: `keysize_gpg`, `external_placeholder`, `tlsend_android`, `pqc_standalone` and
  `sign_unverified`. Like `rng_source`, they are kept out of an ecosystem's closed/open status. The
  quotations were checked against saved copies of the pages (51 found, 0 missing, 2 without a page).
- **Not done.** Row 559 (the OIDC `issuer-uri`) is marked for decision and was left.

### GitHub Action and the README "Measured" section

No detection change: findings and their fingerprint do not move.

- **A GitHub Action** (`action.yml` at the root, composite). It installs uv, runs
  `uvx --from qrp-mcp==X.Y.Z qrp-mcp scan PATH --format sarif --out FILE --level LEVEL`, and gives
  the file as the output `sarif` for `github/codeql-action/upload-sarif` (example in the README).
  Inputs `path`, `output` and `level` only, because those are what `scan` has; there is no
  "fail on" input and the step exits 0 on findings. Inputs reach the command through `env`, not
  through `${{ }}` in the script. `tests/test_github_action.py` holds the command to the real CLI:
  each flag must be in `qrp-mcp scan --help`, the default level one of its choices, the same
  arguments must write SARIF 2.1.0, and the pin and the README's `uses:` must be this release
  (one more place to bump). Not claimed: it has not been run on GitHub yet. SARIF locations are
  relative to `path`, so a `path` other than `.` misplaces them in code scanning; the README
  says so.
- **README "Measured"** replaces "Coverage on three public repositories". It covers OWASP Juice Shop
  and DVWA (shallow clones, commits named) besides OpenSSH, certbot and Vault, with occurrences and
  how many were read by hand. Juice Shop and DVWA were read in full (393 and 34); for the other
  three, 30 each were taken by a fixed rule. What was read is stated plainly, false positives
  included. In Juice Shop, 317 of the 393 rows are ECDSA for the word
  `web3` or an ethers unit helper, and 240 of those are at medium or high confidence. This is
  stated as found and is not fixed here. Counts of lines read, not detection figures: no recall
  or precision.

## 0.53.0 (2026-11-24)

Detection changes: findings and their fingerprint move. Ten more (operation, ecosystem) pairs are
closed, two closed pairs now vary their free parts, and a file read in no ecosystem is said so.

- **What was wrong.** Almost every outside test after 0.50.0 found a scanner gap. Sorting those
  rows against the closure catalogue showed two kinds. Most were outside every closed pair: the
  space of pairs is large and 19 were closed. Two were inside closed pairs: ECVRF in Go (row 540)
  and an environment read in Python (row 546). There the catalogue held each spelling with one
  variable name, setting name or receiver, so a different name was never tested. Separately, a
  file read in no ecosystem (an ECH key in JSON, an HTTPS record in a zone file, from Dong's ECH
  bench) got no "here we may miss" at all, and any `.zone` file was counted as DNSSEC.
- **Variants.** A catalogue spelling may now carry `variants`: the same documented spelling with
  its free parts changed. Each variant is its own test. external/Py and vrf/Go were rewritten
  with them; before the fix 13 variants failed, after it none.
- **`ecosystems.not_attributed`.** Files read that no rule puts in an ecosystem are counted and
  listed with "here we may miss", and `where_to_look` gets one `files_not_attributed` row. It
  reaches the scan JSON, `scan_repo`, `scan --out` and the CBOM (`qrp:ecosystems:not_attributed:*`).
  A zone file is DNSSEC only when it holds a DNSSEC record (DNSKEY, RRSIG, DS, NSEC/NSEC3, CDS,
  CDNSKEY).
- **Ten pairs closed, chosen before the work** (ZATVARYANE.md, stage 4): keysize in Java, C and
  Python; apiname in Java and .NET; sign in .NET and CI; symhash in .NET; pqc in PKI; external in
  Go. All ten closed; none had to ship open. The catalogue now holds 29 pairs and 1,848 sourced
  spellings; the quotations of the spellings added for these ten were checked against saved
  copies of their pages. Under the strict
  rule two ecosystems are now `closed`: PKI and Go.
- **Also fixed:** row 548, hybrid KEM names from a Go registry string (`mlkem768-x25519`) now give
  both halves, and the CBOM shows the hybrid depending on each.
- **New output.** `kind: go_setting` places (crypto GODEBUG settings, `//go:debug`, `GOFIPS140`);
  `replaced_by` on a go.mod dependency; `go.work` is read; ci_pipeline types `notation_sign`,
  `minisign_sign`, `ssh_keygen_sign`, `sigstore_action`; signing steps `set_authenticodesignature`,
  `mage_sign`, `nuget_sign`, `sn_sign`, `strong_name_sign` with `strong_name_mode`; `.vbproj` read
  for signing steps.
- **How it is pinned.** Not every new case was a gap: many already passed on 0.52.2. Those that
  failed before the fixes pass here, and each fix was reverted alone and its cases turned red. Positive control on pinned public repositories
  (santuario, jjwt, wolfssl-examples, Mbed TLS, OpenSSL demos, hpqc, smallstep, paramiko, cosign,
  certbot, cfssl, nuclei, sigstore-python, Vault and others): every new or changed row was read
  against its source line. On the 185-repository corpus, as disagreement with a model and not
  as recall or precision: A' (the labeller names an algorithm, the scanner is silent) is unchanged
  in both splits; B' (the scanner reports, the labeller does not) rises by 2 ECDSA chunks in the
  training split and is unchanged in the held-out one. Each was read: a Java `Signature.getInstance`
  of a same-file constant `"SHA256WithECDSA"` (GrapheneOS Auditor) and .NET `VerifyData` on an
  `ECDsa` key (fido2-net-lib). Both are ECDSA; the name is outside the labelled chunk.
- **What is not claimed.** That a closed pair cannot miss: a spelling the cited documentation
  does not list is not tested. Not covered, by name: GOEXPERIMENT and build tags; composite
  ML-KEM (draft OIDs); a receiver typed two ways in one file; Kotlin `const val` sizes. certreq
  `.inf`, mage, nuget, `sn -R` and `CALG_*` pass their catalogue cases but fired in no control
  repository.

## 0.52.2 (2026-11-23)

Findability only. No detection, coverage or output change.

- **What was wrong.** Agents and directories that search for "find quantum-vulnerable
  cryptography" did not reach qrp-mcp: the server set no `instructions`, so a model had no
  sentence saying when to use its tools; the PyPI summary and the registry description did not
  contain the words people search with; the plugin's `homepage` pointed at the site root, a page
  about the Q-Day forecast, not the scanner. Found by blind probes of AI search on 19–20.11, in
  which an agent with no knowledge of the project searched 24 such queries.
- **The fix.** The server now sends `instructions` in its initialize result. The PyPI summary and
  `server.json` description now lead with "Find quantum-vulnerable cryptography (RSA, ECDSA, DH) in
  code" (100 characters, the registry schema's limit). Keywords `dora` and
  `cryptographic-inventory` were added. The plugin and marketplace `homepage` point to
  https://quantumreadiness.eu/qrp-mcp/.
- **How it is pinned.** `tests/test_server_instructions.py` runs a real initialize handshake and
  checks the instructions; it fails on 0.52.1.
- **What is not claimed.** That this makes any agent recommend the tool. Whether it does is
  measured by the next blind probe, not by this release.

## 0.52.1 (2026-11-21)

Security fix. A scanned repository could run its own code in the processes that read it.
Reported privately on 20.11 by the GitLab Threat Research Group against 0.52.0, reproduced
here before the fix.

- **What was wrong.** From 0.37.0, a tree of 200 files or more is read by a pool of processes.
  Where the pool starts them with `spawn` (macOS, Windows, and Linux whenever the process runs
  more than one thread, which the MCP server always does), each reader starts as `python -c ...`,
  and Python puts the working directory first on `sys.path`. When the server's working directory
  was the scanned repository, a committed `multiprocessing/__init__.py`, or any module of the
  same name as one the reader imports, was imported in its place and ran with the user's rights.
  `scan_repo` is marked read-only, so a host asked for no approval. The scan still returned its
  normal result.
- **The fix.** Readers are started with `PYTHONSAFEPATH=1`, so the working directory is not on
  their `sys.path` (Python 3.11 and later). Python 3.10 has no such switch: there, a tree that
  would need spawned readers is read in one pass. `fork` readers import nothing and are
  unchanged. The variable is set only while the pool starts and is put back afterwards.
- **How it is pinned.** `tests/test_pool_import_path.py` starts the server over stdio the way a
  host does, with a tree of 260 files and a planted `multiprocessing/` as its working directory,
  calls `scan_repo(path=".")`, and fails if the planted code ran. It also fails if no reader
  process started, so it cannot pass by the pool being skipped. It fails on 0.52.0 and passes on
  0.52.1.
- **What is not claimed.** Reproduced on Linux with Python 3.12; macOS and Windows were not
  tested here. The findings do not change: certbot (1,251 files) and OpenSSH (874) read by spawned
  readers give the same result as one pass. Running the server as `python -m qrp_mcp` from inside
  an untrusted tree still puts that tree on the server's own path; start it from its console
  script (`uvx qrp-mcp`, as the plugin does) or from a neutral directory.
- **Affected:** 0.37.0 to 0.52.0. A security policy is now in `SECURITY.md`.

## 0.52.0 (2026-11-19)

Random number generators, asked for on 19.11 ("give the random number generator more attention")
after a LinkedIn post asked who audits the randomness behind PQC keys. The reproduction
(`random.getrandbits` and `random.randint` beside an EC key, `math/rand` with a fixed seed beside
`ecdsa.GenerateKey`, `java.util.Random` and SHA1PRNG) gave 0 rows on 0.51.0.

- **A new operation, `rng_source` (rows 531, 539).** A new section, `randomness`, lists the
  generators the code calls, one row per API on a line, in one of three classes from their own
  documentation: `weak` (a non-cryptographic PRNG),
  `csprng` (a named cryptographic generator) and `check` (a call its documentation does not settle
  by itself, with `why`). It covers Python, Go, Java/Kotlin, JS/TS, C/C++, .NET and PHP: 48
  spellings in `data/operations/rng_source.toml`, each with its page, the words quoted from it and
  a closure test. The reproduction now gives 9 rows.
- **Places to check.** A `weak` or `check` row becomes a place in the same line, function or file as
  a public-key operation the scan reports, or when it is assigned to a name that says key, seed,
  nonce or iv. `link` is always `co-location`: the value is not followed, and a place is not a
  verdict. A `csprng` row is never a place. In the reproduction: `keys.py` lines 3 and 4 (seed,
  nonce) and `gen.go` line 3; `Gen.java` makes no key, so its Random stays a row.
- **FIPS 203/204.** Where an ML-KEM or ML-DSA call draws randomness and has a generator in the
  same function, the section quotes FIPS 203 §3.3 or FIPS 204 §3.6.1 with the page and the minimum
  strength per parameter set: ML-KEM key generation and encapsulation get FIPS 203, ML-DSA key
  generation the seed ξ (shall), ML-DSA signing the hedged `rnd` (should). The operation
  (`operations`) is read from the names called on the row's line or on the name it assigns; verify-
  and decapsulation-only code and tables that only name the algorithm get no entry (no statement
  where the operation is not read). One entry per function, family and parameter set. It says the
  requirement is named, not checked; the meaning travels into the CBOM
  (`qrp:randomness:pqc_requirements_meaning`). OpenSSH: 10 entries (17 before the review);
  smallstep's COSE mapping: none (3 before).
- **The pessimistic side, after the review of 19.11.** `check`, not `csprng`: `new
  SecureRandom(seed)` with the seed in a variable (`seed_supplied`); `getInstance("SHA1PRNG")`, with
  or without a provider, whether or not its file calls setSeed (`sha1prng_seed_not_ruled_out`, or
  `sha1prng_with_setseed`); a name outside the JDK's standard names (`not_a_standard_name`); C
  `getrandom(..., GRND_NONBLOCK)` (`may_return_before_the_pool_is_initialised`), which beside a key
  is now a place. `getrandom` without the flag stays `csprng`. Dense co-location is linear: the
  section takes 1.6 s on 40,000 lines of weak calls beside key rows in one function (155 s before).
- **What is not read** for randomness is listed (entropy at boot, VM and container entropy, an
  HSM's generator, a generator injected at run time, a seed from configuration, statistical
  quality), with the counts of calls seen and calls classified. `out_of_scope_by_design` now says
  where the generators are listed, and that `os.urandom(n)` and the like are read for one thing
  more, the size of a symmetric key an RSA key wraps (row 531 a, b).
- **Context, not findings.** The section is built after the fingerprint, outside `evidence`: the
  findings, their fingerprint, a baseline, `prove_closure`, a gate and the exit code are as before.
  `excerpt` is masked and trimmed like every row; every other field holds a value from a closed
  list.
- **CBOM**: `qrp:randomness:*` properties. A `drbg` component appears where the DRBG family is named
  on the line, and nowhere else (OpenSSL `EVP_RAND_fetch` with `CTR-DRBG`, `HASH-DRBG`, `HMAC-DRBG`). A weak
  generator is never a component.
- **Ecosystem status unchanged**: `rng_source` is in `operation_closure`, but it never counts toward
  an ecosystem's status or `where_to_look`. Almost every tree calls a generator, so counting it could only
  raise a status: in Vault, Go would have read `partially_closed` and fallen from rank 1 to 39 with
  `external` still open and untested.
- **Credited, not copied**: Bandit B311, gosec G404, FindSecBugs, CA5394, Semgrep, CodeQL's
  insecure-randomness queries and Sonar S2245 (its co-location idea is described, nothing is taken
  from it).
- **Not covered**: Rust, Ruby, Swift, methods on a generator variable, entropy estimation and
  statistical tests. Not changed: SHA1PRNG keeps its SHA-1 row in `evidence`.
- **The descriptions.** The PyPI summary, the registry description and the README's first line are
  "Offline post-quantum scanner for code: CycloneDX CBOM, RNG calls next to keys, what it did not read": it names the generator calls and the places to look, not an audit of the
  randomness. Keywords add rng, randomness and csprng.
- **Against us** (said, not left out):
  - A place is co-location, not data flow. The controls hold known false places: certbot's renewal
    jitter (`random.uniform`), Vault's jitter and sink, and a Firebase index in a name that says key.
  - Multi-line strings (a Python docstring, a JS template literal, a Go raw string) are not blanked
    across lines, so a line inside one can give a `weak` row and a place.
  - Some weak generators are neither rows nor counted in `calls_seen_not_classified`: C
    `lrand48`/`drand48`, PHP `uniqid`/`lcg_value`/`str_shuffle`, a .NET alias of `System.Random`
    (`using R = System.Random`), Java's static-import `random()`, `SplittableRandom`,
    `kotlin.random`, and a Go dot-import. The count of calls seen is not complete.
  - The PQC operation is read from names, a heuristic: a seeded call (`_seeded`, `_derand`) is read
    as the operation it names, so OpenSSH's composite ML-DSA-44/Ed25519 signing, which expands its
    key from the stored seed, also gets the seed ξ beside `rnd`.
  - `getRandomValues` is matched on any receiver, so a user-defined one reads `csprng`.

## 0.51.0 (2026-11-19)

Two roles the scan did not name, reported on LinkedIn on 19.11 and reproduced on 0.50.0 from PyPI,
one setup.py case from the fifth review of 0.50.0, and the descriptions.

- **A VRF is its own role, not a signature (row 535).** A Go file electing its leader with
  `vrf.Prove(seed, sk)` over an Ed25519 key and signing blocks with ML-DSA-65 gave rows only for the
  imports and types and summed up as `by_role.signature` = Ed25519 + ML-DSA, `hybrid_partial`; the
  VRF call had no row. Now ECVRF (RFC 9381) is a family of its own, classical and
  quantum-vulnerable, with its own part `summary.by_role.vrf` and `readiness_by_role.vrf`, present
  only where a VRF is found (a scan without one keeps its shape; `roles_differ` compares every part
  present). Read: Go's coname/vrf, go-ecvrf and keytransparency p256 -- the import, the package
  functions only in a file that imports them (`vrf` alone is also virtual routing and forwarding),
  and the methods (`Prove`, `Verify`, `Evaluate`, `ProofToHash`) only on a variable the file declares
  as that library's key, so `cert.Verify(...)`, `policy.Evaluate(...)` and `ed25519.Verify(...)` are
  not the VRF's -- RFC 9381's four suite names, and the Rust `vrf` crate as its README shows it. No
  replacement is named for it: a signature scheme does not replace a VRF. CBOM primitive `other`.
  Not changed: an Ed25519 key beside a VRF call (`ed25519.PrivateKey` handed to `vrf.Prove`) stays
  under `signature` -- the scan does not follow a key into a call, and a key that also signs through
  a method (`sk.Sign(...)`, no Ed25519 call row) cannot be told apart, so the reproduction reads
  signature = Ed25519 + ML-DSA, `hybrid_partial`, beside vrf = ECVRF, `classical_only`: it errs
  toward counting the key, not toward `pqc_ready`. Not covered: C (the libsodium VRF fork), other
  VRF libraries.
- **An RFC 3161 time-stamp request is a place (row 536).** `rfc3161ng.RemoteTimestamper(...)` and
  `openssl ts -query` gave no row and no place. Now a request is a place in `chosen_outside_files`,
  `kind: remote_timestamp`, `key_location: tsa`, as a KMS signature is: the authority signs the
  token with its own key and algorithm, outside the files, and no family is claimed. The place says
  the messageImprint hash the requester chose as `hash_choice` (`-sha256`, `hashname=`, Bouncy
  Castle's `generate(TSPAlgorithms.X, ...)`, .NET `HashAlgorithmName.X`) -- only a digest name from a
  fixed list (MD2/4/5, SHA-1, SHA-2, SHA-3, SHAKE, SM3, RIPEMD, GOST R 34.11, BLAKE2, Whirlpool,
  MDC-2) -- or `default of the OpenSSL
  in use` / `default of the rfc3161ng in use` only where the whole request was read and none is
  written -- openssl-ts(1) gives SHA-256 in 3.0 and SHA-1 in 1.1.1, so no default is assumed. A hash
  written as a variable or as any other name (`-$DIGEST`, `hashname=HASH`, `generate(hashAlg, ...)`)
  is `set in the request, not read as a value`, and a call that goes on past the lines read says so;
  `hash_choice` never carries source text, so the masked levels show nothing of it. A command
  continued with `\` is read on; the .NET hash is read inside the call's own arguments; a generator
  assigned without its type (`var g = new ...`, Kotlin `val g = ...()`) counts; a `)` inside
  a string does not end them. Only the request: `-reply` and Bouncy Castle's TimeStampTokenGenerator
  sign with a local key, `-verify` chooses nothing, and `-query -in req.tsq` prints a request made
  before; Bouncy Castle's `generate(...)` counts on a variable declared as a
  TimeStampRequestGenerator. A weak request hash is said as written, not made a finding.
- **The catalogue** holds 12 (operation, ecosystem) pairs and 1,273 sourced spellings (+ `vrf` for
  Go and Rust, 10; + 2 rfc3161ng spellings in `external`/Py); every quotation found in a saved copy
  of its page. `vrf` is a recorded gap of Go and Rust, and it counts toward their status in
  `ecosystems` -- known, closed or open -- only where the scan found a VRF there, outside test code:
  a Go tree without one still reads `not_closed`.
- **setup.py: a subscript on the next line inside brackets** (row 533, N7). `["requests",
  "paramiko"]` with `[:1]` on the line below, inside `setup(...)`, gave a paramiko row; Python joins
  lines inside brackets, and the lexer now does too. N8 (a subscript past 200 nested brackets) is
  left as it was.
- **The descriptions.** The PyPI summary and the registry description are one plain sentence; the
  README opens with it and a trimmed excerpt of a real scan, and says in one line that the scanner
  has no DORA profile and where the DORA report is. Keywords add cbom, cyclonedx, quantum-safe and
  scanner and drop three web3 words; a "Free DORA report" project link; Homepage and the registry's
  `websiteUrl` point to https://quantumreadiness.eu/qrp-mcp/; the plugin's display name
  is "qrp-mcp post-quantum readiness scanner". The README video is the one re-rendered after 0.50.0.
- `findings_fingerprint` changes only where a VRF is found. The `meaning` of
  `chosen_outside_files` is longer by one sentence on every scan; `operation_closure` lists two more
  pairs; `ecosystems` moves only for a tree with a VRF.

Not claimed: that every VRF or time-stamp client is read -- the libraries above, as their pages
show them; any recall or precision figure.

## 0.50.0 (2026-11-18)

**An adaptive post-quantum readiness scanner.** It closes operations against a catalogue of their
documented spellings, each with a test, says in its output which (operation, ecosystem) pairs are
closed, and carries its coverage and limits inside the CBOM. A maintainer tool in the repository
re-reads the documentation and proposes new spellings, which enter only with a source and a test.
This release changes how gaps are closed: by the operation and its documented spellings, not by the
line a report named. The reasoning is in Tenev (2026), doi:10.5281/zenodo.24336932, now in
`CITATION.cff`. The scan stays deterministic and offline.

- **A catalogue of operations, kept as tests.** `src/qrp_mcp/data/operations/*.toml` holds, for
  10 (operation, ecosystem) pairs, 1,261 documented spellings, each with its source page and the
  words quoted from it (every quotation checked against a saved copy of its page: 1,261 found, 0
  not found): IKE/IPsec; the public-key names of
  OpenSSL, wolfCrypt, libsodium, Mbed TLS/PSA, PKCS#11, GnuTLS and Libgcrypt; key files and key
  sizes in PKI; key sizes in .NET; TLS endpoints and TLS groups in nginx, HAProxy and Caddy; SSH
  algorithms; liboqs, wolfSSL LMS/XMSS and hash-sigs; Python dependencies and environment reads.
  Every spelling is written to a file,
  scanned and expected on its line (`tests/test_operation_closure.py`). What each catalogue leaves
  out is written in its `scope`.
- **Gaps found before anyone reported them.** Run before the fixes, the closure tests failed on 48
  spellings in the five pairs of the first stage and on 64 in the five of the second (47 -> 48 and 65 -> 64 after
  expectations were corrected, each in its own commit). Each fix was then reverted on its own (by
  hand where a later commit touches the same lines) and its cases went red again: the reds add up
  to 48 and to 64. A further 12 came from the first judged round of
  self-tuning (below). Among them: strongSwan and Libreswan group keywords with their IANA sizes and
  curves (brainpool `ecpNNNbp` was reported as P-256/P-384), peer authentication in Libreswan and
  strongSwan, WireGuard peer lists, Libgcrypt S-expressions, libsodium `crypto_sign*`, `.crl`
  files, RFC 4716 SSH2 public keys, private keys in DER, nginx's upstream trust stores and
  verification (`proxy_/grpc_/uwsgi_ssl_*`, the default `off`), HAProxy `ca-file`, Caddy
  `tls_insecure_skip_verify`, setup.cfg/setup.py and hashed requirements, `os.environb`, .NET
  sizes in the constructors, `KeySize` on a later line, CNG and CryptoAPI sizes, Brainpool curves,
  Schannel `ClientMinKeyBitLength`, the size of an `ssh-rsa` line, the P-256 half of
  `mlkem768nistp256-sha256`, liboqs's UOV strings and every hash-sigs entry point.
- **`operation_closure`** in the result: the pairs this version tests, with `spellings_count` and
  `catalogue_version`. A statement about this version's tests, not about the scanned code; not in
  the findings, their fingerprint, a gate or the exit code (pinned by a test that scans one tree
  with the catalogue and with an empty one).
- **Adaptive sections** (`src/qrp_mcp/adaptive.py`), read from the finished result, changing no row
  of it: `ecosystems` (each ecosystem of the files read, by named rules, `closed` /
  `partially_closed` / `not_closed` against the catalogue, with "here we may miss"), `angles`
  ("declared, not seen", "seen, not declared", `not_compared` for Go, Rust, Java, .NET, Ruby, PHP),
  `chosen_outside_files.leads` (include, key file path, key path from the environment, each
  followed to the files read or said to end outside the tree, not found, templated or read at run
  time) and `where_to_look` (the three in one list, production code first). `places` and `count`
  of `chosen_outside_files` are byte for byte what they were. In the scan JSON, `scan_repo` and
  `scan --out`; the CBOM and SARIF do not carry `operation_closure` or these sections.
  **Under the strict rule no ecosystem is `closed` today**: an ecosystem is closed when the
  catalogue holds every operation in which a gap has been recorded for it (the fix list labelled on
  18.11), and PKI, the nearest, lacks `pqc`.
- **Self-tuning, the maintainer's self-audit tool.** `tools/catalogue_refresh.py`, in the repository
  and not in the installed package, run by hand: it fetches each page the catalogue cites (or
  reads saved copies, `--pages`), applies that page's own pattern, and writes the names the
  catalogue lacks to `tests/fixtures/operation_candidates.json`; each is an expected-failure test.
  Each of the 52 source entries carries a positive and a negative control; an entry whose negative
  control is read says `discriminates = false` and its candidates are skipped. A test pins the
  candidates file to the one the catalogue gives. It proposes; a person or an agent confirms with
  a source and a quotation. In the first judged round, of the 119 candidates the scanner was silent
  on, 21 were real spellings and 12 were gaps the scanner missed; the rest were noise (89) or
  unclear (9). That figure is for those 119, not for the other candidates.
- **The 12 gaps of that round, closed.** GnuTLS `GNUTLS_PK_GOST_01/12_256/12_512` and
  `GNUTLS_SIGN_GOST_94/256/512` are GOST R 34.10; `CryptGenKey` with `CALG_DH_EPHEM`/`CALG_DH_SF`
  is DH with its size; nginx `ssl_verify_client` is a `configured_verification` row with its value
  (`on`, `optional`; `optional_no_ca` and `off` read as `off`); PKCS#11 `CKM_XEDDSA`,
  `CKM_X3DH_INITIALIZE`, `CKM_X3DH_RESPOND`.
- **New families XEdDSA and X3DH.** XEdDSA is a signature, X3DH a key agreement; both are
  classical and quantum-vulnerable (Montgomery-curve keys, PKCS#11 3.1 §6.3.15 and §6.5.2; Signal's
  XEdDSA and X3DH specifications). Replacements ML-DSA/SLH-DSA and ML-KEM; CBOM `signature` and
  `key-agree`, nistQuantumSecurityLevel 0. No classical security level is given: the mechanism does
  not say which of the two curves it is.

What changes for an existing user:

- **A stage-3 section cannot fail a scan.** Found by the independent review before the tag: a
  lead whose target had `**` inside a path component (`exclude: "**.pem"` in a YAML file,
  `Include a/**b/c`, `include sites/**.conf;` with nothing under `sites/`) made pathlib raise on
  Python 3.10-3.12, and the whole scan ended with exit 2 (`scan_repo` raised) where 0.49.0 exited
  0. Such a lead now says `pattern_not_followed`, and no pattern from the scanned text reaches a
  glob that can raise. If building `ecosystems`, `angles`, `leads` or `where_to_look` fails for
  any other reason, none of the four is set and `adaptive_not_built` names the exception class;
  the findings and the exit code are what they would be without them
  (`tests/test_stage3_never_fails_a_scan.py`, also run on Python 3.10).
- **The new sections quote at the level the rest of the result does.** Found before the tag:
  at `masked` (the default) and `trimmed`, `where_to_look` wrote out a trust-store path that
  `trust_stores` masks, and `chosen_outside_files.leads` the target of an include, a key file
  named by path and the name of an environment variable. Below `full` such a target, a path
  in `angles` and the certificate path of `tls_termination.authentication_not_read` (in the
  clear since 0.41.0) are masked as a line is; a lead followed to the files read keeps its
  target, and `where_to_look` is built again from the masked sections. The independent review
  then found one more: the key a key file is named under in YAML, INI or HCL
  (`zzhost.corp.example: certs/c.pem`) was in the clear in `leads.items[].setting` and in
  `where_to_look`, for followed leads too. Below `full` such a key is masked, whatever the
  lead's status; the module's own words (`include`, `HostKey`, `cert`, `ssl_dhparam`, a call's
  name, `environment variable`) stay, and of the `load_pem_` calls only cryptography's own names
  (a key such as `load_pem_zzcodehost:` is masked, found by the second review). `full` is unchanged
  (`tests/test_masking_stage3_sections.py`). Not changed, and older than 0.50.0:
  `chosen_outside_files.places` keeps the name of a setting read from the environment at
  every level.
- **A credential in a dependency URL is masked below `full`.** Found by the independent
  review: `evidence.dependencies[].requested` keeps a PEP 508 request as written, and its URL's
  userinfo (`paramiko @ git+https://tok:secret@host/p.git`) was in the clear at `masked` and
  `trimmed`. From `pyproject.toml` (and Pipfile) this is older than 0.50.0; 0.50.0 added
  `setup.py` and `setup.cfg` as sources and with them two more ways in. The second review found
  more of the URL in the clear: a query token, the host, a home directory in a `file:` URL, and
  `user:p@ss@host` past its first `@`. Below `full` everything after a URL's scheme -- userinfo,
  host, path, query, fragment -- is now masked as a line is, at `masked` and `trimmed` alike (as a
  listener's server names are), on every dependency row; the scheme stays (`git+https://`,
  `file:`). `full` is unchanged, and the fingerprint does not read `requested`
  (`tests/test_masking_dependency_url.py`).
- **"proxy_ssl_verify not set" is not claimed across an include.** Found by the independent
  review: with `http { proxy_ssl_verify on; include sites/*.conf; }` in `nginx.conf`, the
  `proxy_pass https://` of `sites/a.conf` was reported as verification `off`, "not set", while
  `leads` showed the include followed. nginx inherits the directive from around the include. A
  "not set" row is now dropped when a file read that includes its file (directly or through
  another include, resolved as `leads` resolves them, every file a glob matches, not only the 20
  a lead lists) sets that module's `*_ssl_verify`; `off` there is its own row on its own line.
  Not resolved: whether the directive and the include are in the same block (any setting above
  suppresses the claim, so this errs toward silence, never toward "off"); a file included from
  outside the tree, which keeps the single-file rule; a directive set in a file the claim's own
  file includes below it (`include snippets/proxy.conf;` holding `proxy_ssl_verify on`), which
  still gives "not set"; and a relative include resolved from the root of the tree when the
  including file's own directory does not have it, as `leads` resolves it: `a/nginx.conf`
  with `include sites/*.conf;` is linked to a root-level `sites/x.conf`, which nginx run from
  `a/` would not read, and the claim there is dropped -- toward silence again
  (`tests/test_upstream_verify_across_include.py`). The third review found the walk quadratic:
  3000 files that each `include *.conf;` did not finish in 600 s. Each (target, directory) is
  now resolved once and the files below a setting file are found by one walk, linear in the
  include links (`tests/test_include_walk_linear.py`).
- **setup.py is read token by token.** Found by the independent review:
  `setup(install_requires=["requests"], description="cryptography")` gave a dependency row
  `cryptography`, because every string after `install_requires=[` on that line was read. The
  first fix ended the list at its bracket, and the second review found what that broke:
  `["paramiko"] + ["ecdsa"]` gave paramiko alone, and a `#` inside a string
  (`"foo @ git+https://h/x.git#egg=foo"`) was taken for a comment, so `description="paramiko"`
  on the next line became a row. The second fix parsed setup.py with Python's `ast`, and the
  third review found that `ast.parse` segfaults CPython 3.10 on a deeply nested expression
  (`x = a+a+...`, 150 000 terms: exit 139, the whole scan gone) and that a file Python cannot
  parse (Python 2) silently gave no row. setup.py is now read by one pass of a lexer with an
  explicit, bounded stack: nothing recurses, each character is matched once, and a Python 2 or
  broken file is read like any other. What is read: the value of `install_requires` or
  `extras_require` (a keyword or an assignment) -- literal lists, `+` of them, parentheses
  around them, both branches of `A if C else B` (not the condition), the values of a dict,
  adjacent strings joined, a string read a line at a time as setuptools reads it (blank and `#`
  lines dropped, a ` #` comment cut), an f-string with no placeholder, the leading literal name
  of one with (`f"acme>={version}"`). A variable, a call, a subscript (also of a literal:
  `["requests", "paramiko"][:1]`), a parenthesised tuple, a set, a lambda, and an element with
  any other operator or keyword (`%`, `.format`, `and`, a comprehension) is
  skipped, not guessed; so is an annotated or augmented assignment (`install_requires +=`).
  All 33 setup.py in the corpus and the control give the rows they gave before, on 3.10 and
  3.12. `setup_requires` and `tests_require` are not read (`tests/test_setup_py_arguments_only.py`,
  `tests/test_setup_py_never_crashes.py`, `tests/test_setup_py_subscript_lambda.py`). A bare
  tuple (`install_requires = "a", "b"`) gives its first element only. With
  every row of such a file now read, a setup.py with 200 000 requirements on one line made
  `qrp-mcp cbom` run past 15 minutes: the CBOM's confidence properties were quadratic in the
  rows that share a line (older code, reached now). Each file:line is graded once
  (`tests/test_cbom_many_rows_one_line.py`).
- **Two pinned expectations changed.** PKCS#11 `CKK_EC_EDWARDS` and
  `CKM_EC_EDWARDS_KEY_PAIR_GEN` are EdDSA, not EC (PKCS#11 3.1 §6.3; `tests/test_pkcs11_names.py`).
  A file whose `ssl_ecdh_curve` lists no group but X25519, X448 or curveSM2 no longer gives ECDH from the
  directive's name alone (`tests/test_row_491_algorithm_named_in_a_path.py`; what row 491 pins,
  ML-DSA-65 and ECDSA-P-256 from the path, is unchanged).
- **`findings_fingerprint` moves** where the new and changed rows appear. On the positive control
  (OpenSSH 7fe3b24, certbot 56ee049, Vault 41e571b, 0.49.0 against this release): OpenSSH 71 -> 72
  findings (+1 XEdDSA, `pkcs11.h:817`), four `CKK/CKM_EC_EDWARDS` rows EC -> EdDSA, sizes on 13
  `.pub` files (10 x RSA-1024, 2 x 2048, 1 x 3072) and P-256 on three EC/ECDH rows of
  `mlkem768nistp256-sha256` (`kex-names.c:70`, `kex.h:61`); certbot 41 -> 41 findings, two dependency
  rows from `setup.py` and `requested` (the pinned version) on four `tools/requirements.txt` rows;
  Vault 74 -> 74 findings, 5,435 -> 5,437 files read (two `.crl`). Every
  change is traced to its fix in the stage logs.
- The `tls_groups` rows of `proxy_/grpc_/uwsgi_ssl_conf_command Groups` carry a different
  `setting`: in a baseline they close and reopen. The CBOM label of a TLS verification row names
  its value (`ssl_verify_client on`); rows from before are all `off`, and their label is the same.
- Corpus regression against 0.49.0 (185 repositories, labels by an independent model): A' and B'
  unchanged in both splits. This is disagreement with a model, not recall or precision; it says
  nothing got worse, not that anything was gained.

Not claimed: that a closed pair catches every spelling (the catalogue is what the cited pages
document); that a catalogue of 10 pairs closes an ecosystem; any recall or precision figure. Left
out on purpose, and written in the catalogues' `scope`: the rest of the C APIs, Envoy and Traefik,
legacy `ipsec.conf`, JKS, Pipfile and Poetry, the `bign-*` groups, the parameter sets of HQC, BIKE,
FrodoKEM, Classic McEliece, Falcon, MAYO and the other schemes the scanner has no field for.

## 0.49.0 (2026-11-17)

Eight rows of the fix list, from five probes of LinkedIn rooms and one thread (17.11). Each was
reproduced on 0.48.0 (dab656c) with its probe before the fix, pinned by a test that fails on
0.48.0, and each fix was reverted once to see its tests fail.

- **A chain's root read as its leaf** (row 517, Georgi Ivanov). In a PEM bundle every
  certificate was `index: 1` (counted inside its block, which holds one), and `tls_listeners`
  takes index 1 as the leaf: in a `fullchain.pem` the root's RSA-2048 entered the listener's
  certificate as a second "signature on the certificate". The index is now the certificate's
  place in the file. Not in `findings_fingerprint`, which does not hold the index.
- **Who trusts the roots was not said** (row 517). The roots were read and `self_signed`, and
  `load_verify_locations(cafile=...)`, Go's `AppendCertsFromPEM` of a file read from /etc and
  nginx's `ssl_client_certificate` gave no output. `trust_stores` lists each such place: the
  path it names, the files read that it is, their anchors with families, whether the path is
  outside the tree, and `in_test_code`; scan JSON, MCP tools and CBOM (`qrp:trust_stores`). A
  path that is not a file read is source text and is masked below `--level full`.
  Bounded to those three forms (and `ssl_trusted_certificate`, `create_default_context(cafile=)`,
  `capath`); not Java trust managers or a system store used by default. On Vault 41e571b: 31
  places, all Go `AppendCertsFromPEM`, most of a PEM held in memory (`file: null`).
- **An algorithm chosen in the environment through a JCA factory was invisible** (row 518).
  `Signature.getInstance(System.getenv("SIG_ALG"))` beside a PKCS#11 KeyStore gave no row and
  `chosen_outside_files` 0. A `getInstance` of Signature, KeyPairGenerator, KeyAgreement or
  KeyGenerator whose argument is read from the environment is now a place there, with no family
  claimed (`Cipher.getInstance(...)` already was). python-pkcs11's
  `generate_keypair(KeyType.RSA, 3072)` now gives `key_size: 3072`. Left as they are: the
  identifier rows for function names such as `new_rsa_key`, which are notes by design.
- **Azure Key Vault's algorithm names, and where a KMS key lives** (row 519, Iakovos Ellinas).
  `client.sign(SignatureAlgorithm.rs256, digest)` gave no row: the Python SDK's members are
  lower-case (`rs256`, `ps256`, `es256`, `es256_k`), and are now read by the enum's name, never as
  a bare word. A row on a boto3 KMS call (`SigningAlgorithm=`, `EncryptionAlgorithm=`,
  `KeyAgreementAlgorithm=`, `KeySpec=` in a file with a boto3 `kms` client) or on an Azure Key
  Vault algorithm enum (in a file importing its cryptography client) carries `key_location:
  "kms"`, as a signing step has since 0.47.0; the CBOM tags the occurrence `[key: kms]`. It is not
  identity for baselines or `closure`. Not read for this: Google Cloud KMS, HashiCorp Vault.
- **ssh.com's SSH2 private key was not opened** (row 520, Bryant Nielson). OpenSSH's
  `regress/rsa_ssh2.prv` (`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`, four dashes) was
  `type_not_claimed`; the peek for key material knew the five-dash PEM header only. It is read:
  the family from the key type (`if-modn` RSA, `dl-modp` DSA), and an unencrypted RSA key's size.
  On OpenSSH 7fe3b24: 741 -> 742 of 873 files read (84.88% -> 84.99%), the key RSA-1024, and one
  more `private_key` finding; nothing else moved.
- **Certificate, configuration and key rows did not say they were test code** (row 521, Abid
  Hussain Mohammed). `in_test_code` was set on rows found in source text only, and
  `test_code.findings_in_other_code` counted a missing flag as other code. Every evidence row with
  a path now carries it, by the same rule. On certbot 56ee049: 252 in test code / 365 other ->
  340 / 277 (the 88 rows under tests/testdata the row named); the CBOM marks 29 more components
  `scope: excluded`. Findings and `findings_fingerprint` are unchanged. Whether a family is
  test-only is now decided over all its names: with the flag on fixture files, OpenSSH's
  composite ML-DSA-44-Ed25519 test keys would otherwise have marked the whole ML-DSA family
  test-only and set aside the ML-DSA outside tests (caught on the positive control before
  release).
- **The classical fallback in an IKE proposal was invisible** (row 522, Gowthami Pagilla).
  strongSwan `proposals = ...-ecp256-ke1_mlkem768, ...-ecp256` and the hybrid proposal alone
  gave the same `findings_fingerprint` and `key_establishment: pqc_ready`. A proposal that can be
  negotiated with a classical key exchange alone (no `keN_`, or every `keN_` with `none` or a
  classical alternative) is a row in `evidence.ike_proposals` (`offered: alone`), as `tls_groups`
  (0.28.0) and `ssh_kex` are: the fingerprint moves, `closure` closes `ecp256 offered alone`, the
  summary lists it in `fallback_beside_hybrid` and its key-establishment part reads
  `hybrid_partial` instead of `pqc_ready` (with `because`), `--mandate` dates it as key
  establishment, and the CBOM has a component. Without the fallback the part is `pqc_ready`, as
  before. Not read for this: Libreswan's `ike=` syntax, FortiOS, Cisco, Junos.
- **A sector's duty with no date for code** (row 523, Meir Goldman). `--mandate il-boi |
  ch-finma | hk-hkma | sg-mas`: Bank of Israel letter 202501, FINMA Guidance 05/2026, HKMA circular
  B1/15C, MAS consultation paper P019-2026, each quoted as the register of 17.11 quotes it, with
  `read_on`. A new kind, `sector_duty`: the sector and the duty, `in_scope: 0`, `gate:
  "not_applicable"`; no occurrence gets a clause and the exit code never moves. MAS is
  `in_force: false` (a consultation). A span ("within a year", "mid-2027") is said as written;
  no day is inferred. HKMA's `url` is null: the circular's address was not recorded.
- **`stale` measured our reading, not the document** (row 524). A mandate now keeps the sha256 of
  each document as downloaded when read (`documents`), where the address and the hash were both
  recorded: nine of the sixteen. A scan says `document_changed: "not_fetched"`. `qrp-mcp
  mandate-check NAME --document FILE ...` compares copies you downloaded, matched by hash in any
  order (without `--document`, a `curl` for each): `document_changed` true, false or not_fetched,
  exit 1 when one changed.
  **Limit:** qrp-mcp still makes no network call, so the fetch is yours; a changed hash says the
  bytes changed, not that a deadline moved; only PDFs are recorded, since an HTML page changes its
  bytes with no change to its text; uk-ncsc, au-ism, sg-csa-cii, cnsa-2.0, nist-ir-8547, ch-finma
  and hk-hkma have no recorded hash and stay not_fetched.

Second batch, the same day, before release: rows 516 and 525–528. Each was reproduced on the
first batch's tree (e897092) and pinned by a test that fails there; each fix was reverted once to
see its tests fail.

- **`--as-of` stopped the scan on certbot** (row 516). certbot's acme tests hold the ARI draft's
  example certificate, valid from and to the year 1 (GeneralizedTime `00010101000000Z`). The
  certificate rows wrote the year as `%Y` does on glibc, unpadded (`1-01-01T00:00:00Z`), and
  `--as-of` could not parse it back: a ValueError, with no output. Dates are now written with a
  four-digit year (`0001-01-01T00:00:00Z`), which `--as-of` and the CBOM's `notValidAfter` read;
  `expired` is true, as it was without `--as-of`. The date is the certificate's own, so it is kept,
  not set aside as unread. `findings_fingerprint` does not hold dates and is unchanged.
- **`--mandate cnsa-2.0` passed AES-128 and SHA-256 code in silence** (row 527). CNSA 2.0 requires
  AES-256 and SHA-384/512 (already under CNSA 1.0), and the gate counted only the public-key
  occurrences: `in_scope: 0`, `pass`. The scan does not read symmetric ciphers or hashes, so it
  cannot count their sizes; four documents date them, and their blocks now carry `symmetric`
  (`status: not_established`, what the document dates, its words with the section): `cnsa-2.0`,
  `au-ism` (AES-128/192, SHA-224/256 and HMAC-SHA256 not approved beyond 2030 -- "for
  interoperability and maintainability reasons", not quantum), `ca-cccs` (SHA-224, SHA3-224, HMAC
  keys under 128 bits by the end of 2030) and `nist-ir-8547` (the 112-bit standards in 2030). A
  gate that would pass reads `not_established` with the reason, as for unread files (row 204); a
  fail stays a fail; the exit code does not change. The ten other documents date public-key
  cryptography only and still pass. Not done: reading AES key sizes or hash output sizes.
- **Randomness and key derivation were out of scope only in docs/measurement.md** (row 525, Tooba
  Qasim). SecureRandom, DRBG, `os.urandom`, `secrets`, `random` for a token and a remote entropy
  service gave no output, and README's "What it is not" did not say why. Decided: they stay out of
  scope. README now says so, with symmetric ciphers, hashes, MACs and KDFs, and the output carries
  it in `coverage.claims.out_of_scope_by_design` -- scan JSON, the MCP tools and the CBOM's coverage
  properties. Nothing is detected that was not before.
- **A PPK written in swanctl.conf was not committed key material** (row 526, Daniel Grazioli).
  `secrets { ppk-qkd { secret = 0x...(256 bits) } }` gave `embedded_keys: []`, and the PPK finding
  did not say where its secret came from. The secret is now a row in `evidence.embedded_keys`
  (`strongSwan PPK secret`, `key_material: shared secret`, `key_size`), a `private_key` finding
  with its own reason (rotate it), and a CycloneDX `secret-key`; its value is never quoted. A
  classical IKE PSK (`ike<suffix>`) is not read for this. The PPK finding gains `ppk_source`: the
  place, or "not in the files read". Out of scope, and said in README: a client of a QKD key
  management entity, and where a PPK comes from beyond the files read.
- **The defects of the blind-spot audit of 0.48.0** (row 528; 50 probes, read-only, 17.11). Each
  is the audit's probe line, now a test:
  - `gpg --batch --detach-sign`, `gpg -b`, `gpg --clearsign` gave no signing step, while README
    names `gpg --sign` (#18). The gpg rule now reads `-s`/`--sign`, `-b`/`--detach-sign`,
    `--clearsign` after other options and in a short-option cluster; not `--verify` or `-c`.
  - Signing through a KMS, Vault or an agent left the file "read" with nothing said (#17). Decided:
    such a call is a place in `chosen_outside_files`, `kind: remote_signing`, with `key_location`
    (`kms`, `vault`, `ssh_agent`): boto3 KMS `sign(KeyId=...)` with no algorithm on the line,
    Google Cloud KMS `asymmetric_sign`, Vault `transit/sign/` by an HTTP or client write and hvac
    `transit.sign_data`, paramiko ssh-agent `sign_ssh_data`. No family is claimed. A boto3 call wrapped
    over lines is read with the four lines after it, so an algorithm written there is a row.
  - AWS KMS `RSASSA_PSS_SHA_*` and `RSASSA_PKCS1_V1_5_SHA_*` gave no row (#9): RSA now, with
    `key_location: kms` in a boto3 KMS file.
  - `ECC_SECG_P256K1` was reported as P-256 (#10): it is secp256k1.
  - Google Cloud KMS's `CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256` (#11) and Swift's
    `kSecAttrKeyTypeRSA` (#39) read as "named but not used": now uses; the Swift line's
    `kSecAttrKeySizeInBits: 1024` is the size.
  - An environment read was a place only by the variable on the left, and Go's `os.Getenv` never
    (#6): the environment variable's own name now decides too (`ALG2 = os.environ["JWT_ALG"]`,
    `curve := os.Getenv("TLS_CURVES")`); a secret or a location (`*_KEY`, `*_FILE`, `*_URL`), a
    debugging switch, or a value written into the environment (`process.env.X = '...'`, found on
    the corpus) is not a place.
  - A JOSE default beside an environment read (`os.environ.get('JWT_ALG', 'ES256')`,
    `process.env.JWT_ALG || 'RS256'`) was not a place (#7, row 511): it is, with `default` and
    `overridable: true`, as docs/what-it-reads.md already promised.
  - RSA-1024 made on one line by `RSA_generate_key(1024, ...)`, paramiko `RSAKey.generate(1024)` or
    cfssl's one-line `{"algo": "rsa", "size": 1024}` had `key_size: undetermined`, so it never
    reached `weak_count` or `algorithm_key_sizes` (#38). The size is read.
  - A private key written as a C byte array in a `.h` gave nothing, not even
    `claimed_but_not_decoded` (#31, row 459): one whose DER parses is in `embedded_keys`, its bytes
    not quoted.
  - The one new file type (decided): `.env`, `.env.production` and the like, read as
    configuration for the private key they can hold.
  - The OpenSSL a base image carries (`FROM alpine:3.12`) is not read, and README now says so in
    "What it is not" (decided: a limit, no code).
  Not done from the audit, and not in this row: HD wallets (BIP32/BIP39), Azure `RSA-HSM`,
  minisign/signify/`ssh-keygen -Y sign`/`git tag -s`, libsodium `crypto_sign_keypair` alone,
  smallstep, a key as a hex string, `SHA1PRNG`, and the other file types it listed.

**What changes for an existing user.** A strongSwan configuration with a proposal that can be
negotiated classical now has `ike_proposals` rows -- beside a hybrid or not -- so its
`findings_fingerprint` moves; a baseline written by 0.48.0 does not hold them (they read as new),
and under `--mandate` they are dated key-establishment rows that can fail a gate that passed on
0.48.0. An IKE hybrid with such a fallback reads `hybrid_partial` in its key-establishment part.
Rows on boto3 KMS and Azure Key Vault calls gain `key_location`, which is not identity, and the
CBOM's `additionalContext` of their occurrences gains `[key: kms]`; certificate, key and
configuration rows gain `in_test_code`, and the CBOM marks the test-only ones `scope: excluded`.
`trust_stores` and the sector duties never move a gate. Under `--mandate cnsa-2.0`, `au-ism`,
`ca-cccs` or `nist-ir-8547` a gate that passed on 0.48.0 now reads `not_established` (row 527),
with the same exit code 0; a check on the word `pass` needs to read `not_established` too.
From the second batch (row 528) a tree with `gpg --detach-sign`/`-b`/`--clearsign`, AWS KMS
`RSASSA_*` names, a C-array private key, a `.env` file or an RSA size now read on one line gets
rows it did not have, so its `findings_fingerprint` moves and a 0.48.0 baseline reads them as new;
`chosen_outside_files` gains places (environment reads by the variable's name, Go `os.Getenv`,
JOSE defaults, `remote_signing`), which are not identity; a `.env` file counts as read, not as
`type_not_claimed`.

Positive controls against 0.48.0 (OpenSSH 7fe3b24, certbot 56ee049, Vault 41e571b): files read
742 (+1), 850, 5,434; findings 71 (+1, the SSH2 key), 40, 74; the same detected families and
`chosen_outside_files` counts. certbot's and Vault's `findings_fingerprint` are the same; OpenSSH's
moves by the SSH2 key. After the second batch, on the installed wheel: OpenSSH 742 of 873, 71
findings, the same fingerprint and 17 `chosen_outside_files` places (the environment-name rule
first added OpenSSH's fuzz-harness `getenv("KEX_FUZZ_DEBUG")`; a debugging switch is now not a
place); certbot 850, 41 findings (+1: `tools/_release.sh:169` signs with `gpg -u ... --detach-sign`,
which was silent), so its fingerprint moves; Vault 5,435 (+1: `ui/.env`, now a read file type), 74
findings, the same fingerprint. `--mandate` does not move `findings_fingerprint` (certbot with six
mandates, checked). The corpus regression against 0.48.0 (185 pinned public repositories, one
labeller's labels) is unchanged in both splits: disagreement with the model, A' 395 and 71, B'
262 and 42 -- disagreement with a model, not recall or precision; after the second batch
(143fb0c -> 69727a9) the same: A' 395 and 71, B' 262 and 42. Not claimed: any change to how
much of a tree's own cryptography is found beyond the rows above.

## 0.48.0 (2026-11-17)

- **`--mandate` knew only the United States** (17.11, after a public deadline tracker: a list
  of dates, with no link to the code they catch). `cnsa-2.0` and
  `nist-ir-8547` were the only names. Ten more, each read from the authority's own document
  (on 2026-11-17; the ISM's sentences from the September 2026 PDF fetched on 2026-09-27, the
  `read_on` its block carries) and quoted in `profiles.DATED_MANDATES`: `eu-pqc-roadmap` (NIS Cooperation Group
  roadmap v1.1), `uk-ncsc` (NCSC timelines v1.0), `ca-cccs` (ITSP.40.111 v5 and ITSM.40.001),
  `au-ism` (ISM September 2026), `nl-rqs` (Rijksbrede Quantumstrategie, 5 oktober 2026),
  `se-ncsc` (NCSC Sweden, 27 maj 2026), `jp-gov` (Cabinet Secretariat interim report, November
  2025), `sg-csa-cii` (CSA Quantum-Safe Handbook V1, CII owners), `in-dst` (DST / National
  Quantum Mission Task Force report, May 2026) and `de-bsi` (BSI TR-02102-1 2026-01 and the
  Leitlinie zur Umstellung auf PQC, 11 September 2026). Each clause gives the rules that name the
  occurrence's family and role and the earliest of their dates as `deadline`, which the gate
  counts; where a document dates algorithms (Canada, Australia, Germany), the date is the
  algorithm's -- DSA, P-224 and RSA below 3072 bits by the end of 2030 in Canada, ML-KEM-768 and
  ML-DSA-65 not approved beyond 2030 in Australia. A family a document does not list (EdDSA and
  DSA in the ISM, X25519 in ITSP.40.111, whose curves are P-224 to P-521) is `not_in_document`,
  with no date. A signing step whose key's family is not read gets no clause from these
  documents (CNSA 2.0 still dates signing as a class). Scan JSON and SARIF, and `.qrp.toml`.
  **Not claimed / not done:** a date for a class of system the scan cannot see (EU and German
  high-risk use cases by 2030, UK highest-priority migrations by 2031, India's CII by 2029) is
  said in `earlier_if` and `conditional` and never counted (`counted_by_gate: false`): the gate
  counts only a date that applies to the occurrence by itself; nothing here is a legal finding, and several are recommendations (`addresses`
  says whose and what kind). Left out: South Korea (the 2031
  date for important national systems is in a press release; the per-algorithm table is in
  drafts that were not downloaded), France (the State's roadmap dates systems handling
  Diffusion Restreinte information and products bought from 2030 -- nothing a line of code
  carries), Singapore's MAS (a consultation, not in force), Hong Kong (sector readiness by 2030,
  not migration), Israel's Bank of Israel letter (a plan within a year), Switzerland's FINMA (a
  roadmap by mid-2027), the Czech NÚKIB estimate and the G7 Cyber Expert Group statement
  ("non-authoritative"). No detection changed: without `--mandate` a scan of OpenSSH and certbot
  gives the same evidence, findings and summary as 0.47.0.
- **The table of deadlines could go stale without a word.** A mandate is a reading of a document
  on a date; a newer edition moves the dates and nothing said so. Every mandate block now has
  `read_on_age_days` (to `as_of`), `stale_after_days` (180) and `stale`; past 180 days,
  `stale_because` with the document's URL, and a line on stderr. It does not change the gate or
  the exit code, and it is counted to `--as-of`, not the clock, so a rerun with the same `--as-of`
  is the same bytes. **Not claimed:** that a reading younger than 180 days is current: a document
  can change the day after it was read.

## 0.47.0 (2026-11-16)

- **Where the signing key lives was not said** (row 482, Richard Blech; probe `hw-sign-proba`,
  0.45.0). `tpm2_sign -c ...ctx` and `pkcs11-tool --sign --mechanism ECDSA-SHA256` gave only
  `source_code` ECDSA rows, not signing steps; a key URI was cut or rewritten -- cosign `--key
  "pkcs11:token=a;object=b"` became `pkcs11:token=a` (the value stopped at `;`) and `--key
  awskms:///alias/x` became `awskms:/alias/x` (a path normalisation). `tpm2_sign`, `pkcs11-tool
  --sign`/`-s` and `openssl pkeyutl -sign` are now signing steps, and every step carries
  `key_location`: `file`, `tpm`, `pkcs11_token`, `kms` or "not determined from the line"; a
  quoted key value is read whole, a key URI is kept as written without its query and without
  any `pin-value`/`pin-source` attribute (RFC 7512; not copied into `signing_key`; at `--level full` the excerpt still holds
  the line as written); tpm2_sign's `-s` and pkcs11-tool's `-m`
  give `key_algorithm`; an OpenSSL `-engine`/`-provider` `pkcs11` or `tpm2` (tpm2-openssl
  docs/keys.md `-provider tpm2`, tpm2-tss-engine README `-engine tpm2tss`) gives the location
  where the key is not a URI of its own. Sources: tpm2-tools man/tpm2_sign.1.md and
  man/common/alg.md, OpenSC pkcs11-tool(1), cosign doc/cosign_sign.md (at 6181e75). Scan JSON, MCP tools, CBOM
  (`qrp:evidence:signing_commands`). **Not claimed / not done:** a key in a Kubernetes secret
  (`k8s://`), `env://`, a gpg keyring or a Java keystore is "not determined"; Android StrongBox
  and Apple Secure Enclave keys in code (rows 484, 483) are still not given a location; cosign's
  `openbao://` and `ovhcloud://` are not in the KMS list; whether the token or TPM is the one the
  line implies is not visible from the file.
- **Swift was not read** (row 483, Fatima Khan; probe `mobile-proba`, 0.45.0).
  `ios/DeviceBinding.swift` (`kSecAttrKeyTypeECSECPrimeRandom`, 256 bits, Secure Enclave) was
  `type_not_claimed`: 1 of 2 files read. `.swift` is now a source type, and Apple's names are
  rules: the Security framework's EC key type (`kSecAttrKeyTypeECSECPrimeRandom`,
  `kSecAttrKeyTypeEC`) and CryptoKit's `P256/P384/P521.Signing` (ECDSA, curve from the name),
  `.KeyAgreement` (ECDH) and `Curve25519.Signing` (Ed25519 -- the X25519 rule took it before).
  CryptoKit's `MLKEM768` / `MLDSA65` and the Security framework's `.rsa*` / `.ecdh*` algorithm
  names were already read by the existing rules once the file is opened. Scan JSON, MCP tools,
  CBOM. Found by re-running the probe. **Not claimed / not done:** the probe's key size (256, on
  the `kSecAttrKeySizeInBits` line) is not read, so the EC row has no curve; where the key lives
  (Secure Enclave; with row 482, which does not cover it either); `Insecure.MD5` and the
  `kSecKeyAlgorithmRSASignature...` C constants give no row; Objective-C (`.m`) is not read.
- **An SLH-DSA name in liboqs's spelling gave no parameter set** (row 486, probe `hbs-proba`,
  0.45.0). `oqs.Signature("SLH_DSA_PURE_SHA2_128S")` read SLH-DSA with `parameter_set: None`:
  liboqs puts `PURE_` or `<hash>_PREHASH_` between `SLH_DSA_` and the FIPS 205 set (src/sig/sig.h,
  e.g. `SLH_DSA_SHA2_512_224_PREHASH_SHAKE_128F`), and the set was read only from
  `SLH-DSA-SHA2-128s` with nothing in between. It now reads `SHA2-128s` from both. Scan JSON, MCP
  tools, CBOM (`parameterSetIdentifier`). Found by re-running the probe. **Not done:** pure vs
  pre-hash is not recorded; pyspx (`import pyspx.shake_128f`) is round-3 SPHINCS+, not FIPS 205,
  and its set is on the import line, not the call; the names leanSPHINCS and leanSig wait for a
  primary source, as the row says. Seen and not fixed: in the probe the pyspx call rows carry
  `provider: liboqs` (the same file also calls `oqs.Signature`).
- **A docstring word made a nested helper's key generation a ban** (row 505, D11 of
  `boot-proba/REZULTAT.md` §8). U-Boot `test/py/tests/test_vboot.py`: `test_vboot_ext_data_bounds`
  ("Test that malformed external-data properties are rejected.") is a rejection test by its
  docstring (rel3-rules), so every line in it was a ban -- including `openssl genpkey -algorithm
  RSA` (:792-793) inside the nested `create_rsa_pair` that makes the key the test signs with.
  A function defined inside a rejection test now runs what it calls, as a library function
  already did: its body is outside the rejection. U-Boot `test_vboot.py`: :792 and :793 `ban` ->
  `registry_name`, nothing else moved. Repro `boot-proba/repro/ban-docstring/a` now gives what
  `b` gives. Scan JSON, MCP tools, CBOM. **Not changed:** the test's own lines stay in the
  rejection (`def create_rsa_pair` at :785 and the call `create_rsa_pair('dev')` at :834 are
  still `ban`); the rule still reads only the docstring's first line, and cannot tell what the
  test rejects (here malformed data, not RSA) from what it does.
- **A negative test set MCUboot's headline to "RSA-1024 critical"** (row 497, D1 of
  `boot-proba/REZULTAT.md` §8). `scripts/tests/keys/test_rsa.py:39` `RSA.generate(key_size=1024)`
  sits in `with self.assertRaises(RSAUsageError):` -- a test that 1024 is refused -- and was a
  `call`: `algorithm_key_sizes.RSA` 1024, a finding `RSA-1024`, `weak_key`, severity `critical`.
  A `with pytest.raises(...)` / `self.assertRaises(...)` block was a rejection test (row 91) only
  when its line also held a denial word; now the block is one when a line in it names a key size
  (RSA, DSA, DH), calls included, to the end of its indentation. A block without a size is read
  as before: `with pytest.raises(InvalidSignature):` over an ECDSA `verify` expects a working
  algorithm to refuse bad data, a use (a first version of this fix made it a ban and lost the
  finding `ECDSA-256`; caught in review). MCUboot: lines 38-39 `call` -> `ban`, RSA headline
  1024 -> 2048, finding `RSA-2048` severity high; no other row moved. Scan JSON, MCP tools, CBOM.
  **Not claimed:** a block that expects a curve refused (`ec.SECP192R1()`), with no size, is still
  read as a use. The size decides for the whole block, not what it expects: `with
  pytest.raises(InvalidSignature):` over `rsa.generate_private_key(65537, key_size=2048)...verify(...)`
  is still a ban (0.46.0: a call, finding `RSA-2048`), and so is an ECDSA line in a block where
  another line names an RSA size.
  **Not reproduced:** the other half of D1, the comments in Mbed TLS `rsa.h` ("128 Bytes if
  RSA-1024 is used"), were already `comment` rows and never reached the headline size; pinned
  by a test, no code changed for it. Test code stays counted, not excluded: only the block
  changed.
- **A CMake variable was read as the environment** (row 505, D10 of `boot-proba/REZULTAT.md`
  §8). MCUboot's `boot/zephyr/CMakeLists.txt:748` `set(key_size "${boot_enc_key_size}")` and
  `:752` `math(EXPR key_size "${key_size} * 2")` -- the byte length of the encrypted-key TLV,
  computed in the build -- were the 2 places of `chosen_outside_files`. In CMake `${name}` is a
  CMake variable and the environment is `$ENV{name}` (cmake-language(7)); in a `CMakeLists.txt`
  or `*.cmake` the `${name}` form is no longer read as a run-time reference, `$ENV{name}` still
  is. MCUboot: 2 places -> 0. Scan JSON, MCP tools, CBOM (`qrp:chosen_outside_files:*`). **Not
  claimed:** a CMake cache variable can be set with `-D` on the command line; that is not read
  as a place, before or now. MCUboot's real key-file path (`CONFIG_BOOT_SIGNATURE_KEY_FILE`) is
  row 500's signing-step record, not this.
- **Three names read as a family they are not** (row 506, D12 of `boot-proba/REZULTAT.md` §8).
  U-Boot's SH7722 register `#define MLDSA1R 0xFE940430` (`arch/sh/include/asm/cpu_sh7722.h:693`)
  was ML-DSA; a digit right after `mldsa` now has to start a FIPS 204 parameter set (44, 65,
  87). tinycrypt's ECDSA file `ecc_dsa` (`#include <tinycrypt/ecc_dsa.h>`, `ecc_dsa.c` in CMake
  and in MCUboot's `sim/mcuboot-sys/build.rs`) was DSA with severity high -- 5 rows, MCUboot's
  whole DSA finding; ECC + DSA (and tinycrypt's ECC + DH) is now joined as EC + DSA was, and the
  Rust DSA word skips `ecc_dsa`. The EC identifier rows on the same `ecc_dsa`/`ecc_dh` lines
  (8 on MCUboot, never counted as uses) go with them. `#define MBEDTLS_REMOVE_3DES_CIPHERSUITES`
  and `MBEDTLS_REMOVE_ARC4_CIPHERSUITES` were a declaration, a use; a `#define` whose name has a
  `REMOVE_` word is now a not-a-use, rule `removal list` (`keys.remove(rsa_key)` is still a use).
  Scan JSON, MCP tools, CBOM. **Not claimed:** `ecc_dsa` does not become an ECDSA row of its own
  -- it now reads as `ec_dsa` always did, one family word the identifier rule does not read
  alone; MCUboot's ECDSA rows come from elsewhere in the same files. Found on MCUboot f30be48
  and U-Boot 6487c50 with 0.46.0; not re-measured on the corpus. **Seen in review, not changed:**
  the join reads every `ECC_DH` that way, and Mbed TLS spells "EC and FFDH" so
  (`tests/scripts/all.sh`: `"ECC" or "ECC_DH"`, `accel_ecc_ffdh`); in U-Boot's copy 6 such lines
  lost their EC and DH rows (5 declarations or references, 1 comment), with no row in their
  place. DH stays found in U-Boot from other lines.
- **Key material in three formats was not read** (row 507, D13 of `boot-proba/REZULTAT.md` §8).
  MCUboot's `sim/src/*_pub_key-rs.txt` (public keys as a Rust byte array, `&[0x30, 0x59, ...]`)
  and U-Boot's `doc/chromium/files/devkeys/kernel_data_key.vbprivk` and `kernel.keyblock` were
  `type_not_claimed`. A `*-rs.txt` is now read as one DER public key after another (MCUboot's
  `ecdsa_pub_key-rs.txt` holds a P-256 and a P-384 key), each a row at its line with family, size,
  curve and `key_material: "public key"`; a `.vbprivk` is read from the DER after its 8-byte
  algorithm word (the size is the key's, not the header's), as a row and an embedded private key;
  `.vbpubk` and `.keyblock` (vboot's own packed-key layout) are claimed and named
  `claimed_but_not_decoded`. In the scan JSON, the MCP tools and the CBOM (one key component
  each, row 502). MCUboot: 7 keys in 6 files, `coverage_pct` 84.9% -> 85.6%; U-Boot: RSA-2048 in
  the `.vbprivk`. **Not done:** MCUboot's `enc-aes128kw.b64` / `enc-aes256kw.b64` stay
  `type_not_claimed` -- 16 or 32 bytes of base64 with nothing to read an algorithm from but the
  file name, and symmetric keys are out of scope (docs/measurement.md); a C array of a key
  (`cypress-test-ec-p256.pub`) is still `claimed_but_not_decoded`; the `.keyblock`'s key is not
  decoded.
- **Every directory named `vendor` was excluded, wherever it was** (row 507, D14). On U-Boot that
  removed `tools/binman/test/vendor/`, 35 test device trees for vendor image formats, before
  counting. `vendor/` is now excluded only at the root of the tree or beside a package manifest
  (`go.mod`, `composer.json`, `Gemfile`, `Cargo.toml`, `package.json`, ...); any other is read, and
  `instrument.excluded_dirs` names the rule (`vendor (at the root, or beside a package
  manifest)`), so a closure against an older result says the filter differs, as it does. Go's
  `vendor/modules.txt` is read as before. U-Boot: the 35 files read, none gives a row. **Not
  changed:** `build/` and the other names still exclude anywhere (U-Boot's `doc/build/`, 10 files).
- **Firmware signing steps were not read, and a step never said its key was out of reach**
  (row 500, D4 of `boot-proba/REZULTAT.md` §8). `SIGNING_COMMAND_PATTERNS` had nothing for
  `mkimage -k/-G/-K`, `binman sign` or `imgtool sign`: both scans had
  `qrp:evidence:ci_signing_commands: 0`. They are now signing steps (`mkimage_sign`, `binman_sign`,
  `imgtool_sign`) in scripts and pipelines, with the key they name (`-k`, `-G`, `--key`); a key
  written as a whole variable (`-k $1`, `${KEY}`, `%KEY%`) is named as written, where before it
  was dropped; a piece of an expression (`--key ${{ secrets.K }}`, `"$(dirname "$0")/k.pem"`) is
  not named. Every
  signing step whose key is not a file the scan read now carries `key_algorithm`: the algorithm
  its line names (`binman sign -a sha256,rsa4096`: "RSA-4096, named on the line") or "not
  determined: key not in the files read". In the scan JSON, the MCP tools (the finding's reason
  says the named algorithm) and the CBOM (`qrp:evidence:signing_commands`, each step with its key
  and `key_algorithm`, beside the count). On U-Boot: tools/iot2050-sign-fw.sh:49,50, RSA-4096,
  key `$1`; on MCUboot none -- its tree holds no `imgtool sign` line in a script, and the CMake
  site D4 names (boot/zephyr/CMakeLists.txt:386-401) is `imgtool getpub`, which is not signing.
  **Not done:** a step written as a Python argument list (`[mkimage, '-F', '-k', tmpdir, ...]`,
  U-Boot test/py/tests/test_vboot.py:256) or a CMake `COMMAND` split over lines is not read as a
  step.
- **MCUboot's EC256 naming was not read** (row 501, D5 of `boot-proba/REZULTAT.md` §8; MCUboot
  f30be48). `MCUBOOT_SIGN_EC256`, `BOOTUTIL_SIGN_EC256: 1`, `CONFIG_ESP_SIGN_EC256=1` and the
  signing key `CONFIG_ESP_SIGN_KEY_FILE=root-ec-p256.pem` gave no row, while the RSA and Ed25519
  lines beside them did. MCUboot's `SIGN_EC256` / `SIGNATURE_TYPE_EC256` is ECDSA P-256 and
  `SIGN_EC384` P-384 (image_validate.c expects IMAGE_TLV_ECDSA_SIG for them); `ENC_EC256`,
  `ENCRYPT_EC256` and the TLV `ENCEC256` are its ECIES-P256 (docs/encrypted_images.md), read as
  ECDH P-256; each row carries the curve and size. `ec-p256` is read as the value of a
  `SIGN_KEY_FILE` / `SIGNATURE_KEY_FILE` setting, as `root-rsa-2048.pem` already was. On MCUboot:
  lines naming EC256 or ec-p256 without any row 161 -> 24 of 198, source rows 4547 -> 4736,
  findings 37 -> 37. **Not claimed:** `ec-p256` in any other file name (a script's
  `../../root-ec-p256.pem`), `EC256` without SIGN or ENC before it (`EC256_PUBK_LEN`, a make
  variable `BOOT_EC256`) stay unread.
- **U-Boot's FIT image sources, device trees and defconfigs were not read** (row 498, D2 of
  `boot-proba/REZULTAT.md` §8; U-Boot 6487c50). `.its` (32), `.dts` (5053), `.dtsi` (4437), `.dtso`
  (379) and `configs/*_defconfig` (1599) were all `type_not_claimed`, so the files that say how
  the firmware is signed -- `algo = "sha256,rsa3072"`, `CONFIG_RSA=y` -- were the ones not read.
  They are now claimed as configuration and read by the algorithm rules (not by the TLS, IKE and
  IaC readers, which found nothing in them and cost U-Boot about 16 s more in one run). `CONFIG_RSA=y` /
  `CONFIG_SPL_RSA=y` is an RSA row (none of the 20 U-Boot defconfigs with it gave one: the
  identifier alone was not read), and Kconfig's `# CONFIG_X is not set` is a switch off, in an
  `sdkconfig` too. On U-Boot: `coverage_pct` 60.28% -> 89.50%, 236 rows in these files (RSA 111,
  SHA-1 79 of which 10 switched off, ECDSA 29, MD5 15, 3DES 2 -- OMAP's DES accelerator clock),
  findings 188 -> 188. Scan time on U-Boot, rows 498-507 together, two back-to-back runs each on
  this machine: 40.8 / 41.1 s before, 48.1 / 48.5 s after. Two false positives the new files
  showed are closed: an EC or DSA carried by a defconfig identifier is not read (all 25 were `CONFIG_DDR_ECC`, `CONFIG_SPL_NAND_ECC` or
  `CONFIG_DM_DSA`), and a hex word `0x25519f22` is no longer X25519. **Not claimed:**
  `key-name-hint`, `required` and `keyfile` name a key, not an algorithm, and give no row;
  `CONFIG_FIT_SIGNATURE=y` names no family and gives none; a plain `defconfig` (no board name) is
  not claimed.
- **U-Boot's FIT algorithm names and RSA header gave no row** (row 499, D3 of
  `boot-proba/REZULTAT.md` §8). `"sha1,rsa2048"` (tools/fdt_add_pubkey.c:7), `-a sha256,rsa4096`
  (tools/iot2050-sign-fw.sh:49), `#include <u-boot/rsa.h>` and, in a file with nothing else,
  `RSA_DEFAULT_PUBEXP` and `struct rsa_public_key` (lib/rsa/rsa-mod-exp.c) were read and silent,
  while `"rsa2048"` and `<openssl/rsa.h>` were rows. `<hash>,rsa<1024|2048|3072|4096>` is now an
  RSA row with its size, and `<u-boot/rsa.h>` is RSA as `<openssl/rsa.h>` is (so the file's RSA
  identifiers are read). Reproduced from the probe's files, one per case. On U-Boot: 84 more RSA
  rows in `.c`, 25 in `.py` and `.sh`. **Not claimed:** the SHA-1 half of `sha1,rsa2048` is not made a row; the ECDSA names
  (`sha256,ecdsa384`) were already read with their size (row 503).
- **An RSA key that wraps a symmetric key did not say so** (row 495, Abhishek J., "AES-256 data
  is largely safe"; probe `aes-proba`). `kek.public_key().encrypt(archive_key, padding.OAEP(...))`
  with `archive_key = AESGCM.generate_key(bit_length=256)` read RSA-4096 at lines 7 and 8 and
  nothing tied the RSA key to the AES key it protects. The RSA row of an OAEP `.encrypt(<name>,
  ...)` (on one line, or split over up to four as a formatter writes it) now carries `wraps`: the name (masked below `--level full`, like a line), and where the
  file assigns that name exactly once with `generate_key(bit_length=N)`, `os.urandom(n)`,
  `secrets.token_bytes(n)` or `get_random_bytes(n)`, `what: "symmetric key"`, `key_size` and
  `assigned_at`; otherwise `what: "not read"` with the reason in `basis`. In the scan JSON, the
  MCP tools and the CBOM (`qrp:wraps`). Found by re-running the probe. **By design, unchanged:**
  AES gives no row of its own -- symmetric cryptography is out of scope (docs/measurement.md),
  now pinned by a test. **Not done:** ECIES, and AES key wrap under a DH-derived key (they need
  the data flow across lines); PKCS#1 v1.5 encryption of a key; a size from any other
  generator; SARIF does not carry `wraps`. The field is named `wraps`, not `protects`, which
  already means what a PPK makes safe.
- **The CBOM put every private key into one component** (row 502, D6 of `boot-proba/REZULTAT.md`
  §8). Both CBOMs had a single `crypto:embedded-private-key-material`, "Embedded private key
  material", whose occurrences said only "private key material in a ... block", though the scan
  JSON had each key's algorithm, size and curve. Each key is now its own `related-crypto-material`
  component (`type: private-key`, or `public-key` for a public-key PEM that parsed, row 503) with
  `size`, `algorithmRef` (the algorithm component at the key's own file and line, of its family,
  where there is exactly one) and `qrp:curve`; a key that did not parse keeps the generic name and
  `qrp:key_unread`. On MCUboot: 21 private-key and 4 public-key components, every `algorithmRef`
  resolving. Validated against the vendored CycloneDX 1.6 schema. **Changed for readers:** the
  bom-ref `crypto:embedded-private-key-material` is gone; a reader that looked it up now finds
  `private-key:<path>-<line>-<hash>` refs. **Not done:** `qrp:classification` on the key components
  (D6's last sentence); the embedded-key finding in the scan JSON is unchanged
  (`algorithm_family: private_key`, `classification: unknown`).
- **A public-key PEM was not read as a key, and key sizes were uneven** (row 503, D7 and D8 of
  `boot-proba/REZULTAT.md` §8; MCUboot f30be48, U-Boot 6487c50). `enc-x25519-pub.pem` and
  `root-ed25519-2-pub.pem` gave "object identifier observed in the file; the file was not decoded
  as a certificate" with no size, while their private keys read 256; a PKCS#1 `RSA PRIVATE KEY`
  file's row read `key_size: undetermined` while its embedded-key row read 2048; U-Boot's FIT names
  `"ecdsa256"`/`"ecdsa384"`/`"ecdsa521"` read `undetermined` where `"rsa2048"` read 2048. A
  `PUBLIC KEY` or `RSA PUBLIC KEY` block that `cryptography` parses now says "in a public key block
  that parsed as a key", carries the size (and curve) it parsed to and `key_material: "public
  key"`; the PKCS#1 private key's row takes its parsed size; `ecdsa256|384|521` as a whole token
  gives the size. In the scan JSON, the MCP tools and the CBOM (through the size). Found by
  re-running the probe; on the MCUboot tree no row was added or lost, 50 rows gained a size (6 key
  files, 2 public keys, 42 imgtool `ECDSA256P1`/`ECDSA384P1` lines, which are P-256 and P-384
  keys), and the findings list (family, raw value, classification, severity) and
  `algorithm_key_sizes` are the same, on MCUboot (37) and U-Boot (188); U-Boot's
  `lib/ecdsa/ecdsa-verify.c:178,184,190` now read 256/384/521. `findings_fingerprint` moves, since
  occurrence key sizes are part of it. **Changes a finding:** a committed PKCS#1 `RSA PRIVATE KEY`
  of 1024 bits, which read `RSA` (high, size undetermined), now reads `RSA-1024`, critical and
  weak, as the same key in PKCS#8 already did. **Not claimed:** a curve from
  `ecdsaNNN` (the size only); `ecdsa-with-SHA256`, `SHA256withECDSA` and `ecdsa512` give no size.
  A public key is not an embedded (committed secret) key and is not counted as one. MCUboot's
  Kconfig `range 2048 3072` is not read.
- **The CBOM carried the absolute path of the scanned folder** (row 487; own probe while
  regenerating `docs/examples/h5bp-server-configs-nginx.cbom.json`). `qrp:coverage:corpus:target`
  was the path on the machine that ran the scan, so two CBOMs of one commit from two places were
  never the same bytes though `qrp:findings_fingerprint:sha256` was, and the 0.46.0 sample held a
  local path. It is now the folder's own name, as `metadata.component` already was (row 430), with
  `qrp:coverage:corpus:target_basis` saying so. Tested: the same tree under two parent folders
  gives byte-identical CBOMs, and the parent path appears nowhere in the document. **Not
  changed:** the scan JSON and the MCP `scan_repo` result keep the absolute path
  (`coverage.corpus.target`; SARIF's SRCROOT and `compare_coverage` read it). The published
  sample is still the 0.46.0 file and is not regenerated here.
- **An Android Keystore key read with no curve, size or role** (row 484; probe `mobile-proba`).
  `KeyPairGenerator.getInstance(KEY_ALGORITHM_EC, "AndroidKeyStore")` initialised with
  `KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)` read EC, `key_size: undetermined`,
  `role: undetermined`. Where the file holds one builder (read up to its `build()`, within 20
  lines; the `getInstance` call may be split over lines, as in the developer documentation's
  examples), its `PURPOSE_*` now set the role, and an EC key's curve comes from
  `ECGenParameterSpec(...)` or `setKeySize(...)` in it; where the builder sets neither, P-256 with `curve_basis` saying it is the Keystore's default -- verified in AOSP
  (AndroidKeyStoreKeyPairGeneratorSpi.java, `EC_DEFAULT_KEY_SIZE = 256`), since the developer
  documentation gives no number. In the scan JSON, the MCP tools and the CBOM (`qrp:role`,
  the curve, and `qrp:curve_basis`). Found by re-running the probe. **Not claimed / not done:**
  where the key lives (StrongBox, TEE; with row 482); a file with two builders is not paired;
  a curve or size set from a variable, or a non-NIST curve, gives no curve and no default; an
  RSA key's size from its builder is not read.
- **The implementation and the parameter set were not always recorded** (row 488, Adam
  Firestone; probe `impl-proba`). Rust `use ml_kem::{MlKem768, ...}` read ML-KEM 768 with no
  `provider`; Go `mlkem.GenerateKey768()` read ML-KEM with no `parameter_set`. RustCrypto's
  `ml_kem::`, `ml_dsa::`, `slh_dsa::` paths now name `RustCrypto`, libcrux's `libcrux_ml_kem` and
  `libcrux_ml_dsa` (Rust paths and their C names) `libcrux`, and Go's crypto/mlkem names
  (GenerateKey, NewEncapsulationKey, NewDecapsulationKey, EncapsulationKey, DecapsulationKey with
  768 or 1024, read from the Go 1.26 source) give the parameter set -- which now also reaches the
  CBOM component and the CNSA 2.0 parameter-set clause. Found by re-running the probe. On
  openssh-portable 1,516 rows of the vendored libcrux code gained `provider: libcrux`, and on
  liboqs and OpenSSH no row lost a provider (before/after against 0.46.0 + earlier 0.47.0 rows). **Not claimed:** any validation; the
  crate path names the API, and a fork that keeps it reads the same. The Rust `pqcrypto::kem::`
  umbrella path is not read (the `pqcrypto_mlkem`-style crate names already were).
- **Where a KEM key is generated was not said** (row 494, Paarrthhh Birla, after Keyber, IACR
  ePrint 2026/2766; probe `keyber-proba`). A pqm4-style `provision.c` generating the device's
  ML-KEM-512 key once with `crypto_kem_keypair` (line 6) and decapsulating with `crypto_kem_dec`
  (line 9) read ML-KEM-512 `pqc_ready` from the comment and the Makefile, and gave neither call a
  row. A call into the NIST KEM and signature API (pqm4, PQClean, SUPERCOP: `crypto_kem_*`,
  `crypto_sign_*`, `crypto_sign`), liboqs (`OQS_KEM_*`, `OQS_SIG_*`, per-scheme forms) or
  mlkem-native's namespaced functions is now a row with `operation` (`keygen`, `encapsulate`,
  `decapsulate`, `sign`, `verify`), in the scan JSON, the MCP tools, SARIF and the CBOM
  (`qrp:operation`). Where the call does not name the scheme, the family is the only KEM (or
  signature) family the same file names, said in `family_named_at`, and the row is as strong as
  that line: a family the file names only in a comment stays not used (in the probe the keygen
  row is `evidence_kind: comment`; ML-KEM is a finding from the Makefile, as before). Found by
  re-running the probe; on liboqs `src/kem/ml_kem` 75 calls read, none of them a declaration;
  on the whole liboqs tree and openssh-portable the findings and verdict are the same as before. **Not claimed:** that the step survives a
  fault -- only a fault test shows that; a call in a file naming no scheme (the scheme only in the
  Makefile or directory) or two gets no row; generic test code calling `OQS_SIG_STFL_verify` is
  given the one family its file names. BoringSSL, Go, Python and Rust KEM calls are not read
  for an operation.
- **Verifying a signature read the same as signing one** (row 480, Paul Snow; probe
  `verify-proba`). `public_key.verify(...PSS...)` in `archive_verify.py` and `key.sign(...)` in
  `issue_record.py` gave the same row: RSA, signature, deprecated after 2030, "due". An RSA, EC,
  ECDSA, EdDSA or DSA line that calls exactly one of `.sign(`, `.verify(`, `.encrypt(`, `.decrypt(` on a key (also Go
  `rsa.VerifyPSS(` and Java `initVerify(` forms) now carries `operation`, in the scan JSON, the
  MCP tools, SARIF and the CBOM (`qrp:operation`). Under `--mandate nist-ir-8547` a verify-only or
  decrypt-only line gets `legacy_use` and is counted in `verify_or_decrypt_only`. Found by
  re-running the probe. **Not claimed / not changed:** that the signature or ciphertext is old --
  a line shows the call, not the age of what it processes; the row asked for "legacy use
  permitted" outside the gate, but IR 8547 final only defines legacy use (section 4.1, and the
  glossary) and Tables 2 and 4 give these schemes no such status, so the dates and the gate stand
  and a verify-only line still trips it; a decrypt-only line stays `hndl_exposed`. Arguments and
  settings (`verify=False`, `ssl_verify_client`) are not calls and give no operation; a call on a
  key whose family is not on the same line is not read.
- **The federal dates by role under `--mandate nist-ir-8547`** (row 493, Tuta; probe
  `ir8547-proba`). An RSA-3072 signature and a P-256 ECDH exchange read "deprecated after
  2030-12-31", which the final text says, but the dates section 4 of the same text restates from
  EO 14412 and OMB M-26-15 were missing: federal high value assets and high impact systems "must
  adopt post-quantum cryptography for key establishment by December 31, 2030, and for digital
  signatures by December 31, 2031". Each NIST IR 8547 clause now carries
  `federal_high_value_assets` (`pqc_by` by role, both dates in `pqc_by_role` where the role was
  not read; a composite clause none) and the block the two dates with `counted_by_gate: false`.
  Found by re-running the probe against the final text. **Not claimed / not changed:** the
  general deprecated-after-2030 / disallowed-after-2035 dates and the gate are unchanged; whether
  a scanned system is a federal high value asset is not known to the scan; OMB M-26-15 itself
  was not read, the dates are as IR 8547 states them; mandates are in the scan JSON (and SARIF),
  not in the MCP tools or the CBOM, as before.
- **Checked, not changed: the ECDH row beside X25519 on `ssl_ecdh_curve X25519MLKEM768`** (row 492;
  probe `dos-proba`). The line gives X25519, ML-KEM-768 and an ECDH row that comes from the
  directive's name. That is the rule as row 172a set it and the README states it: on a group
  setting, ECDH is dropped only when the values name no classical elliptic-curve group, and
  X25519 counts as one ("`secp384r1` and `X25519MLKEM768` keep it"). It is the same in
  `ssl_ecdh_curve X25519;`. Whether X25519 alone should still yield ECDH is left for a decision;
  narrowing it would remove ECDH from every X25519-only or X448-only group line and needs the
  corpus regression.
- **Per TLS listener, for nginx: which server block pays for what** (row 490, Bogomil Atanasov;
  probe `dos-proba`). Two `server` blocks -- 443 with `X25519MLKEM768` and an `mldsa65_srv.crt`,
  8443 with `X25519` and an `ecdsa_p256.crt` -- gave their algorithms for the whole tree, so the
  result could not say which port pays an ML-KEM encapsulation and an ML-DSA signature per
  handshake. `tls_listeners` now lists each nginx `server` block that listens with `ssl` or `quic`:
  ports, server names (masked below `--level full`), the groups set (each with its families and
  `post_quantum`) and the certificates (families from the line, or from the parsed leaf
  certificate -- public key and the signature on it -- when the written path, relative to the root
  or to the config's directory, is a file read; a file read with the same name only is listed as
  "same file name, not established"; ML-DSA with its parameter set). A port is given only where
  written. In the scan JSON, the MCP tools and the
  CBOM (`qrp:tls_listeners`). Found by re-running the probe. **Not claimed / not changed:** what a
  connection negotiates; `include` is not followed; a setting outside the block is reported as set
  outside it, not resolved through nginx inheritance; Apache, HAProxy and other terminators are not
  listed; findings and components are unchanged.
- **An algorithm read only from a certificate's file name is marked so, one confidence level
  lower** (row 491; probe `dos-proba`). `ssl_certificate /etc/nginx/certs/mldsa65_srv.crt;` gave
  ML-DSA at `medium`, the level of a directive that names the algorithm, although only the file's
  name says ML-DSA and the certificate is not in the tree. A row whose rule matches inside the path
  of a certificate or key file a TLS setting loads (nginx `ssl_certificate[_key]`, Apache
  `SSLCertificate[Key]File`, HAProxy `crt`), and nowhere else on the line, now carries
  `named_in_a_path: true` and is one step lower, with "family read from the name of a file the line
  loads, not from the file" in `confidence_basis`; the CBOM's `qrp:confidence` follows. Found by
  re-running the probe. The row's other half holds only as written: `key_size` and
  `algorithm_key_sizes` are empty for ML-DSA, but the parameter set was already taken from the
  name, in `parameter_set: "65"` and the CBOM component `ML-DSA-65`; no change there. **Not claimed / not changed:** the findings, families and components are the same;
  a parsed certificate is still `high`; a row another reader made on the same line (a cipher suite
  on a HAProxy `bind`) keeps its level.
- **A composite declared beside two KMS aliases is tied to the Terraform keys, where the files
  link them** (row 489, Peter Davis, ZeroVaultID; probe `kms-oid-proba`). A signer configuration
  with `algorithm_oid: 1.3.6.1.5.5.7.6.49` beside `alias/...` key names was found as a composite,
  but nothing said which keys it signs with. A composite `hybrid_names` entry in a file that writes
  KMS aliases now carries `kms_keys`: each alias resolved through a Terraform `aws_kms_alias`
  (`name`, `target_key_id`) to an `aws_kms_key` whose `customer_master_key_spec` is that half
  (`ML_DSA_87` for ML-DSA-87, `ECC_NIST_P384` for ECDSA P-384), declared in the alias's own
  directory (a Terraform module), with the places; an alias that does
  not resolve, or resolves to a key of another spec, is under `not_linked` with the reason. The CBOM
  combiner carries the same as `qrp:kms_keys`. Places only, never the alias text, so the field is
  the same at every `--level`. Found by re-running the probe: as written there the yaml names
  `alias/zv-*`, the code `alias/pq-*` and `alias/trad-*`, and the Terraform declares no alias, so
  0.47.0 says "not linked" for both aliases there. **Not claimed / not changed:** an alias name that
  contains "mldsa87" links nothing; aliases in another file than the composite, key IDs and key ARNs, `data`
  sources and other clouds are not read; two environments that declare the same alias name read
  "more than one aws_kms_alias with this name", not linked; the findings stay as they were (ECDSA is still counted as
  quantum-vulnerable), and `readiness_by_role.signature` still reads `hybrid_partial` for a linked
  composite, as a TLS hybrid group does. What a linked composite should read is left open: the
  label has no value for a complete hybrid, and changing it would change the TLS hybrids too.

Left open in this release: row 504 (U-Boot reads `hybrid_partial` for signatures with
`hybrid_names: []`, carried by ML-DSA in libavb and HSS/LMS in vendored Mbed TLS; whether code in
the tree that the build does not configure should count, or the label should say where the
post-quantum rows are, is a decision on what the label means, and the label is unchanged); row
492 (above, checked, not changed); rows 459 and 462 with the reasons given under 0.46.0; the ideas
485 (a weak random source feeding key material) and 496 (the limits in fields a narrow CBOM reader
does not skip).

## 0.46.0

**A TLS protocol component now says what it is linked to, in CycloneDX's own fields** (rows 475
and 465, first in this release because a CBOM consumer depends on it). A reader of the standard
fields saw `TLS 1.3` with nothing under it: the groups the same file configures
(`X25519MLKEM768`, `X25519`) were algorithm components of their own, linked to no protocol, and a
CBOM consumer that reads only the standard fields classed the key exchange as "unknown". The suites of an
`ssl_ciphers` line were split into RSA, ECDH and 3DES on the right line, but the suite itself never
reached `protocolProperties.cipherSuites` (found by running qrp-mcp over QCI's CBOM-Benchmark
2.6.6). Now a TLS version pin carries `protocolProperties.cryptoRefArray` (the bom-refs of the
groups its file sets) and `protocolProperties.cipherSuites` (each suite by its IANA name from
OpenSSL 3.6.5's openssl-ciphers table, with `algorithms` pointing at the families it names). The
suite name is carried from the detector, so it is the same at the default `masked` level. Every
output is validated against the CycloneDX 1.6 schema in the tests, and every ref is checked to
resolve. **Not claimed:** the link is by file, not by `server` block, and says what the file
configures, not what a connection negotiates. A protocol component with links has a new bom-ref
(a suffix from its links); one with nothing to link keeps the one it had. A version Apache enables
by `SSLProtocol all` is linked as a plain pin; Go's `tls.TLS_*` and Envoy's `[A|B]` are read as
the suites they name; OpenSSL selectors (`EECDH+AES`) are not expanded.

Each row below was reproduced as a failing test before the fix, tested through `scan --out`, the
MCP tools and the CBOM export where the row reaches them, and each fix was reverted once to see its
test fail.

- **Composite ML-DSA (RFC 10073) is read, and is one hybrid** (rows 477, 478):
  `{"1.3.6.1.5.5.7.6.45", "1.3.6.1.5.5.7.6.37"}` gave 0 findings while the verdict said every file
  was read, and `COMPSIG-MLDSA65-ECDSA-P256-SHA512` split into ML-DSA and ECDSA with
  `hybrid_names: []`. The 18 OIDs .37-.54, their names and labels are one table, taken from the RFC
  text and shared with the certificate parser; a composite by OID, name or label is one
  `hybrid_names` entry with both halves and their parameters, and in the CBOM one `combiner`
  component that signs and verifies, with its OID and `dependencies` to both halves. Readiness
  reads it as the TLS hybrids read (`hybrid_partial`). The NIST CSOR post-quantum OIDs (ML-DSA,
  SLH-DSA, ML-KEM; HashML-DSA .32-.34 and HashSLH-DSA .35-.46 included) written as numbers are read
  too, and a name such as `ML_DSA_65` beside such an OID no longer settles the line as an
  identifier. So are the classical OIDs of the same NIST arc, `2.16.840.1.101.3.4.3.3`-`.16` (DSA,
  ECDSA and RSA PKCS #1 v1.5 with SHA-2/SHA-3): on the corpus they add DSA and RSA rows to
  asn1crypto's OID table, which the first form reported as not known. Every OID added was checked
  against OpenSSL 3.6.5's `objects.txt`. An OID one component under
  `1.3.6.1.5.5.7.6` or `2.16.840.1.101.3.4.3` that this version does not know is listed in
  `oids_not_known` ("an OID this version does not know") and in the CBOM, not passed over.
  **Changed for `--mandate nist-ir-8547`:** the classical half of a composite on its line (the
  ECDSA of `id-MLDSA65-ECDSA-P256-SHA512`) now reads `composite_allowed`, as a TLS hybrid's
  classical half already did; in 0.45.0 it read `due`, as a classical signature alone.
- **de-bsi no longer recommends Classic McEliece** (row 481, wrong advice). BSI's "Notes on recent
  developments concerning Classic McEliece" (29 September 2026) says it "should currently no
  longer be used in new developments"; the profile offered it as a replacement for RSA and called a
  McEliece finding "recommended". The replacement now names ML-KEM and FrodoKEM in hybrid, and HQC
  once its standard is published; a McEliece finding says it is under review, hybrid in existing
  use only, until the next TR-02102-1; the note is cited beside TR-02102-1 2026-01. No other
  profile named Classic McEliece. Two expectations in `tests/test_de_bsi_2026.py` moved with the
  source: the key-establishment option no longer names McEliece, and the standing test checks the
  section it cites rather than the word "recommended".
- **Public-key encryption in a script is a row** (row 479): `gpg --encrypt --recipient`,
  `openssl smime -encrypt ... vault-rsa4096.crt`, `openssl pkeyutl -encrypt` and `age -r` gave 0
  findings, while `openssl dgst -sign` gave a pipeline row. Each is now a `ci_pipeline` row with
  `operation: public_key_encryption`, role `key_establishment` and `hndl_exposed: true`, "public-key
  encryption to a key not in these files" unless the recipient key or certificate is a file the
  scan read, whose families it then names. `openssl enc` with a passphrase stays silent. The CBOM
  counts these apart from signing commands, and a `--mandate` does not date them as signatures
  (nor counts them in its `hndl_exposed` total, which counts dated occurrences). **Not claimed:**
  `summary.pqc_readiness` and `readiness_by_role` are over algorithm families and do not read
  these rows, so a tree whose only cryptography is `gpg --encrypt` still reads `unknown` /
  `none_found` beside the row; and `gpg -r X` without `-e` is not read.
- **Two TLS layers that disagree are one open finding** (row 472): an nginx group setting with a
  post-quantum hybrid and an AWS load-balancer policy without one were two findings in two
  sections. `layer_disagreements` names both lines, says the weaker value applies until measured on
  the wire, and carries the load balancer's CODEOWNERS owner. No link is claimed: a shared port 443
  is not a basis, so the finding is made at repository level with "link not established". A layer
  in test code is not compared.
- **A line closed as not a use keeps its basis** (row 473): `named_but_not_used_lines` (and
  `qrp:named_but_not_used:lines`) gives file, line and the rule -- removal list, ban list, switch
  off, comment, identifier -- for every line of a family the inventory does not count.
  `named_but_not_used` is unchanged.
- **The self-seeded control names what it does not cover** (row 474): `not_covered_by_control`
  lists the file types that carry the tree's own findings and had no planted style, and the
  sentence says the figure does not cover them.
- **`compositions[].aggregate` is `incomplete` where a file was left out by its directory's name**
  (row 476). Checked first: a file the scan does not claim already gave `incomplete`, but the same
  file under `vendor/` gave `unknown`. This changes the word for most real repositories that hold
  a `vendor/`, `node_modules/` or `dist/` directory; `.git` does not count. No field was added, and
  the file list stays in `properties`.

Left open, with the reason unchanged from 0.45.0: row 462 (a QKD key source over ETSI GS QKD
014/004 needs a new evidence category with no family, a design decision) and row 459 (a DER key
written as a C byte array needs a multi-line assembler and a DER parse per array, whose cost on
C test-vector headers was not measured).

The findings fingerprint changes on a tree where these rows add a finding (an OID, a composite, an
encryption command); it does not change for the protocol links, which are CBOM structure.

## 0.45.0

**A post-quantum name is no longer read as post-quantum code** (row 463, the most important of
this release). QCI's CBOM-Benchmark 2.6.6 carries PQC-washing decoys: `class MlkemSession`,
`self.mlkem_key = ec.generate_private_key(ec.SECP256R1())`, `def kyber_exchange(...)` over
`exchange(ec.ECDH(), ...)`, a Java `KeyPair mlKemKeyPair` field. 0.44.0 reported ML-KEM and Kyber
there as calls at high, and the file alone read `pqc_readiness: hybrid_partial` with ML-KEM
`pqc_ready`, for code that does ECDH on P-256. Found by running qrp-mcp over that outside
benchmark (15.11.2026). Now, for the post-quantum families only, a match that is a piece of a
name the file itself defines (def, class, function, method, field, `let`/`const`/`var`, a
`self.`/`this.` assignment, a `NAME =` at the start of a line), outside any string literal, is
an `identifier` row where the family has no other use in that file. Such a family is
`identifier_only`: still listed, not counted in `pqc_readiness`, `by_role` or the mandates. A
post-quantum family read from names alone no longer carries `pqc_ready` or `pqc_pre_standard`:
its `classification` is `identifier_only` in the scan result, the MCP tools and the CBOM
(`qrp:classification`), with what it would be if used in `classification_if_used`, and its CBOM
component says `qrp:identifier_only: true`. A classical family read from names alone keeps its
class: a name may over-report a risk, never readiness. Where the file also uses the family for real
(a library call, a string naming the algorithm, a configuration value), every row keeps its kind:
on OpenSSH no post-quantum row changed kind. **Not claimed:** a washing name defined in one file
and only used in another still reads as a use there; and in a file that also names the family in
a string or an import, the washing names keep their kind (`call` at high), since the rule is
settled per family and file. The ML-KEM component itself stays in the CBOM, so a consumer that
counts components by name alone, without reading `qrp:classification`, still sees it.

Each row below was reproduced as a failing test before the fix, tested through `scan --out`, the
MCP tools and the CBOM export, and each fix was reverted once to see its test fail.

- **pyca `ec.SECP256K1()` carries its curve** (row 458): it gave EC with no curve and size
  undetermined, and no secp256k1 in the CBOM. A line naming two curves now names none (it had
  picked the NIST one).
- **ethers and eth_keys are secp256k1** (rows 460, 461): `Wallet.createRandom()` gave ECDSA with no
  curve; `eth_keys` gave nothing. `web3` alone is not given the curve (@solana/web3.js is Ed25519).
- **openssl.cnf `default_bits`, `default_md`, `MinProtocol`/`MaxProtocol`** (row 464): read and
  silent before; now RSA with its size ([req] only), the digest where it is one reported elsewhere,
  and the TLS bound as a configured protocol.
- **MD5 quoted alone** (row 466): `digest("MD5", ...)`, `AUDIT_DIGEST = "md5"` gave nothing while
  `TOKEN_DIGEST = "sha1"` gave SHA-1. The two agree now. Cost: a test-vector tuple
  `("MD5", "", ...)` and a dict key `"md5"` now read MD5 too, and on the corpus an icon theme's `name = "md5"` and test enums
  (`MD5 = "MD5"`) now read MD5, beside HTTP Digest authentication (guzzle, requests, httprb), which
  is MD5 in use.
- **A base64 certificate in a Kubernetes TLS Secret is decoded** (row 467), and so is any base64
  run of a PEM certificate in a text file.
- **`sshd_config` / `ssh_config` variants are claimed** (row 468): `sshd_config_pq` was
  `type_not_claimed`; OpenSSH's manual pages (`sshd_config.5`) still are.
- **An OpenSSH private key names its family** (row 469) from the openssh-key-v1 header, which a
  passphrase does not hide.
- **A default beside an environment read is a place** (row 440):
  `os.environ.get("HSM_SIGN_MECH", "RSA-PSS")` keeps the RSA finding and is now also in
  `chosen_outside_files` with `default`, `default_family`, `overridable: true`; the CBOM lists it in
  `qrp:chosen_outside_files:overridable_defaults`.
- **An identifier occurrence is tagged in the CBOM** (row 470): `[identifier]` in
  `additionalContext`, as `[comment]` already was.
- **Directories excluded before counting are named** (row 471):
  `files_excluded_before_counting.directories` lists each excluding directory from the root, its
  file count and its paths (up to 50, then `paths_not_listed`). The counts are unchanged.
- **CBOM: a named curve gives the key size its classical status is read from** (1c9b88a,
  unreleased since 0.44.0).

**What this changes for an existing pipeline.** Rows 458, 460, 461, 464 and 466-469 add rows or
families, so a tree with such lines gets a new `findings_fingerprint`, new entries against an
existing baseline (marked `new`), and can newly fail a `--mandate` gate (an RSA-1024 from
`default_bits`, an OpenSSH test key). Row 463 changes the washing family's classification to
`identifier_only`, which is part of `findings_fingerprint`, so a washing tree's fingerprint
changes too.

Also checked, no change needed: `--mandate nist-ir-8547` already follows the final text
(October 2026): RSA-3072 and P-384 get `deprecated_after: 2030-12-31` (row 168, since 0.39.0),
and `--lead-months 50` from 15.11.2026 fails on them.

Positive controls against 0.44.0:
OpenSSH 7fe3b24 coverage 84.88% and certbot 68.00%, the same files read (741, 850) and the same
findings (70, 39; 39 is also what the v0.44.0 tag gives on this checkout today, against the 40
in the 0.44.0 entry); OpenSSH gains 26 family rows from its OpenSSH-format test keys (row 469) and one
MD5 table entry; certbot is identical.

Corpus regression against 0.44.0 (185 repositories, labels of an independent model): the same in
every family of both splits except RSA in `obuchenie`, 30 -> 31 rows where the scanner reports and
the labeller does not, so the script exits 1. That one row is a correct finding the labeller
cannot see, and it is accepted as such: `WithTestData.groovy` in NCANode holds a real RSA-2048
certificate as base64, which row 467 now decodes and which a reader of the text does not see. It counts the classical families only, so rows 463 and 466 do not show in it.
It is disagreement with a model, never recall or precision.

Left open: rows 459 (a DER key as a C byte array), 462 (a QKD key source) and 465
(`cipherSuites` on TLS protocol components); see the release notes.

## 0.44.0

**`qrp-mcp build-gap SCAN.json BUILD_DIR`: a source scan against the build.** Of K
public-key-bearing packages (NuGet, from `*.deps.json`) or modules (Go, from `go version -m`) in a
build output, the source scan named J; the K - J list by name and version; the families in the
build and not in the source scan, and the reverse; and each Go binary's `DefaultGODEBUG` line,
with its cryptographic settings, as the toolchain recorded it. It reads only tables the
toolchain wrote: `*.deps.json`, the .NET metadata tables AssemblyRef, TypeRef and TypeDef
(names, by a reader of ECMA-335 Partition II in the package, no new dependency), `go version -m`
and `go tool nm`. It never reads method bodies, IL or machine code, builds no call graph, and
reads no key size, mode or curve from the build: a parameter appears only where the source scan
had it. A test fails if the module imports a disassembler or an IL reader. The figure is
**robustness on known patterns**, by the fixed name lists in the report, not recall and not
coverage of the build. [docs/build-gap.md](docs/build-gap.md).

Tested on: a real Go binary built at test time (Go 1.22, two local modules, `crypto/tls`); by
hand, a Go 1.26.9 binary with `golang.org/x/crypto` v0.56.0, where the build-only families came
out as the six of the measurement of 04.11.2026 (ML-KEM, X25519, SHA-1, MD5, DES, RC4). The
.NET metadata reader on real compiler output (one net8.0 assembly in the test where the file
exists, and two COM interop assemblies by hand) and on minimal assemblies written by the test; no crypto-bearing .NET publish was
built for this release (no .NET SDK on the build machine), so the .NET K and J are tested on
written fixtures only.

Each row below was reproduced as a failing test before the fix, and each fix was reverted once
to see its test fail.

- **A SHA-2 digest length in a signature's name is not an RSA key size** (row 434, Daniel
  Stokes). paramiko's `SIGNED_RSA_512` (the fixture of an `rsa-sha2-512` signature) gave
  `key_size: 512` on `tests/test_pkey.py:65` and `:202`, so the scan reported RSA-512, weak and
  broken in public, and the CBOM carried `parameterSetIdentifier: "512"`. In a name, a 256, 384
  or 512 after RSA is no longer read as a size when the name runs on before RSA
  (`SIGNED_RSA_512`) or the line names a SHA. Not changed: `bits=512`, `key_size=512`,
  `openssl ... rsa:512` and `genrsa ... 512` still give 512, and the name form still gives
  sizes that are not a digest length (`KEY_RSA_4096`). On paramiko 0e9ccb9 the only change is
  RSA-512 -> RSA; every other finding is the same.
- **A curve on the row is its size** (row 435). `ec.generate_private_key(ec.SECP256R1())` put
  `curve: P-256` on the row, and the finding still said "key size not read", with no EC in
  `algorithm_key_sizes`. A NIST P-256, P-384 or P-521 on the row now gives `key_size` to the
  row, the finding (`EC-256`, `weak_key: false`), the summary and the CBOM
  (`parameterSetIdentifier: "256"` beside `curve: "P-256"`). A tree with such rows gets a new
  `findings_fingerprint`; baseline entries are keyed on the line text and still match.
- **A signing mechanism read from the environment is chosen outside the files** (row 436).
  `hsm.sign(batch, mechanism=os.environ["HSM_SIGN_MECH"])` gave no row and the scan read as 0
  findings. A sign, verify, encrypt, decrypt, derive, wrap or key-generation call whose
  `mechanism`, `algorithm` or `cipher` argument is read from the environment is now a place in
  `chosen_outside_files`, with no family claimed. `mechanism=` outside such a call (a SASL or
  login mechanism) is not.

Positive controls, against 0.43.0 (OpenSSH 7fe3b24, certbot 56ee049, Vault 41e571b): the same
files read (741, 850, 5,434), the same findings (70, 40, 74), the same families and the same
`chosen_outside_files` counts. The only rows that moved are EC, ECDSA and ECDH rows that named a
curve and now carry its size (199, 22, 487); no RSA row's size changed in the three.
Not claimed: any change to how much of a tree's own cryptography is found.

Corpus regression against 0.43.0 (185 repositories, labels of an independent model): the same
disagreement in both splits and every family (395/261 and 71/42), exit 0. It counts families,
so the key-size and curve changes above do not show in it. It is disagreement with a model,
never recall or precision.

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
