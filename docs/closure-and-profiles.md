# Closure, replacements and profiles

[Back to the README](../README.md) · [CHANGELOG](../CHANGELOG.md)

## Whether a fix closed it

A finding missing from the second scan has not necessarily been fixed. It may have moved down
the file, moved to another file, landed in a directory the second run could not open, or
stopped matching because the scanner changed. Each of those looks exactly like a fix when the
only question is "is it still in the list".

`prove_closure(before, after)` takes two saved results (`qrp-mcp scan PATH --out FILE`) and
answers in two steps:

1. **Can these two runs be compared for closure?** Same instrument commit, version, rules, file
   types and exclusions; both trees pinned to a commit and clean; both results quoting lines at
   the same level. Run from an installed release (`uvx qrp-mcp`, `pip install`) there is no
   commit to name; two runs of the **same installed release** are accepted on its version, and
   the result says so in `basis` — weaker than a commit, since a locally modified install would
   carry the same version string. The trees may differ — that is what is measured. If the runs cannot be
   compared, **nothing is reported as closed**, the reasons are listed, and the repair is named:
   scan the first commit again with the instrument that did the second.
2. **Only then, occurrence by occurrence, without line numbers:** `closed`, still open (and how
   many only moved lines), `relocated` to another path (a rename is not a fix), `changed` (gone
   from a file in which the second run finds the same family again: not closed), moved into or
   out of test code (neither is a fix), `new`, `unverifiable` — in a file the second run did
   not read — and `removed`: the whole file is gone from the second tree. A deleted file does
   remove its code, but it is also the cheapest way to make a finding disappear, so it is named
   apart and **not counted as closed**. A file the second run could not open is never counted
   as fixed. An occurrence's `provider` is shown but is not part of its identity: it can come
   from the file's import line, and editing that line does not close the calls below it.

From 0.20.0 every scan lists `files_read` by name, beside the counts. That is what tells a fixed
line from a deleted file; it stays out of the CBOM. Two results without it (0.19.0) are reported
as `unestablished`, not compared on a weaker rule.

Checked on a copy of certbot (521 occurrences): removing one RSA call closed exactly that one;
inserting blank lines closed none and reported two moved; renaming a file closed none and
reported two relocated; a masked scan against a full one was refused. Two scans of OpenSSH
with the same instrument: 7,143 still open, 0 closed. A second run with an emitter that had
uncommitted changes was refused as `instrument_dirty`. With 0.20.0 installed in a clean
environment, deleting one RSA line in `client.py` and the whole of `challenges.py` gave
`1 closed, 1 removed`, each on the right file and line.

⚠️ What is not claimed: that the fix is correct, only that the occurrence is gone from every
file the second run read. Other scanners close findings between scans too — Semgrep, SonarQube,
GitHub code scanning, and Keyfactor AgileSec ("Deleted findings are automatically resolved",
3.4 release notes). Semgrep marks a finding "Removed" rather than "Fixed" when its rule changed
or its path went away, and GitHub records the tool version to track changes it caused; both do
this as a status after the fact. What was not found in the sources read is a **refusal, before**
calling anything fixed, when the reader changed between the two scans. SonarQube documents that
a file dropped from scope is counted as fixed. They keep a history across many scans; this
compares two documents. A statement about the sources read on 2026-09-27, not a survey of
every tool.

## What to replace it with

Each finding that is quantum-vulnerable or deprecated carries a `replacement`: what to use,
for which role, and the standard that says so, with its address. It is a suggestion; nothing is
applied, nothing leaves the machine, no model is asked.

| Found | Suggested | Source |
| --- | --- | --- |
| ECDH, X25519, X448, DH | ML-KEM | FIPS 203 (final, 13 Aug 2024) |
| ECDSA, EdDSA, Ed25519, Ed448, DSA | ML-DSA or SLH-DSA; LMS/XMSS for firmware signing | FIPS 204, FIPS 205, SP 800-208 |
| RSA, EC | by the role read from each line (below); both where a line does not show it | as above |
| RSA below 2048 bits | two steps: ≥ 2048 now, post-quantum next | SP 800-131A Rev. 2 |
| BLS, Schnorr | **no approved drop-in replacement** — the aggregation property has none; a redesign | FIPS 204/205 as the nearest |
| MD5, SHA-1 | SHA-256 or SHA3-256 | RFC 6151, SP 800-131A Rev. 2 |
| RC4, DES, 3DES | AES (AES-GCM for RC4's place) | RFC 7465, FIPS 46-3 (withdrawn), SP 800-131A Rev. 2 |
| a post-quantum scheme that is not a NIST standard | a standardised one | FIPS 203/204/205 |

Transition dates come from the final NIST IR 8547 (October 2026): every quantum-vulnerable
signature and key-establishment scheme deprecated after 2030 and disallowed after 2035, whatever
its strength. Until 0.38.0 they came from the November 2024 draft, which spared the 128-bit rows
(RSA-3072, P-256, Ed25519) the 2030 date. Hybrids are named as NIST names them — accommodated, and
temporary. The CBOM is not changed: CycloneDX has no standard field for a recommendation, and
this project does not add a private one.

### Whose rules: national profiles

The table above is NIST's. Other authorities disagree with it and with each other, so from
0.22.0 `--profile` (`qrp-mcp scan`) and `profile` (the `scan_repo` tool) choose whose words fill
the options. The CBOM carries no replacement, so it has no profile. Detection is byte-for-byte the same under every
profile; only `replacement` changes, and the result names the profile in `replacement_profile`.

| profile | authority · document | key establishment | signatures | hybrid |
| --- | --- | --- | --- | --- |
| `nist` (default) | NIST · FIPS 203/204/205 | ML-KEM | ML-DSA, SLH-DSA; LMS/XMSS for firmware | accommodated, temporary |
| `us-cnsa2` | NSA · CNSA 2.0 FAQ v2.1 (Dec 2024), CNSSP 15 | ML-KEM-1024 only | ML-DSA-87 only; SLH-DSA not approved; LMS/XMSS single-tree | not required |
| `uk-ncsc` | NCSC · Next steps v2.0 (Aug 2024) | ML-KEM-768 recommended | ML-DSA-65 recommended | allowed, at a cost |
| `au-ism` | ASD · ISM (Sep 2026) | ML-KEM-1024; 768 not beyond 2030 | ML-DSA-87; 65 not beyond 2030; no hash-based | not recommended, not prohibited |
| `ca-cccs` | CCCS · ITSP.40.111 v5 (May 2026) | ML-KEM-512/768/1024 | ML-DSA-44/65/87, SLH-DSA; LMS/HSS/XMSS/XMSS^MT | not addressed |
| `de-bsi` | BSI · TR-02102-1 (2026-01) | ML-KEM-768/1024, **hybrid** | ML-DSA-65/87 hedged, **hybrid**; hash-based alone | lattice schemes recommended only in hybrid form |
| `fr-anssi` | ANSSI · PG-083 v3.00 (Mar 2026) | ML-KEM-768 (512 conformant), **hybrid** | ML-DSA **hybrid** only; SLH-DSA alone | required for ML-KEM, ML-DSA |
| `nl-ncsc` | AIVD/CWI/TNO · PQC Migration Handbook, 2nd ed. (Dec 2024) | ML-KEM-1024/768 | ML-DSA-87/65 | recommended |
| `eu-eccg` | ECCG · Agreed Cryptographic Mechanisms v2.0 (Apr 2025) | ML-KEM-1024/768, combined | ML-DSA-87/65 combined; hash-based alone | lattice not standalone |
| `bg` | — · no Bulgarian guidance found | NIST's | NIST's | EU roadmap: end-2026 / 2030 / 2035 |

⚠️ **What a profile is not.** Each is one document read on 2026-09-27, and each says whom that
document addresses — CNSA 2.0 is written for US National Security Systems, the ECCG list for EU
product certification, the NCSC paper for OFFICIAL-tier and enterprise data. Choosing one does
not make it law for the reader, and the tool makes no legal finding. For the weak algorithms
(MD5, SHA-1, RC4, DES, 3DES) and for the first step of an RSA key under 2048 bits, an
authority's own minimum replaces NIST's row where it has been checked against the text:

| profile | weak hash → | weak cipher → | RSA under 2048, now → |
| --- | --- | --- | --- |
| `us-cnsa2` | SHA-384 or SHA-512 | AES-256 | (CNSA 2.0 admits no RSA; NIST's step) |
| `de-bsi` | SHA-256/384/512, SHA-512/256, SHA3 (Table 4.1) | NIST's | at least 3000 bits |
| `fr-anssi` | ≥ 256-bit output; ≥ 384 for post-quantum security | AES-128; AES-192/256 for post-quantum security | 2048 until 2030, 3072 from 2031 (3072 recommended now) |
| `au-ism` | SHA-384 or SHA-512 (224/256 not beyond 2030) | AES-128/192/256, preferably 256 | at least 2048, preferably 3072; RSA not beyond 2030 |
| `ca-cccs` | NIST's | NIST's | at least 2048, at least 3072 by the end of 2030 |

Where a cell says NIST's, the result says so in `follows` or `first_step_follows`. A role an authority does not fill is left out
rather than filled with NIST's answer: the ISM names no hash-based signature, so `au-ism` offers
none. Documents change — the ISM quarterly, TR-02102-1 yearly — and each profile carries its
version and address so a stale one can be recognised.

### The role of an RSA or EC line

From 0.21.0 every RSA and EC occurrence carries a `role`, read from its own line: `signature`
(`RS256`, `rsa-sha2-256`, `SignPSS`, `sha256WithRSAEncryption`, `ECDHE-RSA-…` in a cipher list),
`key_establishment` (OAEP, `EncryptPKCS1v15`, `TLS_RSA_WITH_…`, a `kex` table) or
`undetermined`. A key generated or declared on a line is used somewhere else, and this reads one
line, so such a line stays `undetermined`; so does a line with signals for both, and a cipher list
longer than the 200-character excerpt. The finding's `replacement` counts the roles of its lines
of code (comments carry a role but are not counted) in `roles_seen`, and drops a path only when
no line showed that role **and** no line was undetermined. Every path says how many lines it is for.
From 0.39.0 the role is in the CBOM too, as `qrp:role` on RSA and EC components, one value per
occurrence; before, it stopped at the scan JSON.

⚠️ **Against this:** on every corpus measured, both paths stayed. Undetermined lines of code:
certbot 208 of 229, OpenSSH 172 of 456, Vault 361 of 656, OpenSSL 3,354 of 3,893. The count is
the gain, not a shorter list.

**Role-assignment precision on a sample** (not detection; judged from the source ±5 lines, not
from the excerpt the rule saw; rules frozen at `3287c1c` before these corpora were opened; seed
20260927):

| corpus | `signature` correct | `key_establishment` correct | `undetermined` with the role visible nearby |
| --- | --- | --- | --- |
| Vault `41e571b` | 30 / 30 | 17 / 20 | 5 / 20 |
| OpenSSL `223e04f` | 25 / 30 (5 should have been undetermined) | 14 / 20 | 4 / 20 |
| Bitcoin Core `33a363e` | none to sample | none to sample | 0 / 8 |

The nine wrong `key_establishment` lines had two causes, both in TLS names: `TLS_ECDHE_RSA_WITH_…`
written with underscores was read as ECDH, and in `ECDH_RSA` suites RSA only signs the certificate
of a fixed ECDH key. **Fixed in 0.23.0**, together with lines that name PSS beside the generic RSA
key type (a table of both uses, now `undetermined`); on Vault and OpenSSL 13 of the 14 are now
right. Measured again on two corpora these rules had not seen (rules frozen at `8ab8e9c`, seed
20260928, same method):

| corpus | TLS-name lines | `key_establishment` | `signature` | `undetermined` with the role visible nearby |
| --- | --- | --- | --- | --- |
| curl `b3640b0` | 17 / 17 | 20 / 20 | 30 / 30 | 13 / 20 |
| Mbed TLS `c0748be` | 20 / 20 | 8 / 8 | 30 / 30 | 17 / 20 |

No wrong role in 125 assigned. ⚠️ The samples are concentrated in tables of cipher suites (47 of
70 curl lines from one test file), which is the easiest case for a rule that reads one line. And the
misses are systematic: `TLS_RSA_PSK_WITH_…` (RSA transports the key) and TLS groups for EC
(`groups=secp256r1`) are left `undetermined` although the role is plain.

**0.24.0** reads both: RSA-PSK as key establishment, and a TLS group as key establishment in its
TLS spellings only (`groups=`, `set1_groups_list`, `+GROUP-`, `selected_group`, `IANA_TLS_GROUP_`) —
`EC_GROUP_new` and `ecp_group` are the curve's mathematical group and say nothing about the role.
Measured on two more corpora these rules had not seen (frozen at `b2eb73b`, seed 20260929):

| corpus | psk/group lines assigned | `key_establishment` | `signature` | `undetermined` with the role visible |
| --- | --- | --- | --- | --- |
| wolfSSL `3c5eead` | 1 / 1 | 15 / 20 (5 should have been undetermined) | 30 / 30 | 4 / 20 |
| s2n-tls `e691294` | 3 / 3 | 20 / 20 | 30 / 30 | 5 / 20 |

Still no wrong role. ⚠️ **But the group fix reached little:** 4 of 40 psk/group lines. s2n-tls names
its groups `Group::secp384r1`, `"group.supported.secp256r1"`, `kem_group`; wolfSSL `ctx->group[0]` —
the rule was written from Mbed TLS's spellings, and 15 of 17 s2n-tls group lines stay undetermined.
And in C `RSA_public_decrypt` verifies a signature; a switch that handles it together with
`RSA_PUBLIC_ENCRYPT` was called key establishment (the five above).

**0.25.0** reads the raw RSA signature operations of C (`RSA_public_decrypt`, `RSA_private_encrypt`)
as signature (a role is only put on a finding, and until 0.27.0 those two lines were found only when
something else on the line named RSA), and the other group spellings (`Group::`, `NamedGroup`, `kx_group`, `kem_group`,
`group.supported`, `supported_groups`, `negotiated_curve`). Measured on BoringSSL and rustls, which
these rules had not seen (frozen at `b8bd5ce`, seed 20260930):

| corpus | crypt/group lines assigned | `key_establishment` | `signature` | `undetermined` with the role visible |
| --- | --- | --- | --- | --- |
| rustls `99f2358` | 18 / 18 | 20 / 20 | 30 / 30 | 2 / 20 |
| BoringSSL `5112448` | **1 / 3** | **14 / 20** | 30 / 30 | 2 / 20 |

🔴 **Seven wrong roles in BoringSSL, one cause, and it was in 0.24.0 as released:** the rule for
`group(` — written for Mbed TLS's `psk_ephemeral group(secp256r1)` — also took BoringSSL's C++
accessor `group()`, which returns the curve's mathematical group, as a TLS group
(`EC_POINT_mul(group(), …)` → key establishment). 0.25.0 accepts `group(` only with a curve or group
name inside. That narrows the rule and cannot add a role: on BoringSSL exactly 95 lines change, all
from key establishment to undetermined, all `group()`. The seven are among them. The fix itself was
not measured on a corpus it had not seen.
