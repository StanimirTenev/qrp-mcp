# The CBOM it emits

[Back to the README](../README.md) · [CHANGELOG](../CHANGELOG.md)

## The CBOM it emits

`export_cbom` produces a CycloneDX 1.6 document, validated against the published schema; from
0.20.0 `qrp-mcp cbom PATH --out FILE` writes the same document to a file. Three things travel in
it that a component list alone cannot say:

- `compositions.aggregate` — `incomplete` where files were not examined, and `unknown` where
  the tool cannot account for its own reading. Reading every file is *not* enough for
  `complete`: that word claims every asset present was found, which is the second axis, and
  only a held control licenses it. The document used to say `complete` on the strength of the
  denominator alone; comparing against other scanners showed findings missed inside files that
  had been read.
- `properties` — the whole coverage block. It travels there because the root object is
  `additionalProperties: false` and the format has no field for it; the awkwardness is the point
  rather than something to hide.
- `evidence.occurrences` — file, line and matched text for every asset.

A policy or an IKE configuration is a `protocol` component whose `qrp:` properties carry what it
says — `qrp:security_policy` and `qrp:policy_status` (OPC UA, protocol type `other`, which is
CycloneDX's word for a protocol it has no name for), `qrp:policy`, `qrp:allows_versions`,
`qrp:post_quantum` and `qrp:default_applied` (AWS), `qrp:product`, `qrp:fragmentation` and
`qrp:fragmentation_default` (IKE) — because the matched text is masked by default and cannot carry
them.

From 0.39.0 an RSA, DSA, DH or EC component carries `qrp:key_size` (never left out:
`undetermined` where no size was read) and `qrp:classical_status` with
`qrp:classical_status_source`; RSA and EC components carry `qrp:role`, one per occurrence;
ML-KEM components `qrp:negotiation`, one per occurrence; and a family compiled only under a build
switch nothing in the tree defines, `qrp:not_enabled` (see *From 0.39.0*).

Where the scan named the module, an algorithm component carries `qrp:providers` (a JSON array)
and `qrp:provider_validation`, which says that validation is not claimed and has to be checked
against the CMVP list for the deployed version. `certificationLevel` is never written: it states
a validation, and nothing in a file establishes one. From 0.32.0 the same component carries
`qrp:provider_pins` (a JSON object, provider → "version (manifest:line)") where a manifest pins
the provider's package, and `qrp:provider_configuration` where an `openssl.cnf` in the tree
activates the FIPS provider for a component whose provider is OpenSSL 3. A DNS size-budget asset
carries `qrp:udp_setting`, `qrp:udp_size` and, for BIND's default, `qrp:default_applied`; a weak
EC key is a `related-crypto-material` component with `qrp:curve`, `qrp:scalar` and `qrp:bound`.

Output is deterministic where it matters. The serial number is derived from the two pins and a
digest of what was found, so the same code over the same corpus that finds the same things gets
the same serial, and a different result gets a different one. From 0.43.0 the target path is not
part of it, and `metadata.component` is named by the directory's own name with the commit as its
`version`: one commit scanned at two places, or on two machines, is one document. Each evidence
file carries `qrp:sha256_crlf_as_lf` beside its raw hash, the same for a CRLF and an LF checkout. The whole CBOM is
byte-identical across two runs over one unchanged tree: the timestamp is the tree's commit time
(or `SOURCE_DATE_EPOCH`, or absent when neither exists), and the read window stays in the scan
result's `coverage.window`, named in the CBOM rather than carried.

## What kind of place a finding sits in

Two things about a match are not the match itself, and both now travel with it — in the
scan result and in the exported CBOM.

**Evidence kind.** `scan_repo` grades every match: `call`, `declaration`, `import`,
`reference`, `ban`, `comment`, and `default` -- a value the provider applies because the file
wrote none (an AWS listener with no `ssl_policy`), counted as in use, never as a comment or a
ban. Comment evidence is kept out of the inventory: a sentence that names an algorithm is
not a use of it. (An earlier version of this paragraph gave precision figures here with the
two tools swapped; the measured figures are under "Measured on a corpus this project did not
write" below.) The exported document
used to drop that grade, so a sentence about certificates reached an auditor looking
exactly like a signature: **78 of 465 occurrences on certbot (17%) and 1174 of 7142 on
OpenSSH (16%)**, including 493 ML-DSA and 429 ML-KEM mentions in OpenSSH, which is a lot
of prose to present as post-quantum adoption. An occurrence whose evidence is a comment
now says `[comment]`.

⚠️ A banned algorithm is not marked, it is **absent**: `!RC4` in a cipher list never
becomes a component. What the line forbids is not inventory; what it enables is.

**Test code.** A finding says whether it sits in test code, and the scan declares the
rule it used:

```json
"test_code": {
  "rule": "a path component named test/tests/testing/spec/specs/fixtures/testdata, or a file named test_*, conftest, *_test, *.test.*, *Test, *Tests, *_spec, *.spec",
  "meaning": "whether the finding sits in test code; named, not excluded",
  "findings_in_test_code": 144,
  "findings_in_other_code": 301
}
```

Components whose every sighting is test code also carry the **standard** field —
`component.scope: "excluded"`, which the schema has defined since 1.6 as documenting
"component usage for test and other non-runtime purposes". ⚠️ v0.18.0 shipped the per-occurrence
marker and no scope at all, which was a private spelling of a field the standard already had.

⚠️ And the honest measurement of that field: on certbot, **not one of the 31 components is
confined to test code** — every family that appears in a fixture also runs in production. At
component granularity `excluded` almost never fires on a real repository, which is exactly why
the per-occurrence marker is not redundant: `scope` is a property of the component, `[test]` is
a property of one sighting, and 144 of 445 findings need the second.

Those are certbot's real numbers: **almost a third of its findings are in fixtures.**
Nothing is dropped — a fixture's RSA key is real RSA. Whether it belongs in a particular
migration plan is the reader's call, and they can only make it if the document says which
is which. Occurrences in test code carry `[test]`, and a comment inside a fixture carries
both.

⚠️ **There is no external convention for this, which is why it is declared rather than
decided.** The two public corpora that could settle it — qscan's recall benchmark and the
cryben corpus of Näther & Hirsch — are 100% synthetic fixtures with no test/production
distinction. The rule here is a path convention, not a fact, so it is printed with the
numbers it produced; a reader who disagrees with the rule can see exactly what it caught.

## How sure the scan is of each occurrence

Every occurrence carries `confidence` — `high`, `medium` or `low` — and `confidence_basis`, the
reason in words. It is derived from what the scan read, not from a score it makes up:

- **What the line is.** A call, a parsed certificate or key, the value of a setting the scan
  parsed (a cipher list, a TLS group, a protocol version): `high`. A declaration or reference in
  source code, a protocol version named by a constant: `medium`. An import, a type in a Go
  function signature, a declared package: `low` — the line names the algorithm and does not use it.
- **Whether the family was read whole or inferred.** A family read from a piece of an identifier
  (`EC_KEY_free`), from an object identifier in a file that was not decoded, through a properties
  file, or through an alias, a constant in another file or literals concatenated on the line is
  one step lower. The fallback of a `getProperty` lookup, read because no properties file in the
  tree sets the key, is `low` whatever the line.
- Comments and bans are `low` and are not uses anywhere. The role is **not** an input. A row
  with a role is one that carries the `role` field (`signature`, `key_establishment` or
  `undetermined`). On Cryben, comments and bans left out, rows with one were 27/31 on a truth line
  and rows without one 42/45 (39/43 in release E), so it separated nothing. Counting only a known
  role (`signature`, `key_establishment`) gives 13/13 against 56/63: 13 rows, too few to build on.

It travels in the scan JSON, in SARIF (`rank` 90 / 60 / 30 and `properties.confidence`; `level`
stays the severity) and in the CBOM: CycloneDX 1.6 gives an occurrence no properties, so each
component carries `qrp:confidence`, a JSON array with one level per occurrence in the order of
`evidence.occurrences`. The coverage block counts the occurrences per level and carries the
measured precision of each level, so the figure travels with the document it describes.

**Precision by confidence level, measured on Cryben and the OWASP Benchmark 1.2, 25.10.2026**
(release E; comments and bans left out). The low row was re-measured on 26.10.2026 on 0.37.0's
detection; the high and medium rows did not move:

| level | Cryben (authors' truth, a row on a truth file:line) | OWASP Benchmark crypto + hash, with `benchmark.properties` | pooled |
|---|---:|---:|---:|
| high | 60/60 | 348/348 | **1.000** (408 rows) |
| medium | 2/3 | 73/73 | **0.987** (76) |
| low | 7/13 | — | **0.538** (13) |

On OWASP a row is graded when its family is one of the Benchmark's weak families for the case's
category: right when the case is true. On the OWASP subset **without** `benchmark.properties`
(the 2026-10-25 06-propusnato layout) the 27 `getProperty` fallbacks to `AES/ECB` are all wrong
— the property file sets AES/CCM — which is why a fallback is `low` (it was `medium` in release
E as first measured; the table above has no fallback row and did not move when it changed).

⚠️ What the table is not. Both corpora were used to choose the mapping, so it is a regression
figure, not a blind one. The medium and low buckets on Cryben are small (3 and 13 rows), OWASP is
Java only and separates nothing (every graded row there is right), and Cryben's truth does not
label Go signature lines, which decides part of `low`. 3 of the 7 right low rows are identifier
rows, which round 3 added, and a row is right when it sits on a truth line, whatever its family:
two of the three, `ec.dsa_sign_asn1` and `ec.dsa_verify_asn1` in `cinv-ruby-0014.rb`, say DSA
where Ruby's method on an EC key is ECDSA. Three other tools in this class print a confidence,
and none publishes its precision. Scored the same way on Cryben (05-novi-merki, 25.10.2026): CryptoScan 1.5.0 `HIGH` 0/10, `MEDIUM` 69/122, `LOW` 2/27; qScan 0.12.0 `high`
30/33, `medium` 11/11 (inverted); PostShor 0.1.0 one bucket, 27/40.
