# Gate, mandates and suppression markers

[Back to the README](../README.md) · [CHANGELOG](../CHANGELOG.md)

This page gathers what the [CHANGELOG](../CHANGELOG.md) says about the gate and the markers, in
one place. The CHANGELOG entry named beside each item is the full text.

## Mandates and the gate

- `--mandate NAME` gives each quantum-vulnerable occurrence its dated clause and
  `hndl_exposed`. With `--lead-months N` the run exits 1 when a deadline falls inside the lead
  time (0.37.0).
- From 0.48.0 NAME is also one of ten other documents, each read from the authority's own text;
  the sentences each date comes from are quoted in the comments of `profiles.DATED_MANDATES`:

  | NAME | document | the date the gate counts | said, not counted |
  |---|---|---|---|
  | `eu-pqc-roadmap` | NIS Cooperation Group roadmap v1.1 (11.06.2025) | 2035-12-31, not stand-alone (medium risk) | 2030 for high-risk use cases; software and firmware upgrades quantum-safe by default |
  | `uk-ncsc` | NCSC timelines v1.0 (20 March 2025) | 2035-12-31, all systems | 2031 highest-priority migrations; 2028 discovery and plan (milestone) |
  | `ca-cccs` | ITSP.40.111 v5 (29 May 2026); ITSM.40.001 (23 June 2025) | by algorithm: 2035-12-31 without a post-quantum scheme; 2030-12-31 for DSA, P-224 and RSA/FFC below 3072 bits | 2031 high priority systems of GC departments; X25519 and X448 are not among its curves (`not_in_document`, no date) |
  | `au-ism` | ASD ISM, September 2026 | 2030-12-31 for DH, ECDH, ECDSA, RSA, and for ML-KEM-768 and ML-DSA-65 | EdDSA and DSA are not approved at all (`not_in_document`, no date) |
  | `nl-rqs` | Rijksbrede Quantumstrategie (5 oktober 2026), central government | 2035-12-31 | 2030 high risk; 2030 software and firmware quantum-safe by default |
  | `se-ncsc` | NCSC Sweden national recommendations (27 maj 2026) | 2035-12-31 | 2030 for information sensitive more than ten years ahead |
  | `jp-gov` | Cabinet Secretariat interim report (November 2025), government bodies | 2035-12-31 ("in principle") | roadmap in FY2026 (milestone) |
  | `sg-csa-cii` | CSA Quantum-Safe Handbook V1 (16 Jul 2026), CII owners only | 2031-12-31 | plan by 31 Mar 2027; new CII systems quantum-safe ready from 1 Jan 2028 (milestones) |
  | `in-dst` | DST / National Quantum Mission Task Force report (May 2026), a recommendation | 2033-12-31 (enterprises) | 2029 for CII; 2030 high-priority systems |
  | `de-bsi` | BSI TR-02102-1 2026-01; Leitlinie zur Umstellung auf PQC (11 September 2026) | by role: 2031-12-31 key agreement alone, 2035-12-31 classical signatures | 2030 very high protection (key agreement) and high-risk use cases; inventory by end of 2026 (milestone) |

  A date for a class of system the scan cannot see (high-risk, highest priority, CII) is in the
  clause's `earlier_if` and the block's `conditional`, with `counted_by_gate: false`, as the
  federal dates of `nist-ir-8547` are. Organisational dates (a plan, an inventory) are in the
  block's `milestones`. Where the document's date is for the classical scheme used alone, the
  classical half of a hybrid on the same line is `composite_allowed` with no date; where the
  document does not say, `composite_not_addressed`, with no date either. Where a line shows no
  role and the document dates the roles differently (`de-bsi`), both dates are given and the
  earlier is the deadline, with a `note`. "By 2030" is read as the end of 2030. None of these is
  law for everyone who picks it: each block says whom the document addresses (`addresses`).
- From 0.48.0 every mandate block says how old its reading of the document is: `read_on_age_days`
  counted to `as_of`, `stale_after_days` (180) and `stale`. Past 180 days the block carries
  `stale_because` with the document's URL, and the command line says it on stderr. It does not
  change the gate or the exit code. It is counted to `--as-of`, not to the clock, so a run with the
  same `--as-of` gives the same bytes.
- From 0.49.0 (row 523) `--mandate il-boi | ch-finma | hk-hkma | sg-mas` names a sector's duty with
  no date for code: Bank of Israel letter 202501 (an initial plan within a year of the letter),
  FINMA Guidance 05/2026 (a PQC roadmap by mid-2027), HKMA circular B1/15C (full sectoral
  readiness by 2030) and MAS consultation paper P019-2026 (proposed migration dates; a
  consultation, `in_force: false`). The block has `kind: "sector_duty"`, the `sector`, each duty
  quoted (`duties[].quote`), `read_on` and `stale` like every mandate, `in_scope: 0` and `gate:
  "not_applicable"`: no occurrence gets a clause and the gate never counts it. A span the document
  gives ("within a year", "mid-2027") is said as written, not turned into a day. HKMA's `url` is
  null: the circular's own address was not recorded when it was read.
- From 0.49.0 (row 524) a mandate whose document address and hash were both recorded when it was
  read carries `documents` (url, sha256 as downloaded, read_on): eu-pqc-roadmap, ca-cccs, nl-rqs,
  se-ncsc, jp-gov, in-dst, de-bsi, il-boi, sg-mas. A scan says `document_changed: "not_fetched"`;
  it makes no network call. `qrp-mcp mandate-check NAME --document FILE ...` compares copies you
  downloaded (without `--document` it lists the documents with a `curl` for each) and says
  `document_changed` true, false or not_fetched; exit 1 when one changed. A changed hash says the
  bytes changed, not that a deadline moved. Only PDFs are recorded: an HTML page changes its
  bytes without a change to its text.
- `--mandate nist-ir-8547` follows the final NIST IR 8547; the gate counts the deprecation date
  (2030), named in `gate_counts` and `next_gate_deadline` beside `next_deadline` (0.38.0, 0.41.0).
- `--mandate nist-ir-8547` also says, in `federal_high_value_assets` on each clause and on the
  block, the federal dates by role from section 4 of the final text (EO 14412, OMB M-26-15 as
  IR 8547 states them): key establishment by 2030-12-31, digital signatures by 2031-12-31, for
  federal high value assets and high impact systems (FIPS 199 high) only. A clause whose role
  was not read gives both (`pqc_by_role`). It is a condition the scan cannot check, so the gate,
  `deadline` and `next_deadline` do not count it (`counted_by_gate: false`) (0.47.0).
- A line that only verifies or decrypts (`operation`, see
  [the role of a line](closure-and-profiles.md)) gets `legacy_use` in its `nist-ir-8547` clause,
  and the block counts such lines in `verify_or_decrypt_only`. IR 8547 section 4.1 calls
  processing already protected information "legacy use", but Tables 2 and 4 give these schemes
  no legacy-use status, so the dates stand and the line trips the gate like any other (0.47.0).
- A gate over files that were not read is not a pass: `gate` reads `not_established` and
  `gate_not_established_because` gives the count; the exit code of that case stays 0 (0.41.0).
- Nor is a gate whose document dates symmetric or hash algorithms, which a scan does not read
  (0.49.0, row 527): `cnsa-2.0` (AES-256, SHA-384/512, already required), `au-ism` (AES-128/192,
  SHA-224/256, HMAC-SHA256 not approved beyond 2030), `ca-cccs` (SHA-224, SHA3-224 and HMAC keys
  under 128 bits by the end of 2030) and `nist-ir-8547` (the 112-bit standards, 2030). Their block
  carries `symmetric` -- `status: not_established`, `evaluated: false`, what the document dates
  and its words (`document_says`) -- and a gate that would pass reads `not_established` with that
  reason; a fail stays a fail and the exit code is unchanged. The other documents date public-key
  cryptography only and pass as before.
- `--min-coverage PERCENT` (with `--mandate`) makes it a failure: when fewer than PERCENT of the
  files present were read (`coverage.scope.coverage_pct`), the gate is `fail`, exit 1, and
  `gate_failed_because` says how many files were not read. It measures files opened; a file read
  only in part counts as opened (`read_in_full_pct` is reported beside it, see
  [coverage](coverage.md)). Command line only (0.41.0, 0.42.0).
- `--profile` (CLI) and `profile` (the `scan_repo` tool) choose whose words fill the
  `replacement` and the profile notes; see [closure, replacements and profiles](closure-and-profiles.md).

## `.qrp.toml`

Read from the scanned tree unless `--no-config`: profile, level, exclude, baseline, mandate,
lead_months. The command line wins. On Python 3.10 `tomli` is a dependency, so the file is read
there too (0.37.0). `--min-coverage` is not read from it.

## Suppression markers

```
# qrp:ignore RSA <reason>
# qrp:ignore-next-line RSA until=2027-06-30 owner=j.doe <reason>
```

- `qrp:ignore <family> <reason>` suppresses that family on its line, `qrp:ignore-next-line` on the
  next one. A suppressed row is listed and counted, never dropped; a marker without a family and
  a reason does not apply and is listed in `markers_not_applied` (0.37.0).
- `until=YYYY-MM-DD` and `owner=<name>` may stand anywhere after the family. Through that day the
  marker suppresses and the suppression carries both; after it the occurrence is back in
  `evidence` and the marker is in `markers_not_applied` with "expired on <date>" (a SARIF
  notification on its line). A `until=` that is not a date does not apply. The date is compared
  with the day the scan runs (0.42.0).
- A reason that calls itself temporary ("temporary", "for now", "interim") with no `until=` still
  applies and is listed in `suppressed.markers_flagged` (and `coverage.suppressed.markers_flagged`):
  it cannot expire (0.42.0).

## Baselines and SARIF

`--write-baseline` / `--baseline` mark rows new or baselined, with the counts in
`coverage.baseline`. `qrp-mcp scan PATH --format sarif` writes SARIF 2.1.0; every file not read
is a notification with its reason (0.37.0).
