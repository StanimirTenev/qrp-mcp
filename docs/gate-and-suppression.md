# Gate, mandates and suppression markers

[Back to the README](../README.md) · [CHANGELOG](../CHANGELOG.md)

This page gathers what the [CHANGELOG](../CHANGELOG.md) says about the gate and the markers, in
one place. The CHANGELOG entry named beside each item is the full text.

## Mandates and the gate

- `--mandate cnsa-2.0|nist-ir-8547` gives each quantum-vulnerable occurrence its dated clause and
  `hndl_exposed`. With `--lead-months N` the run exits 1 when a deadline falls inside the lead
  time (0.37.0).
- `--mandate nist-ir-8547` follows the final NIST IR 8547; the gate counts the deprecation date
  (2030), named in `gate_counts` and `next_gate_deadline` beside `next_deadline` (0.38.0, 0.41.0).
- A gate over files that were not read is not a pass: `gate` reads `not_established` and
  `gate_not_established_because` gives the count; the exit code of that case stays 0 (0.41.0).
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
