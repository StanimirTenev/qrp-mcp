# Sample CBOM from qrp-mcp 0.46.0

`h5bp-server-configs-nginx.cbom.json` is a CycloneDX 1.6 CBOM that qrp-mcp 0.46.0 wrote for a small public
repository. It is meant as an import test for a CBOM reader.

- **Repository:** https://github.com/h5bp/server-configs-nginx (H5BP's nginx configuration)
- **Commit:** `d2f2c3e2fac76f429adb738894499b8fb756d2f3` (20 June 2026)
- **Licence of the repository:** MIT (`LICENSE.txt`, "Copyright (c) H5BP")
- **Command** (the built 0.46.0 wheel, installed in a fresh virtual environment):

  ```
  qrp-mcp cbom server-configs-nginx --out h5bp-server-configs-nginx.cbom.json
  ```

  This uses the default `--level masked`: the quoted lines are starred except for the algorithm
  names. Files and line numbers are kept.
- **sha256 of the file:** `e8938fef8532a57ee1febd858b374dd948071dce9c7395165c958e9423c65bdc`
- **Validated** against the CycloneDX 1.6 JSON schema with zero errors. Two copies were used:
  `bom-1.6.schema.json` from the specification's `master` branch (the copy the qrp-mcp tests
  vendor) and the one from the `1.6` branch. Every `bom-ref` that the document points to resolves
  to a component in it.

## What the TLS component carries now

The repository pins TLS versions in `h5bp/tls/policy_balanced.conf` and
`h5bp/tls/policy_strict.conf` and sets groups with `ssl_ecdh_curve`. Each pinned version is a
`protocol` component. Its key exchange can be read from the standard fields alone, with no
`qrp:` properties:

| component | file | `protocolProperties.cryptoRefArray` |
|---|---|---|
| TLSv1.2 | policy_balanced.conf | X25519, prime256v1, secp521r1, secp384r1 (each a `key-agree` algorithm component) |
| TLSv1.2 | policy_strict.conf | X25519 |
| TLSv1.3 | policy_strict.conf | X25519 |

The link is by file. It records what the file configures, not what a connection negotiates;
`qrp:linked_by` says this.

`protocolProperties.cipherSuites` is not present in this sample. The repository's `ssl_ciphers`
lines are `EECDH+CHACHA20:EECDH+AES`, which are OpenSSL selectors and name no single suite. qrp-mcp
does not expand selectors into suites. Where a file names suites (for example
`ECDHE-RSA-AES128-GCM-SHA256` or `TLS_AES_256_GCM_SHA384`), each one is written by its IANA name,
and its `algorithms` field points at the components for the families it names.

A post-quantum hybrid group such as `X25519MLKEM768` is written the same way. It appears in
`cryptoRefArray` as `hybrid:x25519mlkem768`, and that component's `dependencies` point at its
ML-KEM and X25519 halves. This repository does not configure one.

`compositions[0].aggregate` is `incomplete` because some files present were not read. The list of
those files is in the `qrp:coverage:*` properties.

## Rerunning it yourself

Clone the repository at the commit above and run the command. Your file will differ from this one
in one field, `qrp:coverage:corpus:target`, which records the absolute path of the scanned folder
(here `/tmp/example/server-configs-nginx`). Compare `qrp:findings_fingerprint:sha256` instead; for
this commit and 0.46.0 it is `efaeeeec2048349ac52feb9de26d7c2fbf8d5e4b820856d1737a1821a71bf91a`.
Recording the folder by a relative path is planned.
