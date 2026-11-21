# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's
[private vulnerability reporting](https://github.com/StanimirTenev/qrp-mcp/security/advisories/new)
on this repository. Do not open a public issue for them.

A report is acknowledged within three working days. A confirmed issue is reproduced as a failing
test, fixed, released on PyPI, GitHub and the MCP registry, and described in `CHANGELOG.md` with
the versions it affects. Reporters are credited unless they ask not to be.

## Supported versions

Only the latest release is supported. Fixes are not backported.

## Scope

qrp-mcp is built to read code its user did not write, so a scanned tree is untrusted input.
Anything a scanned tree can do beyond being read, such as running code, writing files or
reaching the network, is in scope.
