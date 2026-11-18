# QRP post-quantum readiness scanner — Claude Code plugin

An adaptive post-quantum readiness scanner. It closes operations against a catalogue of their
documented spellings, each with a test, says in its output which (operation, ecosystem) pairs are
closed, and carries its coverage and limits inside the CBOM. A maintainer tool in the repository
re-reads the documentation and proposes new spellings, which enter only with a source and a test.

Wraps the [`qrp-mcp`](https://github.com/StanimirTenev/qrp-mcp) server as an installable
Claude Code plugin: one MCP server and one skill, `/qrp:pqc-scan`.

```
/plugin marketplace add StanimirTenev/qrp-mcp
/plugin install qrp@quantumreadiness
```

Then, in any project:

```
/qrp:pqc-scan
```

**Requires [`uv`](https://docs.astral.sh/uv/)** on your PATH. The plugin runs the server with
`uvx qrp-mcp==<version>`, pinned to this release, without a separate install step. The
plugin's `uv.lock` lists the exact dependency versions and hashes this release is locked to.

Everything runs on your machine. The server makes zero outbound connections — enforced by a
test in the repository, not promised in a paragraph.
