# QRP post-quantum readiness scanner — Claude Code plugin

An adaptive post-quantum readiness scanner. It closes each operation it claims, tests every
documented spelling, proposes new spellings from the libraries' own documentation, and carries its
coverage and limits inside the CBOM.

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
