# QRP cryptographic inventory — Claude Code plugin

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
`uvx qrp-mcp`, which fetches and runs it without a separate install step.

Everything runs on your machine. The server makes zero outbound connections — enforced by a
test in the repository, not promised in a paragraph.
