# qrp-mcp

<!-- mcp-name: eu.quantumreadiness/qrp-mcp -->

**Find the cryptography in your codebase that a quantum computer would break — from your AI agent, in one command.**

An MCP server that scans a local directory for classical public-key cryptography, weak
primitives and CI signing commands, then classifies what it finds: broken by Shor's
algorithm, post-quantum, or neither.

**Everything runs on your machine.** No network calls, no account, no API key, nothing
uploaded. The server makes zero outbound connections — by design, not by configuration.

## Why deterministic matters

There is no LLM inside this tool. The same input always produces the same output, and every
finding points at a file and a line you can open yourself.

That is the point of giving it to an agent: **the agent brings the language, the tool brings
the truth.** An agent that guesses about your cryptography is worse than useless; one that
reads a deterministic inventory can actually reason about it.

## Quick start

Add it to your MCP client — no installation step, `uvx` fetches and runs it:

```json
{
  "mcpServers": {
    "qrp": {
      "command": "uvx",
      "args": ["qrp-mcp"]
    }
  }
}
```

Then ask your agent:

> Scan ~/code/my-service for quantum-vulnerable cryptography.

## Tools

| Tool | What it does |
| --- | --- |
| `scan_repo(path)` | Scans a directory's source code, CI/CD configs and infrastructure-as-code; returns findings and a summary |
| `list_algorithms()` | The algorithm families the server recognises and how each is classified |

## What it looks at

- **Source code** (Python, Go, Java, JS/TS, Ruby, PHP, C/C++/C#, shell) — RSA, DSA, DH,
  ECDSA and elliptic-curve usage, plus MD5, SHA-1, RC4 and DES/3DES.
- **CI/CD pipelines** (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI) —
  signing commands such as `gpg --sign`, `cosign sign`, `signtool`, `jarsigner`, `codesign`.
- **Infrastructure as code** — Terraform and Kubernetes key algorithms, and private key
  material committed by mistake.

Example summary:

```json
{
  "total_findings": 14,
  "quantum_vulnerable_count": 6,
  "pqc_ready_count": 0,
  "weak_count": 2,
  "highest_severity": "critical",
  "pqc_readiness": "classical_only"
}
```

## What it is not

This is a **free inventory tool**, not a full readiness assessment. It deliberately does not do:

- risk scoring or prioritisation,
- migration planning,
- network, host or certificate scanning,
- tracking change over time.

Those live in the [Quantum Readiness Platform](https://quantumreadiness.eu) — the product this
tool comes from. If the inventory tells you that you have a problem, that is where you go to
work out what to do about it. Nothing here is crippled to make you upgrade: what it does, it
does completely.

## License

Apache-2.0.
