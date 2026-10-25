# qrp-mcp-core

The optional compiled part of [qrp-mcp](https://github.com/StanimirTenev/qrp-mcp): one search
per file for the lines any of qrp-mcp's rules could match, in Rust (`regex`, `aho-corasick`).

qrp-mcp imports it when it is installed and does the same search in Python when it is not.
Either way the lines it reads, the findings and the coverage are the same; only the time
differs. Every rule and every classification stays in qrp-mcp: the gates are built there and
handed to this module as strings, and what comes back is a set of line numbers.

`QRP_MCP_CORE=0` makes qrp-mcp ignore an installed core.

```
pip install qrp-mcp qrp-mcp-core
```

Wheels are abi3 (CPython 3.10 and later), one per platform. Building from source needs a Rust
toolchain: `pip install maturin && maturin build --release -m core/Cargo.toml`.
