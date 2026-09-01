---
description: Inventory the cryptography in a codebase that a quantum computer would break, and report what the scan could not read. Use when asked about post-quantum readiness, cryptographic inventory, a CBOM, or which algorithms a project signs with.
---

# Cryptographic inventory

Scan the directory the user names with the `scan_repo` tool from the `qrp` MCP server. If they
name none, scan the current working directory.

Report in this order.

**1. What was found.** Each algorithm, its classification — quantum-vulnerable, post-quantum,
weak, or unknown — with the file and line, so the user can open it. For post-quantum schemes,
give the family it rests on (structured or unstructured lattice, code-based, hash-based,
isogeny-based) and where it stands: standardised, selected, candidate, withdrawn, or broken.
"Post-quantum" is a category, not an assessment: SIKE is broken and HAWK is withdrawn, and
both are post-quantum by design.

**2. What the scan could not read.** State `unreadable_files` and its count plainly, even when
it is zero. A file nobody could open is not a file that is clean, and the difference is the
coverage of the whole report. Never let an unreadable file pass as an absence of findings.

**3. Coverage.** Files scanned against files present, as a number.

Then stop.

## What not to do

Do not assign a risk level, a severity ranking of your own, a score, or a migration order.
The tool is an inventory, not an assessment, and a priority invented here would be a judgement
the evidence does not support.

If the user asks what to migrate first, say plainly that the ordering depends on how long each
system's data must stay confidential and how long it stays exposed — not on the inventory
alone — and that the inventory is the input to that question rather than the answer.

If a scheme comes back as `unknown`, report it as unknown. Unrecognised reads as nothing found;
it is not the same thing.
