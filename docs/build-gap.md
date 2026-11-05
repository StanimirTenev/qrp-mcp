# Source scan against build output

`qrp-mcp build-gap SCAN.json BUILD_DIR [--out FILE]` sets a saved source scan
(`qrp-mcp scan PATH --out SCAN.json`) beside a build output directory: a .NET publish folder, a
folder holding Go binaries. From 0.44.0.

It reports:

- **K**: the packages (NuGet, from `*.deps.json`) or modules (Go, from `go version -m`) in the
  build that are public-key-bearing by the tables below;
- **J**: how many of those K the source scan named as a dependency;
- the **K - J list**, by name and version, with the families the build's tables name for each;
- the **families on one side only**: in the build and not in the source scan, and the reverse
  (an orphan project, a `#if`, test code, a function the Go linker dropped);
- for each Go binary, the **`DefaultGODEBUG`** line as the toolchain recorded it, and the
  settings in it that concern cryptography (`tls*`, `x509*`, `crypto*`, `rsa*`, `fips140*`, ...).
  They are the settings that differ from that Go version's defaults, set by the `go` line of
  `go.mod` or a `//go:debug` directive. What each one does is in the Go documentation
  ([go.dev/doc/godebug](https://go.dev/doc/godebug)); the command does not interpret them.

## What the figure is

**Robustness on known patterns.** A package counts when its metadata names a type from a fixed
list (RSA, ECDsa, ECDiffieHellman, DSA, Ed25519, X25519, ML-KEM, ML-DSA, SLH-DSA and their
library spellings), a Go module when a package path it contributed to the binary has such a
component (`.../ecdsa`, `.../curve25519`). It is not recall and not coverage of the build: a
package whose metadata names no listed type, a module whose paths name no algorithm, native
code, and anything chosen at run time by a string are not counted.

## What is read, and what is never read

Only tables the toolchain already wrote:

| Source | What is taken from it |
| --- | --- |
| `*.deps.json` | the packages in the build (`libraries`, type `package`), and the DLLs each ships (`runtime`, `runtimeTargets`) |
| .NET metadata tables | AssemblyRef, TypeRef and TypeDef names, from the `#~` and `#Strings` streams (ECMA-335 Partition II, 22 and 24) |
| `go version -m BIN` | the modules linked in and the `DefaultGODEBUG` build setting |
| `go tool nm BIN` | the package path of each symbol name |

Never read: method bodies, IL, machine code, call sites, arguments or data flow. There is no
call graph and no control-flow graph, and no identification by similarity, embeddings or a
learned model. **No key size, mode or curve is read from the build**: a parameter appears in
the report only where the source scan already had it. A test fails if the module imports a
disassembler or an IL reader. No file found is executed; Go binaries are read by `go` itself,
which must be on PATH (without it they are listed under `not_read`).

## Two things to know

- **Scan the source before you build.** The scanner reads `*.deps.json` as a lockfile, so a
  scan taken after the build counts the build as the source and J goes up. The report says so
  when the scan's dependency rows cite a `.deps.json`.
- **Carried is not executed.** A type referenced in metadata may be reachable only from dead
  code; .NET does not trim unless `PublishTrimmed` is set. Go's linker does trim, so a family
  only in unreached Go code shows as source-only.

## Where it comes from

The measurement of 04.11.2026 (two probes of our own construction, one .NET, one Go) that this
command packages. On those probes the source scan of 0.42.0 named 1 of 11 public-key-bearing .NET
packages; the Go binary carried six families no source line named. Those ratios describe the
probes, not .NET or Go at large.
