"""ZA-OPRAVYANE rows 425-428 (the W1 source-vs-build round, 04.11.2026): `*.deps.json`,
`packages.lock.json`, `vendor/modules.txt` and `go.sum` are read as lockfiles.

On one .NET 8 publish the source scan named 1 of 11 packages carrying public-key cryptography;
reading `*.deps.json` against the scanner's own table names 3. `go.sum` was skipped by type and
`vendor/` left out before counting, so `vendor/modules.txt` was never reached.

Formats, as their owners document them (read 04.11.2026):
- .NET deps.json, dotnet/sdk documentation/specs/runtime-configuration-file.md: "only the
  `runtimeTarget`, `targets` and `libraries` sections are required"; "The name of the property
  contains the ID and Version of the dependency in the form `[Id]/[Version]`"; `type` is
  `package` for a NuGet package, `project` for a project reference.
- NuGet packages.lock.json, learn.microsoft.com/nuget/consume-packages/
  package-references-in-project-files#locking-dependencies: "NuGet restore will generate a lock
  file (`packages.lock.json`) at the project root directory that lists all the package
  dependencies"; "NuGet supports project specific lock file `packages.<project_name>.lock.json`".
  Read as JSON: `dependencies` -> target framework -> package id -> `resolved`.
- go.sum, go.dev/ref/mod#go-sum-files: "Each line in `go.sum` has three fields separated by
  spaces: a module path, a version (possibly ending with `/go.mod`), and a hash"; "If the version
  ends with `/go.mod`, the hash is for the module's `go.mod` file only; otherwise, the hash is for
  the files within the module's `.zip` file." So only a line without `/go.mod` says the module's
  code was downloaded.
- vendor/modules.txt, go.dev/ref/mod#go-mod-vendor ("a list of vendored packages and the module
  versions they were copied from") and cmd/go/internal/modload/vendor.go: a line starting `# `
  whose third field is a version names a module (`# path version`, optionally `=> replacement`);
  `## ` lines are annotations; other lines are packages.
"""

from __future__ import annotations

import json

from qrp_mcp.scan import scan_directory


def _deps(tmp_path):
    result = scan_directory(tmp_path, settings=None)
    return result, {(d["path"], d["package"], d.get("version")) for d in result["evidence"]["dependencies"]}


def test_deps_json(tmp_path):
    (tmp_path / "App.deps.json").write_text(json.dumps({
        "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0"},
        "targets": {".NETCoreApp,Version=v8.0": {}},
        "libraries": {
            "App/1.0.0": {"type": "project", "serviceable": False, "sha512": ""},
            "BouncyCastle.Cryptography/2.4.0": {"type": "package", "serviceable": True},
            "System.IdentityModel.Tokens.Jwt/7.1.2": {"type": "package", "serviceable": True},
        }}, indent=2))
    result, deps = _deps(tmp_path)
    assert ("App.deps.json", "BouncyCastle.Cryptography", "2.4.0") in deps
    assert ("App.deps.json", "System.IdentityModel.Tokens.Jwt", "7.1.2") in deps
    # Read by its structure, not matched as configuration text.
    assert not [r for r in result["evidence"]["source_code"] if r["path"] == "App.deps.json"]


def test_packages_lock_json(tmp_path):
    lock = {"version": 1, "dependencies": {"net8.0": {
        "BouncyCastle.Cryptography": {"type": "Direct", "requested": "[2.4.0, )",
                                      "resolved": "2.4.0", "contentHash": "abc=="},
        "Newtonsoft.Json": {"type": "Transitive", "resolved": "13.0.3", "contentHash": "x=="}}}}
    (tmp_path / "packages.lock.json").write_text(json.dumps(lock, indent=2))
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "packages.Api.lock.json").write_text(json.dumps(lock, indent=2))
    _, deps = _deps(tmp_path)
    assert ("packages.lock.json", "BouncyCastle.Cryptography", "2.4.0") in deps
    assert ("sub/packages.Api.lock.json", "BouncyCastle.Cryptography", "2.4.0") in deps


def test_go_sum_reads_the_module_lines_not_the_go_mod_only_lines(tmp_path):
    (tmp_path / "go.sum").write_text(
        "golang.org/x/crypto v0.31.0 h1:ihbySMvVjLAeSH1IbfcRTkD/iNscyz8rGzjF/E5hV6U=\n"
        "golang.org/x/crypto v0.31.0/go.mod h1:kDsLvtWBEx7MV9tJOj9bnXsPbxwJQ6csT/x4KIYZ5SU=\n"
        "github.com/golang-jwt/jwt/v5 v5.2.1/go.mod h1:pqrtFR0X4osieyHYxtmOUWsAWrfe1Q5UVIyoH402zdk=\n")
    result, deps = _deps(tmp_path)
    assert deps == {("go.sum", "golang.org/x/crypto", "v0.31.0")}
    assert "go.sum" in result["files_read"]


def test_vendor_modules_txt_is_read_and_the_rest_of_vendor_is_not(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/app\n\ngo 1.24\n")
    vendor = tmp_path / "vendor"
    (vendor / "golang.org/x/crypto/ssh").mkdir(parents=True)
    (vendor / "golang.org/x/crypto/ssh" / "keys.go").write_text("package ssh\nvar k = rsa.GenerateKey\n")
    (vendor / "modules.txt").write_text(
        "# golang.org/x/crypto v0.31.0\n## explicit; go 1.20\ngolang.org/x/crypto/ssh\n"
        "# github.com/golang-jwt/jwt/v5 v5.2.1 => ./local/jwt\n## explicit\n"
        "github.com/golang-jwt/jwt/v5\n")
    result, deps = _deps(tmp_path)
    assert ("vendor/modules.txt", "golang.org/x/crypto", "v0.31.0") in deps
    assert ("vendor/modules.txt", "github.com/golang-jwt/jwt/v5", "v5.2.1") in deps
    assert "vendor/modules.txt" in result["files_read"]
    assert "vendor/golang.org/x/crypto/ssh/keys.go" not in result["files_read"]
    by_dir = result["coverage"]["scope"]["files_excluded_before_counting"]["by_directory"]
    assert by_dir["vendor"] == 1
