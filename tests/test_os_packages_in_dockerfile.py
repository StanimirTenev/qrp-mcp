"""Crypto libraries installed by the system package manager in a Dockerfile (fix list row 223).

Measured on 0.40.1: `RUN apt-get install -y openssl=3.0.15-1~deb12u1 libssl3=...` was in
`files_read` with 0 rows, and nothing said the packages had been seen. The system OpenSSL was
missing from the inventory, and a change of its pinned version closed nothing, silently.

Now `apt-get install` / `apt install`, `apk add` and `dnf|yum|microdnf install` lines name
the crypto libraries they install as `dependencies` with `basis: os_package`: declared, not
observed. The families are the ones the table already gives the same library's language
bindings (OpenSSL: RSA, ECDSA). The version is the one apt or apk pins with `=`.
Syntax: https://manpages.debian.org/bookworm/apt/apt-get.8.en.html (`pkg=version`),
https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper (`apk add pkg=version`).
"""

from qrp_mcp import cyclonedx
from qrp_mcp.scan import scan_directory

DOCKERFILE = ("FROM debian:bookworm-slim\n"
              "RUN apt-get update && apt-get install -y openssl=3.0.15-1~deb12u1 "
              "libssl3=3.0.15-1~deb12u1 php8.2-fpm=8.2.26-1~deb12u1\n"
              "RUN apk add --no-cache libsodium curl\n")


def test_apt_and_apk_crypto_packages_are_declared_dependencies(tmp_path):
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    r = scan_directory(tmp_path)
    deps = {(d["package"], d["line"]): d for d in r["evidence"]["dependencies"]}
    assert set(deps) == {("openssl", 2), ("libssl3", 2), ("libsodium", 3)}
    ssl = deps[("libssl3", 2)]
    assert ssl["basis"] == "os_package" and ssl["ecosystem"] == "deb"
    assert ssl["version"] == "3.0.15-1~deb12u1" and ssl["families"] == ["RSA", "ECDSA"]
    assert deps[("libsodium", 3)]["ecosystem"] == "apk"
    assert "version" not in deps[("libsodium", 3)]
    comp = next(c for c in cyclonedx.build(r)["components"] if c.get("name") == "libssl3")
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qrp:basis"] == "os_package" and comp["version"] == "3.0.15-1~deb12u1"


def test_a_package_in_a_comment_or_a_non_crypto_package_is_not_named(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n# RUN apk add openssl\n"
                                         "RUN apk add curl bash\n")
    r = scan_directory(tmp_path)
    assert r["evidence"]["dependencies"] == []


def test_a_list_continued_on_the_next_lines(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM debian\nRUN apt-get update && apt-get install -y --no-install-recommends \\\n"
        "      ca-certificates \\\n      libssl3=3.0.15-1~deb12u1 \\\n"
        "      && rm -rf /var/lib/apt/lists/*\nRUN echo openssl\n")
    r = scan_directory(tmp_path)
    assert [(d["package"], d["line"]) for d in r["evidence"]["dependencies"]] == [("libssl3", 4)]
