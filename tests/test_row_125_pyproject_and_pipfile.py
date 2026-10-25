"""Dependencies in pyproject.toml and Pipfile (ZA-OPRAVYANE rows 125, 149).

Both files were claimed and read, and their dependencies never came out: certbot's
`acme/pyproject.toml:29 "cryptography>=47.0.0"` gave nothing. A range is a request, not a
version: the row carries what the manifest asks for, as written, and never a version
guessed from it.
"""

from pathlib import Path

from qrp_mcp import assets

PYPROJECT = """[project]
name = "acme"
dependencies = [
    "cryptography>=47.0.0",
    "josepy>=2.0",
    "pyOpenSSL",
    'PyJWT[crypto] >= 2.8 ; python_version >= "3.10"',
]
[project.optional-dependencies]
dev = ["pycryptodome==3.20.0", "pytest"]
[tool.poetry.dependencies]
python = "^3.10"
cryptography = "47.0.0"
paramiko = { version = ">=3.4", optional = true }
[tool.poetry.group.test.dependencies]
ecdsa = "*"
[dependency-groups]
lint = ["rsa>=4.9"]
[tool.ruff]
select = ["cryptography"]
"""

PIPFILE = """[[source]]
url = "https://pypi.org/simple"
[packages]
cryptography = "==41.0.0"
requests = "*"
paramiko = {version = ">=3.0", extras = ["gssapi"]}
[dev-packages]
pycryptodome = "*"
[requires]
python_version = "3.12"
"""


def _rows(name: str, text: str) -> list[tuple[int, str, str | None]]:
    lines = text.splitlines()
    found = assets.scan_manifest(Path(name), name, lines)
    return [(r["line"], r["package"], r.get("requested")) for r in found]


def test_pyproject_dependencies_with_the_request_as_written():
    rows = _rows("pyproject.toml", PYPROJECT)
    assert (4, "cryptography", ">=47.0.0") in rows
    assert (6, "pyOpenSSL", None) in rows
    assert (7, "PyJWT", ">= 2.8") in rows
    assert (10, "pycryptodome", "==3.20.0") in rows
    assert (13, "cryptography", "47.0.0") in rows
    assert (14, "paramiko", ">=3.4") in rows
    assert (16, "ecdsa", None) in rows
    assert (18, "rsa", ">=4.9") in rows
    # Not a dependency table, and not a package with cryptography in it.
    assert not any(r[0] in (2, 12, 20) for r in rows)
    assert not any(r[1] in ("josepy", "pytest", "python") for r in rows)


def test_pyproject_range_is_never_a_version():
    found = assets.scan_manifest(Path("pyproject.toml"), "pyproject.toml",
                                 PYPROJECT.splitlines())
    first = next(r for r in found if r["line"] == 4)
    assert "version" not in first and first["requested"] == ">=47.0.0"


def test_pipfile_dependencies():
    rows = _rows("Pipfile", PIPFILE)
    assert (4, "cryptography", "==41.0.0") in rows
    assert (6, "paramiko", ">=3.0") in rows
    assert (8, "pycryptodome", None) in rows
    assert not any(r[1] in ("requests", "python_version") for r in rows)
