"""Row 560 (25.11.2026, Rishi Cherukuri; probe `linkedin-postove/2026-11-25/stai/proba/rishi`).

`signature_algorithm: ${SIGNING_ALG:ECDSA-P256}` gave an ECDSA finding and no place in
`chosen_outside_files`, while `os.environ.get("SIG_ALG", "RSA-PSS")` was a place with `default`,
`default_family` and `overridable: true`. Both are a default the environment can replace.

The class, a value read from outside with a default written beside it, in each documented form:
* Spring Boot: "Property placeholders can also specify a default value using a : to separate the
  default value from the property name, for example ${name:default}"
  (https://docs.spring.io/spring-boot/reference/features/external-config.html), in .properties and
  YAML; Spring Framework `@Value("${catalog.name:defaultCatalog}")`
  (https://docs.spring.io/spring-framework/reference/core/beans/annotation-config/value-annotations.html);
* Compose: `${VAR:-default}`, `${VAR-default}` ("Default value"); `${VAR:?error}`, `${VAR?error}`
  are a required value and `${VAR:+replacement}`, `${VAR+replacement}` an alternative, no default
  (https://docs.docker.com/reference/compose-file/interpolation/);
* the shell: `${parameter:-word}`, `${parameter-word}`, and `${parameter:=word}`, `${parameter=word}`,
  which assign the default (https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html).
  In a shell `${X:word}` is substring expansion, not a default, and is not read as one there.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo


def _places(tmp_path: Path, name: str, text: str) -> list[dict]:
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    return result["chosen_outside_files"]["places"]


def _defaults(places: list[dict]) -> list[tuple]:
    # `setting` is the name the line gives the value (the key on the left where there is one), as
    # for os.environ.get; the placeholder's own name is in `read_from`.
    return [(p["line"], p.get("default"), p.get("default_family"), p.get("overridable"))
            for p in places if p.get("default")]


@pytest.mark.parametrize("name,text,line,default,family", [
    ("crypto.yaml", "crypto:\n  signature_algorithm: ${SIGNING_ALG:ECDSA-P256}\n", 2,
     "ECDSA-P256", "ECDSA"),
    ("application.yml", "jwt:\n  signing-algorithm: \"${jwt.alg:RSA-PSS}\"\n", 2,
     "RSA-PSS", "RSA"),
    ("application.properties", "app.signature-algorithm=${SIG_ALG:ECDSA-P384}\n", 1,
     "ECDSA-P384", "ECDSA"),
    ("src/main/java/Keys.java",
     'class Keys {\n  @Value("${jwt.signing-alg:RS256}") private String alg;\n}\n', 2,
     "RS256", "RSA"),
])
def test_spring_placeholder_default(tmp_path, name, text, line, default, family):
    assert _defaults(_places(tmp_path, name, text)) == [(line, default, family, True)]


@pytest.mark.parametrize("value", ["${SIG_ALG:-ECDSA-P256}", "${SIG_ALG-ECDSA-P256}"])
def test_compose_default(tmp_path, value):
    text = f"services:\n  app:\n    environment:\n      SIGNATURE_ALGORITHM: {value}\n"
    assert _defaults(_places(tmp_path, "docker-compose.yml", text)) == [
        (4, "ECDSA-P256", "ECDSA", True)]


@pytest.mark.parametrize("value", ["${SIG_ALG:-ECDSA-P256}", "${SIG_ALG-ECDSA-P256}",
                                   "${SIG_ALG:=ECDSA-P256}", "${SIG_ALG=ECDSA-P256}"])
def test_shell_default(tmp_path, value):
    text = f'#!/bin/sh\nSIGNATURE_ALGORITHM="{value}"\n'
    assert _defaults(_places(tmp_path, "run.sh", text)) == [
        (2, "ECDSA-P256", "ECDSA", True)]


@pytest.mark.parametrize("name,value", [
    ("docker-compose.yml", "${SIG_ALG:?ECDSA-P256}"), ("docker-compose.yml", "${SIG_ALG?ECDSA-P256}"),
    ("docker-compose.yml", "${SIG_ALG:+ECDSA-P256}"), ("docker-compose.yml", "${SIG_ALG+ECDSA-P256}"),
])
def test_required_and_alternative_values_are_no_default(tmp_path, name, value):
    text = f"services:\n  app:\n    environment:\n      SIGNATURE_ALGORITHM: {value}\n"
    assert _defaults(_places(tmp_path, name, text)) == []


def test_shell_substring_is_no_default(tmp_path):
    assert _defaults(_places(tmp_path, "run.sh",
                             '#!/bin/sh\nSIGNATURE_ALGORITHM="${SIG_ALG:ECDSA}"\n')) == []


def test_a_placeholder_with_no_algorithm_is_no_default(tmp_path):
    assert _defaults(_places(tmp_path, "application.yml",
                             "crypto:\n  signature_algorithm: ${SIG_ALG:unknown}\n")) == []


def test_the_finding_stays(tmp_path):
    (tmp_path / "crypto.yaml").write_text("crypto:\n  signature_algorithm: ${SIGNING_ALG:ECDSA-P256}\n")
    result = scan_directory(tmp_path)
    assert [(i["line"], i["algorithm"]) for i in result["evidence"]["source_code"]] == [(2, "ECDSA")]


def test_cli_and_mcp_carry_the_place(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    (root / "crypto.yaml").write_text("crypto:\n  signature_algorithm: ${SIGNING_ALG:ECDSA-P256}\n")
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out)], check=True, capture_output=True,
                   env=dict(os.environ))
    for result in (json.loads(out.read_text()), scan_repo(str(root))):
        assert _defaults(result["chosen_outside_files"]["places"]) == [
            (2, "ECDSA-P256", "ECDSA", True)]
