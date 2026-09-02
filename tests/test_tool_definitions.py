"""The tool definitions are the part an agent reads before choosing this server.

Glama's Tool Definition Quality Score scores every tool of every server in its
registry against a published rubric, and the literature behind it found that
tools with well-written descriptions are selected roughly 260% more often in
competitive settings. Two of the six dimensions carry 20% each and are the
weakest across the whole corpus: whether the description says *when not* to use
the tool and names the alternative, and whether behaviour beyond the annotations
is disclosed.

So these are pinned. A description is not documentation here; it is the
selection surface.
"""

from __future__ import annotations

import asyncio

import pytest

from qrp_mcp.server import mcp


def tools():
    return {t.name: t for t in asyncio.run(mcp.list_tools())}


# Read-only, idempotent and closed-world are the three promises this server is
# built on. An annotation is the only form of them an agent can check without
# reading prose, and a description that contradicted them would be worse than
# silence.
@pytest.mark.parametrize("name", ["scan_repo", "list_algorithms"])
def test_every_tool_declares_what_it_will_not_do(name):
    annotations = tools()[name].annotations
    assert annotations is not None, f"{name} declares no annotations"
    assert annotations.read_only_hint is True
    assert annotations.destructive_hint is False
    assert annotations.idempotent_hint is True
    # Nothing this server touches lives outside the machine it runs on.
    assert annotations.open_world_hint is False


# The weakest dimension in the registry, and the one that decides mis-selection:
# a tool that never says when NOT to use it gets chosen for the wrong question.
@pytest.mark.parametrize(
    "name,sibling", [("scan_repo", "list_algorithms"), ("list_algorithms", "scan_repo")]
)
def test_each_tool_names_the_other_as_its_boundary(name, sibling):
    description = tools()[name].description or ""
    assert sibling in description, f"{name} does not say when {sibling} is the right call"


def test_scan_repo_states_what_it_will_not_look_at():
    """A wrong answer about scope is more expensive than a missing one."""
    description = tools()["scan_repo"].description or ""
    for excluded in ("network endpoint", "running host", "certificate store"):
        assert excluded in description


def test_the_parameter_is_documented_in_the_schema_not_only_the_prose():
    """Either channel earns the credit, but the schema is the one an agent fills from."""
    schema = tools()["scan_repo"].input_schema or {}
    path = schema.get("properties", {}).get("path", {})
    assert path.get("description"), "path has no description in the input schema"
    assert "node_modules" in path["description"], "the exclusion is not stated where it is used"


def test_no_description_merely_restates_its_name():
    """A tautological description is capped at 2 for purpose clarity, by rule."""
    for name, tool in tools().items():
        description = (tool.description or "").strip().lower()
        assert description
        assert description != name.replace("_", " ")
        assert description != name
