"""The scan_repo tool says which directories it leaves out, all of them (ZA-OPRAVYANE row 95,
an agent's word, reproduced 23.10.2026: the description named 6 of the 13 in EXCLUDED_DIRS)."""

import typing

from qrp_mcp import detectors, server


def test_path_description_names_every_excluded_dir():
    hints = typing.get_type_hints(server.scan_repo, include_extras=True)
    description = next(m.description for m in hints["path"].__metadata__
                       if getattr(m, "description", None))
    missing = [d for d in sorted(detectors.EXCLUDED_DIRS) if d not in description]
    assert not missing, missing
