"""Shared test setup.

pqc/PKI closure (24.11.2026): the catalogue's post-quantum material -- ML-DSA, ML-KEM, SLH-DSA and
composite keys, certificates and requests -- is made when the tests run, as the classical material
is (test_operation_closure._make_material), and never committed. It is added to the same table the
closure test reads its `material` and `{{NAME}}` fillers from, once, before any test of that
module (or of test_operation_candidates, which writes through it) runs.
"""

from __future__ import annotations

import sys

import pytest


@pytest.fixture(autouse=True)
def _pqc_closure_material():
    module = sys.modules.get("test_operation_closure")
    if module is not None and "MLDSA65_SPKI_PEM" not in module._MADE:
        try:
            import _pqc_material
            module._MADE.update(_pqc_material.make())
        except Exception:  # noqa: BLE001 -- a `cryptography` without ML-DSA/ML-KEM (the floor
            # is 43): only the pqc/PKI cases fail, on their missing material, not every test.
            pass
    yield
