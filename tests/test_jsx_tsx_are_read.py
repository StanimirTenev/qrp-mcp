"""JSX and TSX are source (ZA-OPRAVYANE row 96, an agent's word, reproduced 23.10.2026: both
were absent from SOURCE_EXTENSIONS and counted as types not claimed)."""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("name", ["Login.jsx", "Login.tsx"])
def test_component_is_read(tmp_path, name):
    (tmp_path / name).write_text(
        "const keys = await crypto.subtle.generateKey(\n"
        "  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048 }, true, ['sign']);\n")
    result = scan_directory(tmp_path)
    assert name in result["files_read"]
    assert "RSA" in result["detected_algorithms"]
