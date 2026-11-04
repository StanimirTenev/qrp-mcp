"""`codesign` is Apple's signing command, not a word inside a file name (fix list row 367).

Measured on 0.41.0 (W1 fixture 08b-signing-in-ci): `signtool sign /f codesign.pfx /fd SHA1 ...`
gave two `ci_pipeline` rows for one step, `signtool_sign` and `codesign`: `\\bcodesign\\b`
matched the file name. codesign(1) takes its options after the command
(https://keith.github.io/xcode-man-pages/codesign.1.html: `codesign -s identity [-i
identifier] ... path ...`), so the command is the word followed by an option.
"""

from qrp_mcp.detectors import scan_ci_file


def _types(tmp_path, line):
    path = tmp_path / "azure-pipelines.yml"
    path.write_text(f"steps:\n- script: {line}\n")
    return [f["command_type"] for f in scan_ci_file(path, "azure-pipelines.yml")]


def test_a_pfx_named_codesign_is_not_apples_tool(tmp_path):
    assert _types(tmp_path, "signtool sign /f codesign.pfx /fd SHA1 setup.exe") == [
        "signtool_sign"]


def test_the_command_itself_is_still_found(tmp_path):
    assert _types(tmp_path, 'codesign --sign "$IDENTITY" --timestamp App.app') == ["codesign"]
    assert _types(tmp_path, "/usr/bin/codesign -s - build/App.app") == ["codesign"]
