"""ZA-OPRAVYANE row 150 (windows-latest, 26.10.2026): `files_left_out` said
`service\\.qrp.toml` on Windows, every other path in the result `service/.qrp.toml`. The two
places that list a left-out file used `str(path.relative_to(root))`, which is the OS's
separator; the rest of the scan joins the parts with `/`. Reproduced here on Linux by making
`relative_to` answer as Windows would."""

import pathlib

from qrp_mcp.scan import scan_directory


def test_a_left_out_path_is_written_with_slashes(tmp_path, monkeypatch):
    (tmp_path / "service").mkdir()
    (tmp_path / ".qrp.toml").write_text("level = \"full\"\n")
    (tmp_path / "service" / ".qrp.toml").write_text("level = \"full\"\n")
    (tmp_path / "service" / "a.py").write_text("x = 1\n")
    real = pathlib.PurePath.relative_to

    def windows_relative_to(self, *other, **kw):
        return pathlib.PureWindowsPath(*real(self, *other, **kw).parts)

    monkeypatch.setattr(pathlib.PurePath, "relative_to", windows_relative_to)
    result = scan_directory(str(tmp_path))
    assert sorted(result["files_left_out"]) == [".qrp.toml", "service/.qrp.toml"]
