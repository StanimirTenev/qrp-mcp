"""Comments in Visual Basic and batch files (the limits named for rows 308 and 388).

* Visual Basic, https://learn.microsoft.com/en-us/dotnet/visual-basic/programming-guide/program-structure/comments-in-code
  -- the comment symbol (') "tells the Visual Basic compiler to ignore the text following it";
  "Comments can follow a statement on the same line, or occupy an entire line."
* Batch, https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/goto
  -- "If a line begins with a colon, it's treated as a label and any commands on that line are
  ignored." (`::` comments rely on this.) `rem` "Records comments in a script, batch, or
  config.sys file" (https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rem).
"""

from qrp_mcp.scan import scan_directory


def _kinds(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    return sorted((f["line"], f["algorithm"], f["evidence_kind"]) for f in result["evidence"]["source_code"])


def test_vb_apostrophe_comment(tmp_path):
    rows = _kinds(tmp_path, "Crypto.vb", (
        "Module Crypto\n"
        "    ' Dim old As MD5 = MD5.Create()\n"
        "    Dim tdes As TripleDES = TripleDES.Create() ' replaces MD5.Create()\n"
        "    Dim s As String = \"it's MD5.Create()\"\n"
        "End Module\n"))
    assert [r for r in rows if r[2] != "comment"] == [(3, "3DES", "call"), (4, "MD5", "call")]
    assert (2, "MD5", "comment") in rows


def test_batch_double_colon_comment(tmp_path):
    rows = _kinds(tmp_path, "gen.bat", ":: openssl genrsa -out old.key 1024\n"
                                       "openssl genrsa -out server.key 2048\n")
    assert [r[:2] for r in rows if r[2] != "comment"] == [(2, "RSA")]
