"""ZA-OPRAVYANE row 424 (the L1 self-seeded control, 04.11.2026): a bare algorithm name on its
own line, inside a call split over lines, is read as the call would be on one line.

```
const key = generateKeyPairSync(
  'rsa',
  { modulusLength: 1024 },
);
```

was silent in TypeScript, and `KeyPairGenerator.getInstance(\\n "RSA");` in Java; written on one
line both are calls. The name is read only where the line above ends in the open parenthesis of
the call and the line holds nothing but the string; a bare string elsewhere stays what it was.
"""

from __future__ import annotations

from qrp_mcp.scan import scan_directory


def _rows(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return [(r["line"], r["algorithm"], r["evidence_kind"])
            for r in scan_directory(tmp_path, settings=None)["evidence"]["source_code"]]


def test_typescript_split_call(tmp_path):
    rows = _rows(tmp_path, "a.ts", "import { generateKeyPairSync } from 'crypto';\n"
                                   "const key = generateKeyPairSync(\n"
                                   "  'rsa',\n"
                                   "  { modulusLength: 1024 },\n"
                                   ");\n")
    assert (3, "RSA", "call") in rows


def test_java_split_call(tmp_path):
    rows = _rows(tmp_path, "A.java", "public class A {\n"
                                     "    static void m() throws Exception {\n"
                                     "        KeyPairGenerator kpg = KeyPairGenerator.getInstance(\n"
                                     "                \"RSA\");\n"
                                     "    }\n"
                                     "}\n")
    assert (4, "RSA", "call") in rows


def test_a_bare_string_elsewhere_is_not_a_call(tmp_path):
    rows = _rows(tmp_path, "a.ts", "const names = [\n  'rsa',\n];\nconst other = f(x,\n  'rsa',\n);\n")
    assert not any(kind == "call" for _, _, kind in rows)
