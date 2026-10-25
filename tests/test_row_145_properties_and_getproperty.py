"""Algorithms named in Java .properties and read with getProperty (ZA-OPRAVYANE rows 145, 149).

OWASP Benchmark 1.2 (hash, CWE-328) scored 0.690, and all 40 misses were one shape: the
code reads `getProperty("hashAlg1", "SHA512")` and `benchmark.properties` sets
`hashAlg1=MD5`. The literal in the code is safe; the algorithm that runs is in the file.

* A property whose key names an algorithm setting and whose value is an algorithm is a
  finding on its own line.
* `getProperty("key", ...)` whose key a .properties file in the tree sets to an algorithm
  is a finding on the line that reads it, naming the file and line. The tree-wide join is
  by key; a key set to different values in different files is not guessed between.
* The default literal is what runs only when no file in the tree sets the key: then
  `getProperty("x", "MD5")` and `"AES/ECB/PKCS5Padding"` are read (row 149). Where the key
  is set, the default is not read: OWASP's cryptoAlg2 cases default to AES/ECB and are
  overridden to AES/CCM, and reading the default would put AES-ECB on 27 safe cases.
"""

from qrp_mcp.scan import scan_directory

JAVA = """import java.util.Properties;
class H {
  void f(Properties props) throws Exception {
    String a1 = props.getProperty("hashAlg1", "SHA512");
    String a2 = props.getProperty("cryptoAlg2", "AES/ECB/PKCS5Padding");
    String a3 = props.getProperty("hashAlg3", "MD5");
    String a4 = props.getProperty("cryptoAlg3", "AES/ECB/PKCS5Padding");
    String a5 = props.getProperty("hashAlg2", "SHA5");
    String a6 = props.getProperty("conflicted");
  }
}
"""

PROPS = """# algorithms
cryptoAlg2=AES/CCM/NoPadding
hashAlg1=MD5
hashAlg2=SHA-256
conflicted=MD5
greeting=RSA
"""


def _rows(result, path):
    return {(e["line"], e["algorithm"]) for e in result["evidence"]["source_code"]
            if e["path"] == path and e.get("evidence_kind") not in ("ban", "comment")}


def test_properties_values_and_getproperty_join(tmp_path):
    (tmp_path / "src" / "main" / "java").mkdir(parents=True)
    (tmp_path / "src" / "main" / "resources").mkdir(parents=True)
    (tmp_path / "src" / "test" / "resources").mkdir(parents=True)
    (tmp_path / "src" / "main" / "java" / "H.java").write_text(JAVA)
    (tmp_path / "src" / "main" / "resources" / "benchmark.properties").write_text(PROPS)
    (tmp_path / "src" / "test" / "resources" / "other.properties").write_text("conflicted=SHA1\n")
    result = scan_directory(str(tmp_path))

    java = _rows(result, "src/main/java/H.java")
    assert (4, "MD5") in java                     # resolved through benchmark.properties:3
    assert not any(line == 5 for line, _ in java)  # set to AES/CCM: the default is not read
    assert (6, "MD5") in java                     # unresolved: the default runs
    assert (7, "AES-ECB") in java                 # unresolved: the default runs
    assert not any(line in (8, 9) for line, _ in java)  # SHA-256; conflicting values

    props = _rows(result, "src/main/resources/benchmark.properties")
    assert (3, "MD5") in props
    assert not any(line == 6 for line, _ in props)  # `greeting` is not an algorithm setting

    said = next(e for e in result["evidence"]["source_code"]
                if e["path"] == "src/main/java/H.java" and e["line"] == 4)
    assert "hashAlg1" in said["description"]
    assert "benchmark.properties:3" in said["description"]


def test_a_disabled_algorithms_property_is_a_ban(tmp_path):
    (tmp_path / "java.security").write_text("")
    (tmp_path / "sec.properties").write_text("jdk.certpath.disabledAlgorithm=MD5\n")
    result = scan_directory(str(tmp_path))
    rows = [e for e in result["evidence"]["source_code"] if e["path"] == "sec.properties"]
    assert all(e["evidence_kind"] == "ban" for e in rows)
