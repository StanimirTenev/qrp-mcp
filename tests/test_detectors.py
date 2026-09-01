from pathlib import Path

from qrp_mcp.detectors import is_ci_config_file, is_iac_file, scan_iac_file, scan_repo


def test_scan_repo_detects_source_algorithms_and_signing_commands(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "crypto.py").write_text(
        "from Crypto.PublicKey import RSA\n"
        "import hashlib\n"
        "digest = hashlib.md5(b'x').hexdigest()\n",
        encoding="utf-8",
    )
    (tmp_path / "app" / "hash.go").write_text(
        'import "crypto/sha1"\n',
        encoding="utf-8",
    )

    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "release.yml").write_text(
        "steps:\n"
        "  - run: gpg --detach-sign artifact.tar.gz\n"
        "  - run: cosign sign my-image:latest\n",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert result["files_scanned"] == {"source": 2, "ci_config": 1, "iac": 0, "config": 0}
    algorithms = {f["algorithm"] for f in result["source_code_findings"]}
    assert algorithms == {"RSA", "MD5", "SHA1"}

    command_types = {f["command_type"] for f in result["ci_pipeline_findings"]}
    assert command_types == {"gpg_sign", "cosign_sign"}


def test_scan_repo_excludes_vendor_and_git_dirs(tmp_path: Path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text("from Crypto.PublicKey import RSA\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config.py").write_text("hashlib.md5\n", encoding="utf-8")

    result = scan_repo(tmp_path)

    assert result["files_scanned"] == {"source": 0, "ci_config": 0, "iac": 0, "config": 0}
    assert result["source_code_findings"] == []


def test_scan_repo_no_findings_in_clean_repo(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('hello world')\n", encoding="utf-8")

    result = scan_repo(tmp_path)

    assert result["files_scanned"] == {"source": 1, "ci_config": 0, "iac": 0, "config": 0}
    assert result["source_code_findings"] == []
    assert result["ci_pipeline_findings"] == []
    assert result["detected_algorithms"] == []


def test_is_iac_file_recognizes_terraform_and_kubernetes_manifests(tmp_path: Path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text('resource "tls_private_key" "example" {\n  algorithm = "RSA"\n}\n', encoding="utf-8")

    k8s_manifest = tmp_path / "secret.yaml"
    k8s_manifest.write_text("apiVersion: v1\nkind: Secret\nmetadata:\n  name: tls-secret\n", encoding="utf-8")

    plain_yaml = tmp_path / "config.yaml"
    plain_yaml.write_text("some_key: some_value\nother_key: other_value\n", encoding="utf-8")

    assert is_iac_file(tf_file, tmp_path) is True
    assert is_iac_file(k8s_manifest, tmp_path) is True
    assert is_iac_file(plain_yaml, tmp_path) is False


def test_scan_iac_file_detects_algorithm_and_embedded_key(tmp_path: Path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        'resource "tls_private_key" "example" {\n'
        '  algorithm = "RSA"\n'
        "}\n"
        'variable "fallback_key" {\n'
        '  default = "-----BEGIN RSA PRIVATE KEY-----\\nMIIB...\\n-----END RSA PRIVATE KEY-----"\n'
        "}\n",
        encoding="utf-8",
    )

    algorithm_findings, embedded_key_findings = scan_iac_file(tf_file, "main.tf")

    assert [f["algorithm"] for f in algorithm_findings] == ["RSA"]
    assert len(embedded_key_findings) == 1
    assert embedded_key_findings[0]["path"] == "main.tf"


def test_scan_repo_detects_iac_findings_end_to_end(tmp_path: Path):
    (tmp_path / "main.tf").write_text(
        'resource "tls_private_key" "example" {\n  algorithm = "ECDSA"\n}\n', encoding="utf-8"
    )
    k8s_dir = tmp_path / "k8s"
    k8s_dir.mkdir()
    (k8s_dir / "tls-secret.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Secret\n"
        "type: kubernetes.io/tls\n"
        "data:\n"
        "  tls.key: |\n"
        "    -----BEGIN PRIVATE KEY-----\n"
        "    MIIEvQ...\n"
        "    -----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    result = scan_repo(tmp_path)

    assert result["files_scanned"] == {"source": 0, "ci_config": 0, "iac": 2, "config": 0}
    assert {f["algorithm"] for f in result["iac_findings"]} == {"ECDSA"}
    assert len(result["embedded_key_findings"]) == 1
    assert result["detected_algorithms"] == ["ECDSA"]


def test_is_ci_config_file_recognizes_known_paths(tmp_path: Path):
    gh = tmp_path / ".github" / "workflows" / "ci.yml"
    gh.parent.mkdir(parents=True)
    gh.write_text("", encoding="utf-8")
    gitlab = tmp_path / ".gitlab-ci.yml"
    gitlab.write_text("", encoding="utf-8")
    regular = tmp_path / "main.py"
    regular.write_text("", encoding="utf-8")

    assert is_ci_config_file(gh, tmp_path) is True
    assert is_ci_config_file(gitlab, tmp_path) is True
    assert is_ci_config_file(regular, tmp_path) is False


def test_a_file_that_cannot_be_read_is_reported_not_counted_as_clean(tmp_path: Path):
    """A failed read must not look like a pass: it leaves the scanned count and shows up
    as unreadable, so "0 findings" can be checked against what was actually opened."""
    readable = tmp_path / "wallet.py"
    readable.write_text("from ecdsa import SECP256k1\n", encoding="utf-8")
    blocked = tmp_path / "secrets_helper.py"
    blocked.write_text("from ecdsa import SECP256k1\n", encoding="utf-8")

    before = scan_repo(tmp_path)
    assert before["files_scanned"]["source"] == 2
    assert before["unreadable_files"] == []

    blocked.chmod(0o000)
    try:
        after = scan_repo(tmp_path)
    finally:
        blocked.chmod(0o644)

    assert after["unreadable_files"] == ["secrets_helper.py"]
    assert after["files_scanned"]["source"] == 1, "an unopened file must not count as scanned"
