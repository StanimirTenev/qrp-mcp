"""Dependency manifests that were "type not claimed" on 0.41.0 (ZA-OPRAVYANE row 313; fixtures
L1/f11-manifests). A Gradle script of any name, a gem's `.gemspec`, a CocoaPods `.podspec`
and SwiftPM's Package.resolved name crypto packages as Gemfile and build.gradle do.

Formats: RubyGems `add_dependency` / `add_runtime_dependency`
(https://guides.rubygems.org/specification-reference/#add_runtime_dependency); CocoaPods
`spec.dependency` (https://guides.cocoapods.org/syntax/podspec.html#dependency); SwiftPM's
resolved file lists `pins` with `identity` (v2) or `object.pins[].package` (v1). JOSESwift's
families from its README (https://github.com/airsidemobile/JOSESwift): RS*/PS*, ES*,
RSA1_5/RSA-OAEP and ECDH-ES are supported.
"""

import json

import pytest

from qrp_mcp.scan import scan_directory


def _declared(result):
    return {(d["path"], d["package"]) for d in result["evidence"]["dependencies"]}


@pytest.mark.parametrize("name", ["samples-demo.gradle", "settings.gradle", "lib.gradle.kts"])
def test_gradle_script_of_any_name(tmp_path, name):
    (tmp_path / name).write_text('dependencies {\n  implementation("org.bouncycastle:bcprov-jdk18on:1.78")\n}\n')
    result = scan_directory(tmp_path)
    assert name in result["files_read"]
    assert (name, "bcprov-jdk18on") in _declared(result)


def test_gemspec(tmp_path):
    (tmp_path / "ruby-lib.gemspec").write_text(
        'Gem::Specification.new do |spec|\n  spec.name = "ruby-lib"\n'
        '  spec.add_dependency "jwt", "~> 2.8"\n  spec.add_runtime_dependency("rbnacl", "~> 7.1")\n'
        '  # spec.add_dependency "net-ssh"\nend\n')
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["ruby-lib.gemspec"]
    assert _declared(result) == {("ruby-lib.gemspec", "jwt"), ("ruby-lib.gemspec", "rbnacl")}


def test_podspec(tmp_path):
    (tmp_path / "Lib.podspec").write_text(
        "Pod::Spec.new do |s|\n  s.name = 'Lib'\n  s.dependency 'JOSESwift', '~> 2.4'\n  s.ios.dependency 'JOSESwift/Core'\nend\n")
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["Lib.podspec"]
    dep, ios = result["evidence"]["dependencies"]
    assert (ios["package"], ios["line"]) == ("JOSESwift", 4)
    assert (dep["package"], dep["line"], dep["families"]) == ("JOSESwift", 3, ["RSA", "ECDSA", "ECDH"])


@pytest.mark.parametrize("data", [
    {"pins": [{"identity": "joseswift", "location": "https://github.com/airsidemobile/JOSESwift.git",
               "state": {"version": "2.4.0"}}], "version": 2},
    {"object": {"pins": [{"package": "JOSESwift", "repositoryURL": "https://github.com/x/y",
                          "state": {"version": "2.4.0"}}]}, "version": 1},
])
def test_package_resolved(tmp_path, data):
    (tmp_path / "Package.resolved").write_text(json.dumps(data, indent=2))
    result = scan_directory(tmp_path)
    assert result["files_read"] == ["Package.resolved"]
    assert [d["package"] for d in result["evidence"]["dependencies"]] == ["joseswift"]
