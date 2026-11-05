#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for sarif_report.py (license findings as code scanning alerts)."""

import json
import logging
import os
import tempfile
import unittest

from sarif_report import (
    RULE_DENIED,
    RULE_NEEDS_REVIEW,
    RULE_NO_LICENSE,
    ManifestLocator,
    build_sarif,
    parse_purl,
    write_sarif,
)

logging.disable(logging.CRITICAL)


def _finding(purl, license_expr, policy, package=None):
    return {"package": package or purl.split("/")[-1], "purl": purl, "license": license_expr, "policy": policy}


def _write(base, rel, content):
    path = os.path.join(base, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


class TestParsePurl(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(parse_purl("pkg:npm/lodash@4.17.21"), ("npm", "lodash", "4.17.21"))

    def test_scoped_npm(self):
        self.assertEqual(parse_purl("pkg:npm/%40babel/core@7.0.0"), ("npm", "@babel/core", "7.0.0"))

    def test_qualifiers_stripped(self):
        self.assertEqual(parse_purl("pkg:maven/org.slf4j/slf4j-api@2.0.9?type=jar"),
                         ("maven", "org.slf4j/slf4j-api", "2.0.9"))

    def test_golang(self):
        self.assertEqual(parse_purl("pkg:golang/golang.org/x/sys@v0.48.0"),
                         ("golang", "golang.org/x/sys", "v0.48.0"))

    def test_invalid(self):
        self.assertEqual(parse_purl("not-a-purl"), (None, None, None))
        self.assertEqual(parse_purl(None), (None, None, None))


class TestManifestLocator(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_finds_line_in_go_mod(self):
        _write(self.ws, "go.mod", "module x\n\nrequire (\n\tgolang.org/x/sys/unix v1\n\tgolang.org/x/sys v0.48.0\n)\n")
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:golang/golang.org/x/sys@v0.48.0"), ("go.mod", 5))

    def test_prefers_declaring_manifest_over_lockfile(self):
        _write(self.ws, "package-lock.json", '{\n "lodash": {}\n}\n')
        _write(self.ws, "package.json", '{\n  "dependencies": {\n    "lodash": "^4"\n  }\n}\n')
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:npm/lodash@4.17.21"), ("package.json", 3))

    def test_falls_back_to_lockfile_for_transitive(self):
        _write(self.ws, "package.json", '{\n  "dependencies": {"express": "^4"}\n}\n')
        _write(self.ws, "package-lock.json", '{\n "x": 1,\n "node_modules/qs": {}\n}\n')
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:npm/qs@6.0.0"), ("package-lock.json", 3))

    def test_maven_group_artifact(self):
        _write(self.ws, "build.gradle", "dependencies {\n  implementation 'org.slf4j:slf4j-api:2.0.9'\n}\n")
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:maven/org.slf4j/slf4j-api@2.0.9"),
                         ("build.gradle", 2))

    def test_maven_artifact_in_pom(self):
        _write(self.ws, "pom.xml", "<project>\n<dependency>\n<artifactId>slf4j-api</artifactId>\n</dependency>\n")
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:maven/org.slf4j/slf4j-api@2.0.9"), ("pom.xml", 3))

    def test_nested_manifest_and_skipped_dirs(self):
        _write(self.ws, "node_modules/foo/package.json", '"lodash"\n')
        _write(self.ws, "web/package.json", '{\n "lodash": "1"\n}\n')
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:npm/lodash@1.0.0"), ("web/package.json", 2))

    def test_github_actions_workflow(self):
        _write(self.ws, ".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:githubactions/actions/checkout@4.*.*"),
                         (".github/workflows/ci.yml", 4))

    def test_manifest_without_match_uses_first_line(self):
        _write(self.ws, "go.mod", "module x\n")
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:golang/github.com/a/b@v1"), ("go.mod", 1))

    def test_no_manifest(self):
        self.assertEqual(ManifestLocator(self.ws).locate("pkg:cargo/serde@1.0.0"), (None, None))

    def test_missing_workspace(self):
        self.assertEqual(ManifestLocator(None).locate("pkg:npm/a@1"), (None, None))


class TestBuildSarif(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = self.tmp.name
        _write(self.ws, "package.json", '{\n  "dependencies": {\n    "gpl-lib": "1",\n    "odd-lib": "1"\n  }\n}\n')

    def tearDown(self):
        self.tmp.cleanup()

    def _results(self, findings, **kwargs):
        sarif = build_sarif(findings, workspace=self.ws, **kwargs)
        return sarif, sarif["runs"][0]["results"]

    def test_structure(self):
        sarif, results = self._results([_finding("pkg:npm/gpl-lib@1.0.0", "AGPL-3.0-only", "deny")])
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("$schema", sarif)
        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "SBOM Auditor")
        for rule in driver["rules"]:
            self.assertTrue(rule["shortDescription"]["text"])
            self.assertTrue(rule["fullDescription"]["text"])
            self.assertTrue(rule["help"]["text"])
        self.assertEqual(len(results), 1)
        loc = results[0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "package.json")
        self.assertEqual(loc["region"]["startLine"], 3)

    def test_rule_and_level_mapping(self):
        _, results = self._results([
            _finding("pkg:npm/gpl-lib@1.0.0", "AGPL-3.0-only", "deny"),
            _finding("pkg:npm/odd-lib@1.0.0", "LicenseRef-odd", "needs-review"),
            _finding("pkg:npm/none-lib@1.0.0", "NO-LICENSE-FOUND", "needs-review"),
            _finding("pkg:npm/pinned@1.0.0", "GPL-2.0-only", "deny (package policy)"),
        ])
        by_pkg = {r["properties"]["package"]: r for r in results}
        self.assertEqual(by_pkg["gpl-lib"]["ruleId"], RULE_DENIED)
        self.assertEqual(by_pkg["gpl-lib"]["level"], "error")
        self.assertEqual(by_pkg["odd-lib"]["ruleId"], RULE_NEEDS_REVIEW)
        self.assertEqual(by_pkg["odd-lib"]["level"], "warning")
        self.assertEqual(by_pkg["none-lib"]["ruleId"], RULE_NO_LICENSE)
        self.assertEqual(by_pkg["pinned"]["ruleId"], RULE_DENIED)
        rules = [r["id"] for r in build_sarif([])["runs"][0]["tool"]["driver"]["rules"]]
        for result in results:
            self.assertEqual(rules[result["ruleIndex"]], result["ruleId"])

    def test_fingerprint_stable_across_versions(self):
        _, a = self._results([_finding("pkg:npm/gpl-lib@1.0.0", "AGPL-3.0-only", "deny")])
        _, b = self._results([_finding("pkg:npm/gpl-lib@2.0.0", "AGPL-3.0-only", "deny")])
        self.assertEqual(a[0]["partialFingerprints"], b[0]["partialFingerprints"])

    def test_fingerprint_changes_with_license(self):
        _, a = self._results([_finding("pkg:npm/gpl-lib@1.0.0", "AGPL-3.0-only", "deny")])
        _, b = self._results([_finding("pkg:npm/gpl-lib@2.0.0", "SSPL-1.0", "deny")])
        self.assertNotEqual(a[0]["partialFingerprints"], b[0]["partialFingerprints"])

    def test_multiple_versions_grouped(self):
        _, results = self._results([
            _finding("pkg:npm/gpl-lib@1.0.0", "AGPL-3.0-only", "deny"),
            _finding("pkg:npm/gpl-lib@2.0.0", "AGPL-3.0-only", "deny"),
        ])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["properties"]["versions"], ["1.0.0", "2.0.0"])
        self.assertIn("1.0.0, 2.0.0", results[0]["message"]["text"])

    def test_message_mentions_resolution(self):
        item = _finding("pkg:npm/gpl-lib@1.0.0", "AGPL-3.0-only", "deny")
        item["license_original"] = "GNU Affero GPL v3"
        _, results = self._results([item])
        self.assertIn("GNU Affero GPL v3 (resolved: AGPL-3.0-only)", results[0]["message"]["text"])

    def test_fallback_location_without_manifest(self):
        _, results = self._results([_finding("pkg:cargo/serde@1.0.0", "AGPL-3.0-only", "deny")])
        loc = results[0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "Cargo.toml")
        self.assertEqual(loc["region"]["startLine"], 1)

    def test_explicit_fallback_uri(self):
        _, results = self._results([_finding("pkg:cargo/serde@1.0.0", "AGPL-3.0-only", "deny")],
                                   fallback_uri="sbom.json")
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "sbom.json")

    def test_missing_purl(self):
        _, results = self._results([{"package": "thing@1.0", "purl": None, "license": "X", "policy": "needs-review"}])
        self.assertEqual(results[0]["properties"]["package"], "thing")
        self.assertTrue(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])

    def test_no_findings_produces_empty_run(self):
        _, results = self._results([])
        self.assertEqual(results, [])

    def test_write_sarif(self):
        out = os.path.join(self.ws, "out.sarif")
        write_sarif([_finding("pkg:npm/gpl-lib@1.0.0", "AGPL-3.0-only", "deny")], out, workspace=self.ws)
        with open(out) as f:
            self.assertEqual(len(json.load(f)["runs"][0]["results"]), 1)


if __name__ == "__main__":
    unittest.main()
