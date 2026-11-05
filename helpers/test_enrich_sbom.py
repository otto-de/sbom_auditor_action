#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the deps.dev lookup in enrich_sbom.py (Go modules, scoped npm packages)."""

import json
import logging
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import enrich_sbom
from enrich_sbom import (
    depsdev_coordinates,
    enrich_sbom_with_intelligent_resolution,
    is_internal_package,
)

logging.disable(logging.CRITICAL)


class TestDepsdevCoordinates(unittest.TestCase):

    def test_golang_x_module(self):
        self.assertEqual(depsdev_coordinates("pkg:golang/golang.org/x/sys@v0.48.0"),
                         ("go", "golang.org/x/sys", "v0.48.0"))

    def test_golang_github_module_with_major_version(self):
        self.assertEqual(depsdev_coordinates("pkg:golang/github.com/alecthomas/chroma/v2@v2.27.0"),
                         ("go", "github.com/alecthomas/chroma/v2", "v2.27.0"))

    def test_golang_pseudo_version(self):
        self.assertEqual(depsdev_coordinates("pkg:golang/github.com/cli/go-internal@v0.0.0-20241025142207-6c48bcd5ce24"),
                         ("go", "github.com/cli/go-internal", "v0.0.0-20241025142207-6c48bcd5ce24"))

    def test_scoped_npm_is_decoded(self):
        self.assertEqual(depsdev_coordinates("pkg:npm/%40babel/core@7.24.0"), ("npm", "@babel/core", "7.24.0"))

    def test_plain_npm(self):
        self.assertEqual(depsdev_coordinates("pkg:npm/lodash@4.17.21"), ("npm", "lodash", "4.17.21"))

    def test_maven(self):
        self.assertEqual(depsdev_coordinates("pkg:maven/org.slf4j/slf4j-api@2.0.9?type=jar"),
                         ("maven", "org.slf4j:slf4j-api", "2.0.9"))

    def test_pypi_without_version(self):
        self.assertEqual(depsdev_coordinates("pkg:pypi/requests"), ("pypi", "requests", None))

    def test_unsupported_ecosystems(self):
        for purl in ("pkg:githubactions/actions/checkout@4.*.*", "pkg:github/cli/cli@trunk",
                     "pkg:gem/rails@7.0.0", "not-a-purl", None):
            self.assertIsNone(depsdev_coordinates(purl), purl)


class TestIsInternalPackage(unittest.TestCase):

    def test_matches_purl(self):
        self.assertTrue(is_internal_package("pkg:golang/github.com/otto-de/foo@v1", None,
                                            [r"pkg:golang/github\.com/otto-de/.*"]))

    def test_matches_name(self):
        self.assertTrue(is_internal_package("pkg:npm/%40otto/ui@1", "@otto/ui", [r"@otto/.*"]))

    def test_no_patterns(self):
        self.assertFalse(is_internal_package("pkg:golang/github.com/otto-de/foo@v1", None, []))

    def test_invalid_pattern_is_ignored(self):
        self.assertFalse(is_internal_package("pkg:npm/a@1", "a", ["("]))


def _pkg(spdx_id, name, purl, license_concluded=None):
    pkg = {"SPDXID": spdx_id, "name": name,
           "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                             "referenceLocator": purl}]}
    if license_concluded:
        pkg["licenseConcluded"] = license_concluded
    return pkg


class FakeCache:
    def __init__(self, *args, **kwargs):
        self.store = {}

    def get_cache_stats(self):
        return {"valid_entries": 0, "expired_entries": 0}

    def get_cached_package_info(self, key):
        return self.store.get(key)

    def cache_package_info(self, key, data):
        self.store[key] = data

    def cleanup_expired_cache(self):
        return 0


class TestEnrichment(unittest.TestCase):

    DEPSDEV = {
        "https://api.deps.dev/v3alpha/systems/go/packages/github.com%2Fopencontainers%2Fimage-spec/versions/v1.1.1":
            {"licenses": ["Apache-2.0"]},
        "https://api.deps.dev/v3alpha/systems/go/packages/golang.org%2Fx%2Fsys/versions/v0.48.0":
            {"licenses": ["BSD-3-Clause"]},
        "https://api.deps.dev/v3alpha/systems/npm/packages/%40babel%2Fcore/versions/7.24.0":
            {"licenses": ["MIT"]},
        "https://api.deps.dev/v3alpha/systems/go/packages/github.com%2Fopencontainers%2Fgo-digest/versions/v1.0.0":
            {"licenses": ["Apache-2.0", "Apache-2.0", "CC-BY-SA-4.0"]},
    }

    def _fake_get(self, url, timeout=None):
        response = MagicMock()
        if url in self.DEPSDEV:
            response.status_code = 200
            response.json.return_value = self.DEPSDEV[url]
        else:
            response.status_code = 404
        self.requested.append(url)
        return response

    def _run(self, packages, internal_patterns=""):
        self.requested = []
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = os.path.join(tmp, "in.json"), os.path.join(tmp, "out.json")
            with open(src, "w") as f:
                json.dump({"SPDXID": "SPDXRef-DOCUMENT", "packages": packages}, f)
            with patch.object(enrich_sbom, "SBOMCacheManager", FakeCache), \
                    patch.object(enrich_sbom.requests, "get", side_effect=self._fake_get), \
                    patch.dict(os.environ, {"INTERNAL_PATTERNS": internal_patterns}), \
                    patch("builtins.print"):
                enrich_sbom_with_intelligent_resolution(src, dst, cache_ttl_hours=0, resolve_licenses=False)
            with open(dst) as f:
                return {p["name"]: p for p in json.load(f)["packages"]}

    def test_github_hosted_go_module_is_enriched(self):
        result = self._run([_pkg("a", "github.com/opencontainers/image-spec",
                                 "pkg:golang/github.com/opencontainers/image-spec@v1.1.1",
                                 "Apache-2.0 AND LicenseRef-scancode-dco-1.1 AND MIT")])
        pkg = result["github.com/opencontainers/image-spec"]
        self.assertEqual(pkg["licenseConcluded"], "Apache-2.0")
        self.assertEqual(pkg["enrichment"]["githubLicense"], "Apache-2.0 AND LicenseRef-scancode-dco-1.1 AND MIT")

    def test_golang_x_module_uses_go_system_and_full_name(self):
        result = self._run([_pkg("b", "golang.org/x/sys", "pkg:golang/golang.org/x/sys@v0.48.0",
                                 "BSD-3-Clause AND LicenseRef-scancode-google-patent-license-golang")])
        self.assertEqual(result["golang.org/x/sys"]["licenseConcluded"], "BSD-3-Clause")

    def test_scoped_npm_is_encoded_once(self):
        result = self._run([_pkg("c", "@babel/core", "pkg:npm/%40babel/core@7.24.0")])
        self.assertEqual(result["@babel/core"]["licenseConcluded"], "MIT")
        self.assertIn("https://api.deps.dev/v3alpha/systems/npm/packages/%40babel%2Fcore/versions/7.24.0",
                      self.requested)

    def test_duplicate_licenses_are_removed(self):
        result = self._run([_pkg("h", "github.com/opencontainers/go-digest",
                                 "pkg:golang/github.com/opencontainers/go-digest@v1.0.0")])
        self.assertEqual(result["github.com/opencontainers/go-digest"]["licenseConcluded"],
                         "Apache-2.0 AND CC-BY-SA-4.0")

    def test_github_license_kept_when_depsdev_has_no_data(self):
        result = self._run([_pkg("d", "github.com/x/unknown", "pkg:golang/github.com/x/unknown@v1.0.0", "MIT")])
        pkg = result["github.com/x/unknown"]
        self.assertEqual(pkg["licenseConcluded"], "MIT")

    def test_internal_packages_are_not_sent_to_depsdev(self):
        self._run([_pkg("e", "github.com/otto-de/secret", "pkg:golang/github.com/otto-de/secret@v1.0.0")],
                  internal_patterns=r"pkg:golang/github\.com/otto-de/.*")
        self.assertEqual(self.requested, [])

    def test_github_actions_and_repository_not_queried(self):
        self._run([_pkg("f", "actions/checkout", "pkg:githubactions/actions/checkout@4.*.*"),
                   _pkg("g", "com.github.cli/cli", "pkg:github/cli/cli@trunk")])
        self.assertEqual(self.requested, [])


if __name__ == "__main__":
    unittest.main()
