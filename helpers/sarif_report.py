#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Convert license audit results into a SARIF 2.1.0 file for GitHub code scanning.

Each denied or needs-review package becomes one code scanning alert. Alerts are
anchored to the manifest file (and line) that declares the package when it can be
found in the checked-out workspace.
"""

import hashlib
import json
import logging
import os
import re
import urllib.parse
from fnmatch import fnmatch

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "SBOM Auditor"
TOOL_URI = "https://github.com/otto-de/sbom_auditor_action"

RULE_DENIED = "license/denied"
RULE_NEEDS_REVIEW = "license/needs-review"
RULE_NO_LICENSE = "license/no-license-found"

RULES = [
    {
        "id": RULE_DENIED,
        "name": "DeniedLicense",
        "shortDescription": {"text": "Dependency uses a license that is denied by the license policy"},
        "fullDescription": {"text": "The license of this dependency is classified as 'deny' in the license "
                                    "policy. Using it may violate your organization's license compliance rules."},
        "defaultConfiguration": {"level": "error"},
        "help": {
            "text": "Replace the dependency, or, after legal approval, add a package policy exception "
                    "(packagePolicies) or adjust the license policy.",
            "markdown": "Replace the dependency, or, after legal approval, add a package policy exception "
                        "(`packagePolicies`) or adjust the license policy. See the "
                        f"[SBOM Auditor documentation]({TOOL_URI}#readme).",
        },
        "properties": {"tags": ["license", "compliance"], "precision": "high", "problem.severity": "error"},
    },
    {
        "id": RULE_NEEDS_REVIEW,
        "name": "LicenseNeedsReview",
        "shortDescription": {"text": "Dependency license needs review"},
        "fullDescription": {"text": "The license of this dependency is not covered by the license policy or is "
                                    "explicitly marked for review."},
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": "Check the license. If it is acceptable, add it to the license policy or add a package "
                    "policy exception; otherwise replace the dependency.",
            "markdown": "Check the license. If it is acceptable, add it to the license policy or add a package "
                        "policy exception (`packagePolicies`); otherwise replace the dependency. See the "
                        f"[SBOM Auditor documentation]({TOOL_URI}#readme).",
        },
        "properties": {"tags": ["license", "compliance"], "precision": "medium", "problem.severity": "warning"},
    },
    {
        "id": RULE_NO_LICENSE,
        "name": "NoLicenseFound",
        "shortDescription": {"text": "No license information found for dependency"},
        "fullDescription": {"text": "Neither the dependency graph nor the enrichment sources provided license "
                                    "information for this dependency."},
        "defaultConfiguration": {"level": "warning"},
        "help": {
            "text": "Determine the license manually. Without a license, the dependency may not be usable. "
                    "Add a package policy exception once the license has been clarified.",
            "markdown": "Determine the license manually. Without a license, the dependency may not be usable. "
                        "Add a package policy exception (`packagePolicies`) once the license has been clarified.",
        },
        "properties": {"tags": ["license", "compliance"], "precision": "medium", "problem.severity": "warning"},
    },
]

# Manifest files per PURL type, most specific (declaring) file first.
MANIFESTS_BY_TYPE = {
    "npm": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"],
    "maven": ["pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"],
    "pypi": ["requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg",
             "poetry.lock", "Pipfile.lock", "uv.lock"],
    "golang": ["go.mod", "go.sum"],
    "cargo": ["Cargo.toml", "Cargo.lock"],
    "nuget": ["*.csproj", "*.fsproj", "*.vbproj", "Directory.Packages.props", "packages.config",
              "packages.lock.json"],
    "gem": ["Gemfile", "*.gemspec", "Gemfile.lock"],
    "composer": ["composer.json", "composer.lock"],
    "hex": ["mix.exs", "mix.lock"],
    "pub": ["pubspec.yaml", "pubspec.lock"],
    "swift": ["Package.swift", "Package.resolved"],
    "githubactions": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
}
SKIP_DIRS = {".git", "node_modules", "vendor", "target", "build", "dist", ".venv", "venv", "__pycache__"}
MAX_FILE_BYTES = 5 * 1024 * 1024


def parse_purl(purl):
    """Return (type, versionless name, version) of a PURL; tolerant of malformed input."""
    if not purl or not purl.startswith("pkg:"):
        return None, None, None
    body = purl[4:].split("?")[0].split("#")[0].lstrip("/")
    version = None
    if "@" in body:
        body, version = body.rsplit("@", 1)
    purl_type, _, path = body.partition("/")
    return purl_type.lower(), urllib.parse.unquote(path), version


def _search_names(purl_type, name):
    """Names to look for in manifest files, most specific first."""
    if not name:
        return []
    candidates = [name]
    if purl_type == "maven" and "/" in name:
        group, artifact = name.split("/", 1)
        candidates = [f"{group}:{artifact}", artifact]
    elif "/" in name and purl_type not in ("golang", "npm"):
        candidates.append(name.rsplit("/", 1)[-1])
    return candidates


def _matches(rel_path, pattern):
    if "/" in pattern:
        return fnmatch(rel_path, pattern)
    return fnmatch(os.path.basename(rel_path), pattern)


class ManifestLocator:
    """Finds the manifest file and line that declares a package inside a workspace."""

    def __init__(self, workspace):
        self.workspace = os.path.abspath(workspace) if workspace else None
        self._files = None
        self._content_cache = {}

    def _all_files(self):
        if self._files is None:
            self._files = []
            if self.workspace and os.path.isdir(self.workspace):
                for root, dirs, files in os.walk(self.workspace):
                    dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                    for f in sorted(files):
                        rel = os.path.relpath(os.path.join(root, f), self.workspace).replace(os.sep, "/")
                        self._files.append(rel)
        return self._files

    def _lines(self, rel_path):
        if rel_path not in self._content_cache:
            full = os.path.join(self.workspace, rel_path)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    self._content_cache[rel_path] = []
                else:
                    with open(full, "r", encoding="utf-8", errors="replace") as f:
                        self._content_cache[rel_path] = f.read().splitlines()
            except OSError:
                self._content_cache[rel_path] = []
        return self._content_cache[rel_path]

    def candidates(self, purl_type):
        patterns = MANIFESTS_BY_TYPE.get(purl_type, [])
        files = self._all_files()
        ordered = []
        for pattern in patterns:
            for rel in files:
                if rel not in ordered and _matches(rel, pattern):
                    ordered.append(rel)
        return ordered

    def locate(self, purl):
        """Return (relative path, line) for the package, or (None, None) if no manifest exists."""
        purl_type, name, _ = parse_purl(purl)
        manifests = self.candidates(purl_type)
        for search in _search_names(purl_type, name):
            needle = re.compile(r"(?<![\w.\-@])" + re.escape(search) + r"(?![\w\-/])", re.IGNORECASE)
            for rel in manifests:
                for index, line in enumerate(self._lines(rel), start=1):
                    if needle.search(line):
                        return rel, index
        if manifests:
            return manifests[0], 1
        return None, None


def _rule_for(item):
    policy = item.get("policy", "").split(" (")[0]
    if policy == "deny":
        return RULE_DENIED
    if item.get("license") == "NO-LICENSE-FOUND":
        return RULE_NO_LICENSE
    return RULE_NEEDS_REVIEW


def _fingerprint(rule_id, purl_type, name, license_expr):
    key = f"{rule_id}|{purl_type}|{(name or '').lower()}|{license_expr}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32] + ":1"


def build_sarif(findings, workspace=None, fallback_uri=None):
    """Build a SARIF log from denied / needs-review audit results.

    findings: iterable of audit result dicts (package, purl, license, policy, ...).
    workspace: checkout directory used to locate manifest files.
    fallback_uri: file used as location when no manifest is found.
    """
    locator = ManifestLocator(workspace)
    grouped = {}
    for item in findings:
        purl = item.get("purl") or ""
        purl_type, name, version = parse_purl(purl)
        if not name:
            name = (item.get("package") or "unknown").rsplit("@", 1)[0]
            version = None
        license_expr = item.get("license") or "N/A"
        rule_id = _rule_for(item)
        key = (rule_id, purl_type, name.lower(), license_expr)
        entry = grouped.setdefault(key, {"item": item, "purl_type": purl_type, "name": name,
                                         "license": license_expr, "rule": rule_id,
                                         "versions": [], "purls": []})
        if version and version not in entry["versions"]:
            entry["versions"].append(version)
        if purl and purl not in entry["purls"]:
            entry["purls"].append(purl)

    rule_index = {rule["id"]: i for i, rule in enumerate(RULES)}
    results = []
    for entry in grouped.values():
        item = entry["item"]
        purl = entry["purls"][0] if entry["purls"] else None
        uri, line = locator.locate(purl) if purl else (None, None)
        if not uri:
            uri, line = fallback_uri or _default_fallback(entry["purl_type"]), 1

        versions = ", ".join(entry["versions"]) or "unknown version"
        policy = item.get("policy", "needs-review")
        license_display = entry["license"]
        if item.get("license_original") and item.get("license_original") != entry["license"]:
            license_display = f"{item['license_original']} (resolved: {entry['license']})"

        if entry["rule"] == RULE_DENIED:
            headline = f"Denied license {license_display} in dependency {entry['name']} ({versions})."
        elif entry["rule"] == RULE_NO_LICENSE:
            headline = f"No license found for dependency {entry['name']} ({versions})."
        else:
            headline = f"License {license_display} of dependency {entry['name']} ({versions}) needs review."
        message = f"{headline} Policy: {policy}. PURL: {', '.join(entry['purls']) or 'n/a'}"

        results.append({
            "ruleId": entry["rule"],
            "ruleIndex": rule_index[entry["rule"]],
            "level": RULES[rule_index[entry["rule"]]]["defaultConfiguration"]["level"],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": _fingerprint(entry["rule"], entry["purl_type"],
                                                        entry["name"], entry["license"]),
            },
            "properties": {
                "package": entry["name"],
                "versions": entry["versions"],
                "purls": entry["purls"],
                "license": entry["license"],
                "policy": policy,
            },
        })

    results.sort(key=lambda r: (r["ruleIndex"], r["properties"]["package"]))
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "informationUri": TOOL_URI, "rules": RULES}},
            "results": results,
        }],
    }


def _default_fallback(purl_type):
    patterns = MANIFESTS_BY_TYPE.get(purl_type) or ["sbom.json"]
    first = patterns[0]
    return first if "*" not in first else "sbom.json"


def write_sarif(findings, output_path, workspace=None, fallback_uri=None):
    sarif = build_sarif(findings, workspace=workspace, fallback_uri=fallback_uri)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    logging.info("📄 SARIF report with %d alert(s) written to %s",
                 len(sarif["runs"][0]["results"]), output_path)
    return sarif
