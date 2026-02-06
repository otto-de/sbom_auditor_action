#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for audit_licenses.py core functionality."""

import unittest
import json
import tempfile
import os
import logging

from audit_licenses import (
    extract_components,
    get_purl,
    find_license_policy,
    audit_component_with_resolution
)

# Suppress logging during tests
logging.disable(logging.CRITICAL)


class TestExtractComponents(unittest.TestCase):
    """Tests for extract_components function."""
    
    def test_extract_from_packages_key(self):
        """SPDX format uses 'packages' key."""
        sbom = {
            'packages': [
                {'name': 'package1', 'versionInfo': '1.0.0'},
                {'name': 'package2', 'versionInfo': '2.0.0'}
            ]
        }
        result = extract_components(sbom)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['name'], 'package1')
    
    def test_extract_from_components_key(self):
        """CycloneDX format uses 'components' key."""
        sbom = {
            'components': [
                {'name': 'component1', 'version': '1.0.0'}
            ]
        }
        result = extract_components(sbom)
        self.assertEqual(len(result), 1)
    
    def test_extract_from_empty_sbom(self):
        """Empty SBOM returns empty list."""
        result = extract_components({})
        self.assertEqual(result, [])
    
    def test_packages_key_takes_precedence(self):
        """If both keys exist, 'packages' takes precedence."""
        sbom = {
            'packages': [{'name': 'pkg'}],
            'components': [{'name': 'comp'}]
        }
        result = extract_components(sbom)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'pkg')


class TestGetPurl(unittest.TestCase):
    """Tests for get_purl function."""
    
    def test_purl_from_external_refs(self):
        """Extract PURL from externalRefs."""
        component = {
            'name': 'test',
            'externalRefs': [
                {'referenceType': 'purl', 'referenceLocator': 'pkg:maven/org/test@1.0.0'}
            ]
        }
        result = get_purl(component)
        self.assertEqual(result, 'pkg:maven/org/test@1.0.0')
    
    def test_purl_not_found_returns_default(self):
        """Missing PURL returns sentinel value."""
        component = {'name': 'test'}
        result = get_purl(component)
        self.assertEqual(result, 'purl-not-found')
    
    def test_ignores_non_purl_refs(self):
        """Non-PURL references should be ignored."""
        component = {
            'externalRefs': [
                {'referenceType': 'cpe', 'referenceLocator': 'cpe:2.3:a:vendor:product'},
                {'referenceType': 'purl', 'referenceLocator': 'pkg:npm/test@1.0.0'}
            ]
        }
        result = get_purl(component)
        self.assertEqual(result, 'pkg:npm/test@1.0.0')
    
    def test_empty_external_refs(self):
        """Empty externalRefs returns sentinel."""
        component = {'externalRefs': []}
        result = get_purl(component)
        self.assertEqual(result, 'purl-not-found')


class TestFindLicensePolicy(unittest.TestCase):
    """Tests for find_license_policy function."""
    
    def setUp(self):
        self.policies = [
            {'id': 'MIT', 'usagePolicy': 'allow'},
            {'id': 'Apache-2.0', 'usagePolicy': 'allow'},
            {'id': 'GPL-3.0-only', 'usagePolicy': 'deny'},
            {'id': 'LGPL-2.1-only', 'usagePolicy': 'needs-review'}
        ]
        self.aliases = {
            'mit license': 'MIT',
            'apache license 2.0': 'Apache-2.0'
        }
    
    def test_exact_match(self):
        """Exact license ID match."""
        result = find_license_policy('MIT', self.policies)
        self.assertEqual(result, 'allow')
    
    def test_case_insensitive(self):
        """License IDs should be case-insensitive."""
        result = find_license_policy('mit', self.policies)
        self.assertEqual(result, 'allow')
    
    def test_deny_policy(self):
        """Denied license returns 'deny'."""
        result = find_license_policy('GPL-3.0-only', self.policies)
        self.assertEqual(result, 'deny')
    
    def test_not_found_returns_needs_review(self):
        """Unknown license returns 'needs-review' (not None)."""
        result = find_license_policy('Unknown-License', self.policies)
        # The function uses SPDX parser which returns 'needs-review' for unknown licenses
        self.assertEqual(result, 'needs-review')
    
    def test_spdx_expression_and(self):
        """AND expression - all must be allowed."""
        result = find_license_policy('MIT AND Apache-2.0', self.policies)
        self.assertEqual(result, 'allow')
    
    def test_spdx_expression_and_with_denied(self):
        """AND expression with denied license."""
        result = find_license_policy('MIT AND GPL-3.0-only', self.policies)
        self.assertEqual(result, 'deny')
    
    def test_spdx_expression_or(self):
        """OR expression - any allowed suffices."""
        result = find_license_policy('MIT OR GPL-3.0-only', self.policies)
        self.assertEqual(result, 'allow')
    
    def test_alias_resolution(self):
        """License aliases should be resolved."""
        result = find_license_policy('MIT License', self.policies, self.aliases)
        self.assertEqual(result, 'allow')


class TestAuditComponentWithResolution(unittest.TestCase):
    """Tests for audit_component_with_resolution function."""
    
    def setUp(self):
        self.policies = [
            {'id': 'MIT', 'usagePolicy': 'allow'},
            {'id': 'Apache-2.0', 'usagePolicy': 'allow'},
            {'id': 'GPL-3.0-only', 'usagePolicy': 'deny'}
        ]
        self.package_policies = []
    
    def test_allowed_license(self):
        """Component with allowed license."""
        component = {
            'name': 'test-package',
            'versionInfo': '1.0.0',
            'licenseConcluded': 'MIT',
            'externalRefs': [
                {'referenceType': 'purl', 'referenceLocator': 'pkg:npm/test-package@1.0.0'}
            ]
        }
        
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies
        )
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['policy'], 'allow')
        self.assertEqual(results[0]['license'], 'MIT')
    
    def test_denied_license(self):
        """Component with denied license."""
        component = {
            'name': 'gpl-package',
            'versionInfo': '1.0.0',
            'licenseConcluded': 'GPL-3.0-only',
            'externalRefs': [
                {'referenceType': 'purl', 'referenceLocator': 'pkg:npm/gpl-package@1.0.0'}
            ]
        }
        
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies
        )
        
        self.assertEqual(results[0]['policy'], 'deny')
    
    def test_no_license_needs_review(self):
        """Component without license needs review."""
        component = {
            'name': 'no-license-pkg',
            'versionInfo': '1.0.0',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl', 'referenceLocator': 'pkg:npm/no-license-pkg@1.0.0'}
            ]
        }
        
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies
        )
        
        self.assertEqual(results[0]['policy'], 'needs-review')
        self.assertEqual(results[0]['license'], 'NO-LICENSE-FOUND')
    
    def test_github_action_allowed_without_license(self):
        """GitHub Actions without license should be allowed."""
        component = {
            'name': 'actions/checkout',
            'versionInfo': 'v3',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl', 'referenceLocator': 'pkg:githubactions/actions/checkout@v3'}
            ]
        }
        
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies
        )
        
        self.assertEqual(results[0]['policy'], 'allow')
    
    def test_package_policy_override(self):
        """Package-specific policy overrides license policy."""
        component = {
            'name': 'special-package',
            'versionInfo': '1.0.0',
            'licenseConcluded': 'GPL-3.0-only',  # Would be denied
            'externalRefs': [
                {'referenceType': 'purl', 'referenceLocator': 'pkg:npm/special-package@1.0.0'}
            ]
        }
        
        package_policies = [
            {'purl': 'pkg:npm/special-package', 'usagePolicy': 'allow', 'reason': 'approved exception'}
        ]
        
        results = audit_component_with_resolution(
            component, self.policies, package_policies
        )
        
        self.assertIn('allow', results[0]['policy'])
    
    def test_internal_dependency_skipped(self):
        """Internal dependencies should be skipped."""
        component = {
            'name': 'internal-lib',
            'versionInfo': '1.0.0',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl', 'referenceLocator': 'pkg:maven/com.company.internal/lib@1.0.0'}
            ]
        }
        
        internal_patterns = [r'pkg:maven/com\.company\.internal/.*']
        
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            internal_dependency_patterns=internal_patterns
        )
        
        self.assertEqual(results[0]['policy'], 'internal')
    
    def test_unknown_license_needs_review(self):
        """Unknown license needs review."""
        component = {
            'name': 'weird-license-pkg',
            'versionInfo': '1.0.0',
            'licenseConcluded': 'Proprietary-Unknown-License',
            'externalRefs': [
                {'referenceType': 'purl', 'referenceLocator': 'pkg:npm/weird-pkg@1.0.0'}
            ]
        }
        
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies
        )
        
        self.assertEqual(results[0]['policy'], 'needs-review')


class TestLoadJsonFile(unittest.TestCase):
    """Tests for load_json_file function."""
    
    def test_load_valid_json(self):
        """Valid JSON file should load correctly."""
        from audit_licenses import load_json_file
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'test': 'data'}, f)
            temp_path = f.name
        
        try:
            result = load_json_file(temp_path, "Test")
            self.assertEqual(result, {'test': 'data'})
        finally:
            os.unlink(temp_path)
    
    def test_load_json_with_bom(self):
        """JSON file with UTF-8 BOM should load correctly."""
        from audit_licenses import load_json_file
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.json', delete=False) as f:
            # Write UTF-8 BOM followed by JSON
            f.write(b'\xef\xbb\xbf{"test": "bom"}')
            temp_path = f.name
        
        try:
            result = load_json_file(temp_path, "Test")
            self.assertEqual(result, {'test': 'bom'})
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
