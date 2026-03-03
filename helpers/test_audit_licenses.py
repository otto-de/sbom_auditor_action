#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for audit_licenses.py core functionality."""

import unittest
import json
import tempfile
import os
import logging
from unittest.mock import patch

from audit_licenses import (
    extract_components,
    get_purl,
    find_license_policy,
    audit_component_with_resolution
)
from license_resolver import LicenseResolver

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


class TestIssue19NoLicenseForKnownPackages(unittest.TestCase):
    """Issue #19: Well-known Maven packages flagged as NO-LICENSE-FOUND.

    With the fix, the audit phase attempts a Maven POM fallback before
    returning NO-LICENSE-FOUND for Maven packages when a license_resolver
    is available.
    """

    def setUp(self):
        self.policies = [
            {'id': 'MIT', 'usagePolicy': 'allow'},
            {'id': 'Apache-2.0', 'usagePolicy': 'allow'},
            {'id': 'EPL-2.0', 'usagePolicy': 'allow'},
        ]
        self.package_policies = []
        # Patch SPDX data fetching to avoid live network calls during tests
        spdx_licenses = {
            'MIT': {'name': 'MIT License', 'id': 'MIT', 'deprecated': False, 'osi_approved': True, 'see_also': []},
            'Apache-2.0': {'name': 'Apache License 2.0', 'id': 'Apache-2.0', 'deprecated': False, 'osi_approved': True, 'see_also': []},
            'EPL-2.0': {'name': 'Eclipse Public License 2.0', 'id': 'EPL-2.0', 'deprecated': False, 'osi_approved': True, 'see_also': []},
        }
        self._spdx_patcher = patch.object(
            LicenseResolver,
            '_fetch_spdx_data',
            return_value=(spdx_licenses, {}),
        )
        self._spdx_patcher.start()
        self.license_resolver = LicenseResolver()

    def tearDown(self):
        self._spdx_patcher.stop()

    @patch('audit_licenses.get_maven_license_from_pom')
    def test_spring_webmvc_resolved_via_pom_fallback(self, mock_pom):
        """FIX: spring-webmvc NOASSERTION → Apache-2.0 via POM fallback."""
        mock_pom.return_value = "Apache License, Version 2.0"
        component = {
            'name': 'spring-webmvc',
            'versionInfo': '6.1.14',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/org.springframework/spring-webmvc@6.1.14'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=self.license_resolver
        )
        self.assertEqual(results[0]['license'], 'Apache-2.0')
        self.assertEqual(results[0]['policy'], 'allow')
        mock_pom.assert_called_once_with('org.springframework:spring-webmvc', '6.1.14')

    @patch('audit_licenses.get_maven_license_from_pom')
    def test_slf4j_api_resolved_via_pom_fallback(self, mock_pom):
        """FIX: slf4j-api NOASSERTION → MIT via POM fallback."""
        mock_pom.return_value = "MIT License"
        component = {
            'name': 'slf4j-api',
            'versionInfo': '2.0.16',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/org.slf4j/slf4j-api@2.0.16'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=self.license_resolver
        )
        self.assertEqual(results[0]['license'], 'MIT')
        self.assertEqual(results[0]['policy'], 'allow')

    @patch('audit_licenses.get_maven_license_from_pom')
    def test_spring_context_no_license_field_resolved(self, mock_pom):
        """FIX: Missing licenseConcluded → resolved via POM fallback."""
        mock_pom.return_value = "The Apache Software License, Version 2.0"
        component = {
            'name': 'spring-context',
            'versionInfo': '6.1.14',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/org.springframework/spring-context@6.1.14'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=self.license_resolver
        )
        self.assertEqual(results[0]['license'], 'Apache-2.0')
        self.assertEqual(results[0]['policy'], 'allow')

    @patch('audit_licenses.get_maven_license_from_pom')
    def test_pom_fallback_returns_none_still_no_license(self, mock_pom):
        """When POM fallback also fails, still returns NO-LICENSE-FOUND."""
        mock_pom.return_value = None
        component = {
            'name': 'mystery-lib',
            'versionInfo': '1.0.0',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/com.example/mystery-lib@1.0.0'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=self.license_resolver
        )
        self.assertEqual(results[0]['license'], 'NO-LICENSE-FOUND')
        self.assertEqual(results[0]['policy'], 'needs-review')

    @patch('audit_licenses.get_maven_license_from_pom')
    def test_pom_fallback_unresolved_uses_original_license(self, mock_pom):
        """When POM returns a license but resolver can't normalize it, use original string."""
        mock_pom.return_value = "Some Exotic License v42"
        component = {
            'name': 'exotic-lib',
            'versionInfo': '1.0.0',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/com.example/exotic-lib@1.0.0'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=self.license_resolver
        )
        # Should use the original POM license, not NO-LICENSE-FOUND
        self.assertEqual(results[0]['license'], 'Some Exotic License v42')
        self.assertEqual(results[0]['policy'], 'needs-review')
        self.assertEqual(results[0]['resolution']['source'], 'maven_pom_fallback')
        self.assertEqual(results[0]['resolution']['original'], 'Some Exotic License v42')

    def test_npm_package_no_pom_fallback(self):
        """Non-Maven packages should NOT trigger POM fallback."""
        component = {
            'name': 'lodash',
            'versionInfo': '4.17.21',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:npm/lodash@4.17.21'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=self.license_resolver
        )
        # npm packages have no POM fallback, should remain NO-LICENSE-FOUND
        self.assertEqual(results[0]['license'], 'NO-LICENSE-FOUND')
        self.assertEqual(results[0]['policy'], 'needs-review')

    def test_no_resolver_no_pom_fallback(self):
        """Without license_resolver, no POM fallback is attempted."""
        component = {
            'name': 'spring-webmvc',
            'versionInfo': '6.1.14',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/org.springframework/spring-webmvc@6.1.14'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=None
        )
        self.assertEqual(results[0]['license'], 'NO-LICENSE-FOUND')
        self.assertEqual(results[0]['policy'], 'needs-review')

    def test_known_package_with_license_works_fine(self):
        """CONTROL: Package WITH existing license works correctly."""
        component = {
            'name': 'jackson-core',
            'versionInfo': '2.18.2',
            'licenseConcluded': 'Apache-2.0',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/com.fasterxml.jackson.core/jackson-core@2.18.2'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies
        )
        self.assertEqual(results[0]['license'], 'Apache-2.0')
        self.assertEqual(results[0]['policy'], 'allow')

    def test_package_policy_workaround_works(self):
        """WORKAROUND: Package policy override correctly allows the package."""
        component = {
            'name': 'spring-webmvc',
            'versionInfo': '6.1.14',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/org.springframework/spring-webmvc@6.1.14'}
            ]
        }
        package_policies = [
            {'purl': 'pkg:maven/org.springframework/spring-webmvc',
             'usagePolicy': 'allow',
             'reason': 'Apache License 2.0'}
        ]
        results = audit_component_with_resolution(
            component, self.policies, package_policies
        )
        self.assertIn('allow', results[0]['policy'])

    def test_github_action_still_allowed_without_license(self):
        """GitHub Actions without license should still be allowed (no regression)."""
        component = {
            'name': 'actions/checkout',
            'versionInfo': 'v3',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:githubactions/actions/checkout@v3'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=self.license_resolver
        )
        self.assertEqual(results[0]['policy'], 'allow')

    @patch('audit_licenses.get_maven_license_from_pom')
    def test_pom_fallback_includes_resolution_metadata(self, mock_pom):
        """POM fallback result includes resolution metadata."""
        mock_pom.return_value = "Apache License, Version 2.0"
        component = {
            'name': 'spring-webmvc',
            'versionInfo': '6.1.14',
            'licenseConcluded': 'NOASSERTION',
            'externalRefs': [
                {'referenceType': 'purl',
                 'referenceLocator': 'pkg:maven/org.springframework/spring-webmvc@6.1.14'}
            ]
        }
        results = audit_component_with_resolution(
            component, self.policies, self.package_policies,
            license_resolver=self.license_resolver
        )
        self.assertIn('resolution', results[0])
        self.assertEqual(results[0]['resolution']['source'], 'maven_pom_fallback')
        self.assertEqual(results[0]['resolution']['original'], 'Apache License, Version 2.0')


class TestIssue21AllowNewLicenses(unittest.TestCase):
    """Tests for Issue #21: Allow DSDP, curl, PSF-2.0, MIT AND Zlib, ODC-By-1.0, ASLv2."""

    def setUp(self):
        """Load actual policy.json for integration-level tests."""
        policy_path = os.path.join(os.path.dirname(__file__), 'policy.json')
        with open(policy_path, 'r') as f:
            policy_data = json.load(f)
        self.policies = policy_data['policies']
        self.aliases = policy_data.get('licenseAliases', {})
        self.combined_aliases = policy_data.get('combinedLicenseAliases', {})

    def test_curl_license_allowed(self):
        """curl license should be allowed per legal approval."""
        result = find_license_policy('curl', self.policies)
        self.assertEqual(result, 'allow')

    def test_psf_2_0_license_allowed(self):
        """PSF-2.0 license should be allowed per legal approval."""
        result = find_license_policy('PSF-2.0', self.policies)
        self.assertEqual(result, 'allow')

    def test_zlib_license_allowed(self):
        """Zlib license should be allowed per legal approval."""
        result = find_license_policy('Zlib', self.policies)
        self.assertEqual(result, 'allow')

    def test_zlib_acknowledgement_allowed(self):
        """zlib-acknowledgement license should be allowed."""
        result = find_license_policy('zlib-acknowledgement', self.policies)
        self.assertEqual(result, 'allow')

    def test_dsdp_license_allowed(self):
        """DSDP license should be allowed per legal approval."""
        result = find_license_policy('DSDP', self.policies)
        self.assertEqual(result, 'allow')

    def test_odc_by_1_0_license_allowed(self):
        """ODC-By-1.0 license should be allowed per legal approval."""
        result = find_license_policy('ODC-By-1.0', self.policies)
        self.assertEqual(result, 'allow')

    def test_mit_and_zlib_expression_allowed(self):
        """MIT AND Zlib compound expression should be allowed (both constituents allowed)."""
        result = find_license_policy('MIT AND Zlib', self.policies)
        self.assertEqual(result, 'allow')

    def test_aslv2_alias_resolves_to_apache(self):
        """ASLv2 alias should resolve to Apache-2.0 and be allowed."""
        result = find_license_policy('ASLv2', self.policies, self.aliases)
        self.assertEqual(result, 'allow')

    def test_asl_2_0_alias_resolves_to_apache(self):
        """ASL 2.0 alias should resolve to Apache-2.0 and be allowed."""
        result = find_license_policy('ASL 2.0', self.policies, self.aliases)
        self.assertEqual(result, 'allow')


class TestIssue22QosCopyrightAlias(unittest.TestCase):
    """Tests for Issue #22: QOS.ch copyright text should map to MIT."""

    def setUp(self):
        """Load actual policy.json for integration-level tests."""
        policy_path = os.path.join(os.path.dirname(__file__), 'policy.json')
        with open(policy_path, 'r') as f:
            policy_data = json.load(f)
        self.policies = policy_data['policies']
        self.aliases = policy_data.get('licenseAliases', {})

    def test_qos_copyright_resolves_to_mit(self):
        """QOS.ch copyright text should resolve to MIT via alias."""
        result = find_license_policy(
            'Copyright (c) 2004-2022 QOS.ch Sarl (Switzerland)',
            self.policies, self.aliases
        )
        self.assertEqual(result, 'allow')

    def test_qos_copyright_case_insensitive(self):
        """QOS.ch copyright alias should work case-insensitively."""
        result = find_license_policy(
            'copyright (c) 2004-2022 qos.ch sarl (switzerland)',
            self.policies, self.aliases
        )
        self.assertEqual(result, 'allow')


if __name__ == '__main__':
    unittest.main()
