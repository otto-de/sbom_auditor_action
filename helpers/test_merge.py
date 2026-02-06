#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for policy merging logic in audit_licenses.py"""

import unittest
import logging

from audit_licenses import (
    merge_license_policies, 
    merge_package_policies, 
    merge_aliases,
    find_package_policy
)

# Suppress logging during tests
logging.disable(logging.CRITICAL)


class TestMergeLicensePolicies(unittest.TestCase):
    """Tests for merge_license_policies function."""
    
    def test_merge_with_empty_override(self):
        """Override is empty - should return base policies."""
        base = [{'id': 'MIT', 'usagePolicy': 'allow'}]
        result = merge_license_policies(base, [])
        self.assertEqual(result, base)
    
    def test_merge_with_empty_base(self):
        """Base is empty - should return override policies."""
        override = [{'id': 'Apache-2.0', 'usagePolicy': 'deny'}]
        result = merge_license_policies([], override)
        self.assertEqual(result, override)
    
    def test_merge_no_overlap(self):
        """Policies don't overlap - should combine all."""
        base = [{'id': 'MIT', 'usagePolicy': 'allow'}]
        override = [{'id': 'Apache-2.0', 'usagePolicy': 'allow'}]
        result = merge_license_policies(base, override)
        
        self.assertEqual(len(result), 2)
        result_ids = {p['id'] for p in result}
        self.assertEqual(result_ids, {'MIT', 'Apache-2.0'})
    
    def test_merge_with_override(self):
        """Override replaces base policy with same id."""
        base = [{'id': 'GPL-3.0', 'usagePolicy': 'allow'}]
        override = [{'id': 'GPL-3.0', 'usagePolicy': 'deny'}]
        result = merge_license_policies(base, override)
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['usagePolicy'], 'deny')
    
    def test_merge_preserves_additional_fields(self):
        """Merging should preserve additional fields like 'reason'."""
        base = [{'id': 'MIT', 'usagePolicy': 'allow', 'family': 'permissive'}]
        override = [{'id': 'MIT', 'usagePolicy': 'deny', 'reason': 'legal review'}]
        result = merge_license_policies(base, override)
        
        self.assertEqual(result[0]['usagePolicy'], 'deny')
        self.assertEqual(result[0]['reason'], 'legal review')


class TestMergePackagePolicies(unittest.TestCase):
    """Tests for merge_package_policies function."""
    
    def test_merge_with_empty_override(self):
        """Override is empty - should return base policies."""
        base = [{'purl': 'pkg:maven/org/test', 'usagePolicy': 'allow'}]
        result = merge_package_policies(base, [])
        self.assertEqual(result, base)
    
    def test_merge_with_empty_base(self):
        """Base is empty - should return override policies."""
        override = [{'purl': 'pkg:npm/package', 'usagePolicy': 'deny'}]
        result = merge_package_policies([], override)
        self.assertEqual(result, override)
    
    def test_merge_package_policies_no_overlap(self):
        """Package policies don't overlap - should combine all."""
        base = [{'purl': 'pkg:maven/base/package', 'usagePolicy': 'allow'}]
        override = [
            {'purl': 'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api', 'usagePolicy': 'allow'},
            {'purl': 'pkg:maven/javax.annotation/javax.annotation-api', 'usagePolicy': 'allow'}
        ]
        result = merge_package_policies(base, override)
        
        self.assertEqual(len(result), 3)
        purls = {p['purl'] for p in result}
        self.assertIn('pkg:maven/base/package', purls)
        self.assertIn('pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api', purls)
    
    def test_merge_strips_query_params_for_matching(self):
        """Query parameters should be stripped for merge matching."""
        base = [{'purl': 'pkg:maven/org/test?type=jar', 'usagePolicy': 'allow'}]
        override = [{'purl': 'pkg:maven/org/test', 'usagePolicy': 'deny'}]
        result = merge_package_policies(base, override)
        
        # Should be merged into one (override wins)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['usagePolicy'], 'deny')


class TestMergeAliases(unittest.TestCase):
    """Tests for merge_aliases function."""
    
    def test_merge_aliases_empty_override(self):
        """Empty override returns base."""
        base = {'mit license': 'MIT'}
        result = merge_aliases(base, {})
        self.assertEqual(result, base)
    
    def test_merge_aliases_empty_base(self):
        """Empty base returns override."""
        override = {'apache 2': 'Apache-2.0'}
        result = merge_aliases({}, override)
        self.assertEqual(result, override)
    
    def test_merge_aliases_combined(self):
        """Combines both alias dictionaries."""
        base = {'mit license': 'MIT'}
        override = {'apache 2': 'Apache-2.0'}
        result = merge_aliases(base, override)
        
        self.assertEqual(len(result), 2)
        self.assertEqual(result['mit license'], 'MIT')
        self.assertEqual(result['apache 2'], 'Apache-2.0')
    
    def test_merge_aliases_override_wins(self):
        """Override value replaces base value for same key."""
        base = {'gpl': 'GPL-2.0-only'}
        override = {'gpl': 'GPL-3.0-only'}
        result = merge_aliases(base, override)
        
        self.assertEqual(result['gpl'], 'GPL-3.0-only')


class TestFindPackagePolicy(unittest.TestCase):
    """Tests for find_package_policy function."""
    
    def test_exact_match(self):
        """Exact PURL match should return the policy."""
        policies = [{'purl': 'pkg:maven/org/test', 'usagePolicy': 'allow'}]
        result = find_package_policy('pkg:maven/org/test', policies)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['usagePolicy'], 'allow')
    
    def test_query_params_stripped(self):
        """Query parameters in SBOM PURL should be stripped for matching."""
        policies = [{'purl': 'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api', 'usagePolicy': 'allow'}]
        result = find_package_policy(
            'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@3.1.0?type=jar', 
            policies
        )
        
        self.assertIsNotNone(result)
    
    def test_version_agnostic_policy(self):
        """Policy without version should match all versions of the package."""
        policies = [{'purl': 'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api', 'usagePolicy': 'allow'}]
        
        # Should match version 3.1.0
        result1 = find_package_policy(
            'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@3.1.0', 
            policies
        )
        self.assertIsNotNone(result1)
        
        # Should also match version 2.0.0
        result2 = find_package_policy(
            'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@2.0.0', 
            policies
        )
        self.assertIsNotNone(result2)
    
    def test_version_specific_policy_no_match(self):
        """Policy with specific version should not match different version."""
        policies = [{'purl': 'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@3.1.0', 'usagePolicy': 'allow'}]
        result = find_package_policy(
            'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@2.0.0', 
            policies
        )
        
        self.assertIsNone(result)
    
    def test_wildcard_match(self):
        """Wildcard patterns should match appropriately."""
        policies = [{'purl': 'pkg:maven/org.jboss/*', 'usagePolicy': 'allow'}]
        result = find_package_policy(
            'pkg:maven/org.jboss/jboss-transaction-spi@1.0.0', 
            policies
        )
        
        self.assertIsNotNone(result)
    
    def test_no_match_returns_none(self):
        """No matching policy should return None."""
        policies = [{'purl': 'pkg:maven/org/different', 'usagePolicy': 'allow'}]
        result = find_package_policy('pkg:maven/org/test@1.0.0', policies)
        
        self.assertIsNone(result)
    
    def test_empty_policies_returns_none(self):
        """Empty policies list should return None."""
        result = find_package_policy('pkg:maven/org/test', [])
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
