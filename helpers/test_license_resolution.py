#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for license_resolver.py and spdx_expression_parser.py"""

import unittest
from unittest.mock import patch, MagicMock
import logging

from license_resolver import LicenseResolver
from spdx_expression_parser import SPDXExpressionParser

# Suppress logging during tests
logging.disable(logging.CRITICAL)


class TestLicenseResolverNormalization(unittest.TestCase):
    """Tests for license name normalization in LicenseResolver."""
    
    def setUp(self):
        self.resolver = LicenseResolver()
    
    def test_normalize_basic(self):
        """Basic normalization removes 'The' prefix."""
        result = self.resolver._normalize_license_name("The MIT License")
        self.assertEqual(result, "mit license")
    
    def test_normalize_whitespace(self):
        """Extra whitespace is normalized."""
        result = self.resolver._normalize_license_name("  MIT   License  ")
        self.assertEqual(result, "mit license")
    
    def test_normalize_version_patterns(self):
        """Version patterns are normalized."""
        result = self.resolver._normalize_license_name("Apache License version 2.0")
        self.assertIn("v2", result)
    
    def test_normalize_empty_string(self):
        """Empty string returns empty."""
        result = self.resolver._normalize_license_name("")
        self.assertEqual(result, "")
    
    def test_normalize_none(self):
        """None input returns empty string."""
        result = self.resolver._normalize_license_name(None)
        self.assertEqual(result, "")


class TestLicenseResolverFuzzyMatch(unittest.TestCase):
    """Tests for SPDX fuzzy matching in LicenseResolver."""
    
    def setUp(self):
        self.resolver = LicenseResolver()
        # Mock the SPDX data to avoid network calls
        self.resolver._spdx_licenses = {
            'MIT': {'name': 'MIT License', 'id': 'MIT', 'deprecated': False},
            'Apache-2.0': {'name': 'Apache License 2.0', 'id': 'Apache-2.0', 'deprecated': False},
            'BSD-3-Clause': {'name': 'BSD 3-Clause License', 'id': 'BSD-3-Clause', 'deprecated': False},
            'EPL-2.0': {'name': 'Eclipse Public License 2.0', 'id': 'EPL-2.0', 'deprecated': False},
            'EPL-1.0': {'name': 'Eclipse Public License 1.0', 'id': 'EPL-1.0', 'deprecated': False},
            'MPL-2.0': {'name': 'Mozilla Public License 2.0', 'id': 'MPL-2.0', 'deprecated': False},
            'GPL-3.0-only': {'name': 'GNU General Public License v3.0 only', 'id': 'GPL-3.0-only', 'deprecated': False},
            'GPL-2.0-only': {'name': 'GNU General Public License v2.0 only', 'id': 'GPL-2.0-only', 'deprecated': False},
            'LGPL-2.1-only': {'name': 'GNU Lesser General Public License v2.1 only', 'id': 'LGPL-2.1-only', 'deprecated': False},
        }
        self.resolver._spdx_exceptions = {}
    
    def test_exact_match_by_id(self):
        """Exact ID match should return the license."""
        result = self.resolver._fuzzy_match_spdx("MIT")
        self.assertEqual(result, "MIT")
    
    def test_case_insensitive_match(self):
        """Match should be case-insensitive."""
        result = self.resolver._fuzzy_match_spdx("mit")
        self.assertEqual(result, "MIT")
    
    def test_apache_pattern_match(self):
        """Common Apache variations should match."""
        test_cases = [
            "The Apache Software License, Version 2.0",
            "Apache License Version 2.0",
            "Apache License 2.0"
        ]
        for test in test_cases:
            result = self.resolver._fuzzy_match_spdx(test)
            self.assertEqual(result, "Apache-2.0", f"Failed for: {test}")
    
    def test_eclipse_pattern_match(self):
        """Eclipse license variations should match."""
        result = self.resolver._fuzzy_match_spdx("Eclipse Public License v2.0")
        self.assertEqual(result, "EPL-2.0")
    
    def test_bsd_pattern_match(self):
        """BSD license variations should match."""
        result = self.resolver._fuzzy_match_spdx("BSD 3-Clause License")
        self.assertEqual(result, "BSD-3-Clause")
    
    def test_no_match_returns_none(self):
        """Unknown license returns None."""
        result = self.resolver._fuzzy_match_spdx("Unknown Proprietary License XYZ")
        self.assertIsNone(result)


class TestLicenseResolverResolve(unittest.TestCase):
    """Tests for the main resolve_license method."""
    
    def setUp(self):
        self.resolver = LicenseResolver()
        # Mock SPDX data
        self.resolver._spdx_licenses = {
            'MIT': {'name': 'MIT License', 'id': 'MIT', 'deprecated': False},
            'Apache-2.0': {'name': 'Apache License 2.0', 'id': 'Apache-2.0', 'deprecated': False},
        }
        self.resolver._spdx_exceptions = {}
    
    def test_resolve_empty_returns_empty(self):
        """Empty license name returns empty result."""
        result = self.resolver.resolve_license("")
        self.assertIsNone(result['resolved'])
        self.assertEqual(result['method'], 'empty')
    
    def test_resolve_known_license(self):
        """Known license resolves via SPDX fuzzy match."""
        result = self.resolver.resolve_license("MIT License")
        self.assertEqual(result['resolved'], 'MIT')
        self.assertEqual(result['method'], 'spdx_fuzzy')
        self.assertGreater(result['confidence'], 0)
    
    def test_resolve_apache_variation(self):
        """Apache license variation resolves correctly."""
        result = self.resolver.resolve_license("Apache License, Version 2.0")
        self.assertEqual(result['resolved'], 'Apache-2.0')
    
    def test_resolve_unknown_returns_unresolved(self):
        """Unknown license without AI returns unresolved."""
        result = self.resolver.resolve_license("Weird Custom License 123")
        self.assertIsNone(result['resolved'])
        self.assertEqual(result['method'], 'unresolved')


class TestSPDXExpressionParserTokenize(unittest.TestCase):
    """Tests for SPDX expression tokenization."""
    
    def setUp(self):
        self.parser = SPDXExpressionParser()
    
    def test_tokenize_simple_license(self):
        """Simple license ID tokenizes correctly."""
        tokens = self.parser._tokenize("MIT")
        self.assertEqual(len(tokens), 2)  # LICENSE_ID + EOF
        self.assertEqual(tokens[0].value, "MIT")
    
    def test_tokenize_and_expression(self):
        """AND expression tokenizes correctly."""
        tokens = self.parser._tokenize("MIT AND Apache-2.0")
        token_types = [t.type.name for t in tokens]
        self.assertIn('LICENSE_ID', token_types)
        self.assertIn('AND', token_types)
    
    def test_tokenize_or_expression(self):
        """OR expression tokenizes correctly."""
        tokens = self.parser._tokenize("MIT OR GPL-3.0")
        token_types = [t.type.name for t in tokens]
        self.assertIn('OR', token_types)
    
    def test_tokenize_with_expression(self):
        """WITH expression tokenizes correctly."""
        tokens = self.parser._tokenize("GPL-2.0 WITH Classpath-exception-2.0")
        token_types = [t.type.name for t in tokens]
        self.assertIn('WITH', token_types)
    
    def test_tokenize_parentheses(self):
        """Parentheses tokenize correctly."""
        tokens = self.parser._tokenize("(MIT OR Apache-2.0)")
        token_types = [t.type.name for t in tokens]
        self.assertIn('LPAREN', token_types)
        self.assertIn('RPAREN', token_types)
    
    def test_tokenize_or_later(self):
        """Plus suffix (or-later) tokenizes correctly."""
        tokens = self.parser._tokenize("GPL-2.0+")
        # Should have LICENSE_ID, PLUS, EOF
        token_values = [t.value for t in tokens if t.value]
        self.assertIn('GPL-2.0', token_values)
        self.assertIn('+', token_values)


class TestSPDXExpressionParserEvaluate(unittest.TestCase):
    """Tests for SPDX expression evaluation."""
    
    def setUp(self):
        self.policies = [
            {'id': 'MIT', 'usagePolicy': 'allow'},
            {'id': 'Apache-2.0', 'usagePolicy': 'allow'},
            {'id': 'BSD-3-Clause', 'usagePolicy': 'allow'},
            {'id': 'GPL-3.0-only', 'usagePolicy': 'deny'},
            {'id': 'GPL-2.0-only', 'usagePolicy': 'allow'},
            {'id': 'LGPL-2.1-only', 'usagePolicy': 'needs-review'},
            {'id': 'EPL-2.0', 'usagePolicy': 'allow'},
            {'id': 'GPL-2.0-with-classpath-exception', 'usagePolicy': 'allow'},
        ]
        self.parser = SPDXExpressionParser()
    
    def test_simple_allow(self):
        """Simple allowed license."""
        policy, _ = self.parser.parse_and_evaluate("MIT", self.policies)
        self.assertEqual(policy, "allow")
    
    def test_simple_deny(self):
        """Simple denied license."""
        policy, _ = self.parser.parse_and_evaluate("GPL-3.0-only", self.policies)
        self.assertEqual(policy, "deny")
    
    def test_unknown_needs_review(self):
        """Unknown license needs review."""
        policy, _ = self.parser.parse_and_evaluate("Unknown-License", self.policies)
        self.assertEqual(policy, "needs-review")
    
    def test_and_all_allowed(self):
        """AND expression - all allowed."""
        policy, _ = self.parser.parse_and_evaluate("MIT AND Apache-2.0", self.policies)
        self.assertEqual(policy, "allow")
    
    def test_and_one_denied(self):
        """AND expression - one denied."""
        policy, _ = self.parser.parse_and_evaluate("MIT AND GPL-3.0-only", self.policies)
        self.assertEqual(policy, "deny")
    
    def test_or_one_allowed(self):
        """OR expression - one allowed suffices."""
        policy, _ = self.parser.parse_and_evaluate("MIT OR GPL-3.0-only", self.policies)
        self.assertEqual(policy, "allow")
    
    def test_or_all_denied(self):
        """OR expression - all denied."""
        policy, _ = self.parser.parse_and_evaluate("GPL-3.0-only OR Unknown", self.policies)
        # Unknown is needs-review, not deny, so result is needs-review
        self.assertIn(policy, ["deny", "needs-review"])
    
    def test_complex_expression(self):
        """Complex nested expression."""
        policy, _ = self.parser.parse_and_evaluate(
            "(MIT OR Apache-2.0) AND BSD-3-Clause", 
            self.policies
        )
        self.assertEqual(policy, "allow")
    
    def test_case_insensitive(self):
        """License IDs are case-insensitive."""
        policy, _ = self.parser.parse_and_evaluate("mit", self.policies)
        self.assertEqual(policy, "allow")
    
    def test_noassertion(self):
        """NOASSERTION needs review."""
        policy, _ = self.parser.parse_and_evaluate("NOASSERTION", self.policies)
        self.assertEqual(policy, "needs-review")
    
    def test_empty_expression(self):
        """Empty expression needs review."""
        policy, _ = self.parser.parse_and_evaluate("", self.policies)
        self.assertEqual(policy, "needs-review")


class TestSPDXExpressionParserAliases(unittest.TestCase):
    """Tests for alias resolution in SPDX expression parser."""
    
    def setUp(self):
        self.policies = [
            {'id': 'MIT', 'usagePolicy': 'allow'},
            {'id': 'Apache-2.0', 'usagePolicy': 'allow'},
            {'id': 'CDDL-1.1', 'usagePolicy': 'allow'},
        ]
        self.license_aliases = {
            'mit license': 'MIT',
            'the apache software license, version 2.0': 'Apache-2.0',
            'eclipse distribution license v. 1.0': 'BSD-3-Clause',
        }
        self.combined_aliases = {
            'cddl + gplv2': 'CDDL-1.1',
            'cddl + gplv2 with classpath exception': 'CDDL-1.1',
        }
    
    def test_license_alias_resolution(self):
        """License aliases should resolve to SPDX IDs."""
        parser = SPDXExpressionParser(license_aliases=self.license_aliases)
        policy, _ = parser.parse_and_evaluate("MIT License", self.policies)
        self.assertEqual(policy, "allow")
    
    def test_combined_alias_resolution(self):
        """Combined license aliases should resolve."""
        parser = SPDXExpressionParser(combined_aliases=self.combined_aliases)
        policy, _ = parser.parse_and_evaluate("CDDL + GPLv2", self.policies)
        self.assertEqual(policy, "allow")


class TestSPDXExpressionParserComponents(unittest.TestCase):
    """Tests for extracting components from expressions."""
    
    def setUp(self):
        self.parser = SPDXExpressionParser()
    
    def test_get_single_component(self):
        """Single license returns one component."""
        components = self.parser.get_expression_components("MIT")
        self.assertEqual(components, ["MIT"])
    
    def test_get_and_components(self):
        """AND expression returns all components."""
        components = self.parser.get_expression_components("MIT AND Apache-2.0")
        self.assertIn("MIT", components)
        self.assertIn("Apache-2.0", components)
    
    def test_get_or_components(self):
        """OR expression returns all components."""
        components = self.parser.get_expression_components("MIT OR GPL-3.0")
        self.assertEqual(len(components), 2)
    
    def test_get_complex_components(self):
        """Complex expression returns all license IDs."""
        components = self.parser.get_expression_components(
            "(MIT OR Apache-2.0) AND BSD-3-Clause"
        )
        self.assertIn("MIT", components)
        self.assertIn("Apache-2.0", components)
        self.assertIn("BSD-3-Clause", components)


if __name__ == '__main__':
    unittest.main()
