#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
SPDX License Expression Parser
Handles complex SPDX license expressions with AND/OR operators.
Includes normalization for non-standard license names.
License aliases are loaded from policy.json.
"""

import re
import logging
from typing import List, Dict, Optional, Tuple

# Default aliases as fallback (used when no policy provides aliases)
DEFAULT_LICENSE_ALIASES = {
    'apache': 'Apache-2.0',
    'apache 2.0': 'Apache-2.0',
    'mit license': 'MIT',
    'bsd': 'BSD-3-Clause',
    'gpl2': 'GPL-2.0-only',
    'gplv2': 'GPL-2.0-only',
}

DEFAULT_COMBINED_LICENSE_ALIASES = {}


class SPDXExpressionParser:
    """Parser for SPDX license expressions with AND/OR logic."""
    
    def __init__(self, license_aliases: Dict[str, str] = None, combined_aliases: Dict[str, str] = None):
        """
        Initialize the parser.
        
        Args:
            license_aliases: Mapping of non-standard license names to SPDX IDs (from policy.json).
            combined_aliases: Mapping of combined license expressions to preferred single license.
        """
        self.logger = logging.getLogger(__name__)
        # Use provided aliases or fall back to defaults
        self.license_aliases = license_aliases if license_aliases is not None else DEFAULT_LICENSE_ALIASES.copy()
        self.combined_aliases = combined_aliases if combined_aliases is not None else DEFAULT_COMBINED_LICENSE_ALIASES.copy()
        
        # Remove _comment keys if present (from JSON)
        self.license_aliases = {k: v for k, v in self.license_aliases.items() if k != '_comment'}
        self.combined_aliases = {k: v for k, v in self.combined_aliases.items() if k != '_comment'}
        
        self.logger.debug(f"Initialized SPDXExpressionParser with {len(self.license_aliases)} license aliases "
                         f"and {len(self.combined_aliases)} combined aliases")
    
    def _normalize_expression(self, expression: str) -> str:
        """
        Normalize non-standard license expressions to SPDX format.
        
        Handles:
        - "+" as AND operator
        - "w/" as WITH
        - Non-standard license names
        - Combined license aliases
        """
        if not expression:
            return expression
            
        original = expression
        normalized = expression.strip()
        
        # First check for known combined license patterns (exact match)
        normalized_lower = normalized.lower()
        if normalized_lower in self.combined_aliases:
            result = self.combined_aliases[normalized_lower]
            self.logger.debug(f"🔄 Normalized combined license '{original}' → '{result}'")
            return result
        
        # Normalize operators
        # Replace " + " with " AND " (but not in license names like "GPL-2.0+")
        normalized = re.sub(r'\s+\+\s+', ' AND ', normalized)
        
        # Replace "w/" with "WITH"
        normalized = re.sub(r'\s+w/\s+', ' WITH ', normalized, flags=re.IGNORECASE)
        
        # Replace "CPE" (Classpath Exception) with the full exception name when used with WITH
        # Only if not already containing "Classpath"
        if 'classpath' not in normalized.lower():
            normalized = re.sub(r'\s+WITH\s+CPE\b', ' WITH Classpath-exception-2.0', normalized, flags=re.IGNORECASE)
        
        # Replace standalone "classpath exception" with the full exception name
        # But only if it doesn't already have a version number
        if 'classpath-exception-2.0' not in normalized.lower():
            normalized = re.sub(r'\bclasspath[\s-]*exception\b(?!-2\.0)', 'Classpath-exception-2.0', normalized, flags=re.IGNORECASE)
        
        if original != normalized:
            self.logger.debug(f"🔄 Normalized operators in '{original}' → '{normalized}'")
        
        return normalized
    
    def _normalize_license_id(self, license_id: str) -> str:
        """Normalize a single license ID using the alias mapping."""
        if not license_id:
            return license_id
            
        license_id = license_id.strip()
        normalized_lower = license_id.lower()
        
        # Check alias mapping
        if normalized_lower in self.license_aliases:
            result = self.license_aliases[normalized_lower]
            self.logger.debug(f"🔄 Normalized license ID '{license_id}' → '{result}'")
            return result
        
        return license_id
        
    def parse_and_evaluate(self, expression: str, license_policies: List[Dict]) -> Tuple[str, str]:
        """
        Parse SPDX expression and evaluate policy.
        
        Args:
            expression: SPDX license expression (e.g., "Apache-2.0 AND MIT")
            license_policies: List of license policies
            
        Returns:
            Tuple of (policy_result, explanation)
        """
        if not expression or expression == "NO-LICENSE-FOUND":
            return "needs-review", "No license found"
        
        # Normalize the expression first
        normalized = self._normalize_expression(expression)
        
        # Check if the normalized expression is a simple single license (after combined alias resolution)
        if not self._contains_operators(normalized):
            # Also normalize the individual license ID
            normalized_id = self._normalize_license_id(normalized)
            policy = self._find_license_policy(normalized_id, license_policies)
            if policy:
                if normalized_id != expression:
                    return policy, f"Policy match for '{expression}' (normalized to '{normalized_id}')"
                return policy, f"Direct policy match for '{expression}'"
            return "needs-review", f"No policy found for '{expression}'"
        
        # Parse complex expressions
        try:
            result = self._evaluate_expression(normalized, license_policies)
            return result
        except Exception as e:
            self.logger.warning(f"Failed to parse expression '{expression}': {e}")
            return "needs-review", f"Failed to parse license expression: {expression}"
    
    def _contains_operators(self, expression: str) -> bool:
        """Check if expression contains SPDX operators (including non-standard ones)."""
        # Check for standard operators
        if any(op in expression.upper() for op in [' AND ', ' OR ', ' WITH ']):
            return True
        # Check for non-standard operators that will be normalized
        if re.search(r'\s+\+\s+', expression):  # " + "
            return True
        if re.search(r'\s+w/\s+', expression, re.IGNORECASE):  # " w/ "
            return True
        return False
    
    def _evaluate_expression(self, expression: str, license_policies: List[Dict]) -> Tuple[str, str]:
        """Recursively evaluate SPDX expression."""
        expression = expression.strip()
        
        # Handle parentheses (for future extensibility)
        if '(' in expression and ')' in expression:
            # Simple implementation - would need proper parsing for complex nested expressions
            expression = expression.replace('(', '').replace(')', '')
        
        # Split on AND (both must be allowed)
        if ' AND ' in expression.upper():
            return self._evaluate_and_expression(expression, license_policies)
        
        # Split on OR (at least one must be allowed)
        elif ' OR ' in expression.upper():
            return self._evaluate_or_expression(expression, license_policies)
        
        # Handle WITH operator (license exceptions)
        elif ' WITH ' in expression.upper():
            return self._evaluate_with_expression(expression, license_policies)
        
        # Single license
        else:
            policy = self._find_license_policy(expression, license_policies)
            if policy:
                return policy, f"Policy match for '{expression}'"
            return "needs-review", f"No policy found for '{expression}'"
    
    def _evaluate_and_expression(self, expression: str, license_policies: List[Dict]) -> Tuple[str, str]:
        """Evaluate AND expression - all parts must be allowed."""
        parts = re.split(r'\s+AND\s+', expression, flags=re.IGNORECASE)
        
        results = []
        explanations = []
        
        for part in parts:
            part = part.strip()
            policy, explanation = self._evaluate_expression(part, license_policies)
            results.append(policy)
            explanations.append(f"{part}: {policy}")
        
        # For AND: all must be "allow" for result to be "allow"
        if all(result == "allow" for result in results):
            return "allow", f"All parts allowed: {'; '.join(explanations)}"
        elif any(result == "deny" for result in results):
            return "deny", f"At least one part denied: {'; '.join(explanations)}"
        else:
            return "needs-review", f"Some parts need review: {'; '.join(explanations)}"
    
    def _evaluate_or_expression(self, expression: str, license_policies: List[Dict]) -> Tuple[str, str]:
        """Evaluate OR expression - at least one part must be allowed."""
        parts = re.split(r'\s+OR\s+', expression, flags=re.IGNORECASE)
        
        results = []
        explanations = []
        
        for part in parts:
            part = part.strip()
            policy, explanation = self._evaluate_expression(part, license_policies)
            results.append(policy)
            explanations.append(f"{part}: {policy}")
        
        # For OR: if any is "allow", result is "allow"
        if any(result == "allow" for result in results):
            return "allow", f"At least one part allowed: {'; '.join(explanations)}"
        elif all(result == "deny" for result in results):
            return "deny", f"All parts denied: {'; '.join(explanations)}"
        else:
            return "needs-review", f"No parts allowed: {'; '.join(explanations)}"
    
    def _evaluate_with_expression(self, expression: str, license_policies: List[Dict]) -> Tuple[str, str]:
        """Evaluate WITH expression - license with exception."""
        # For "GPL-2.0-only WITH Classpath-exception-2.0", check if combined form is allowed
        # or if base license allows exceptions
        
        # First try exact match of the full expression
        policy = self._find_license_policy(expression, license_policies)
        if policy:
            return policy, f"Exact policy match for '{expression}'"
        
        # Split and check base license
        parts = re.split(r'\s+WITH\s+', expression, flags=re.IGNORECASE)
        if len(parts) == 2:
            base_license = parts[0].strip()
            exception = parts[1].strip()
            
            # Try to find a combined form in the policy (e.g., "GPL-2.0-with-classpath-exception")
            combined_forms = [
                f"{base_license}-with-{exception}".lower().replace(' ', '-'),
                f"{base_license}-with-{exception.replace('-exception', '')}".lower().replace(' ', '-'),
            ]
            
            # Special handling for GPL + Classpath
            if 'classpath' in exception.lower() and 'gpl' in base_license.lower():
                combined_forms.append('GPL-2.0-with-classpath-exception')
            
            for combined in combined_forms:
                for pol in license_policies:
                    if pol.get('id', '').lower() == combined.lower():
                        return pol.get('usagePolicy'), f"Combined form match: '{pol.get('id')}' for '{expression}'"
            
            # Check base license policy
            base_policy = self._find_license_policy(base_license, license_policies)
            if base_policy == "allow":
                return "allow", f"Base license '{base_license}' allows exceptions (WITH {exception})"
            elif base_policy == "deny":
                return "deny", f"Base license '{base_license}' is denied"
            else:
                return "needs-review", f"Base license '{base_license}' needs review (WITH {exception})"
        
        return "needs-review", f"Complex WITH expression needs review: {expression}"
    
    def _find_license_policy(self, license_id: str, license_policies: List[Dict]) -> Optional[str]:
        """Find policy for a single license ID with normalization support."""
        license_id = license_id.strip()
        
        # First try exact match
        for policy in license_policies:
            if policy.get('id') == license_id:
                return policy.get('usagePolicy')
        
        # Try normalized version
        normalized = self._normalize_license_id(license_id)
        if normalized != license_id:
            for policy in license_policies:
                if policy.get('id') == normalized:
                    return policy.get('usagePolicy')
        
        # Try case-insensitive match
        license_id_lower = license_id.lower()
        for policy in license_policies:
            if policy.get('id', '').lower() == license_id_lower:
                return policy.get('usagePolicy')
        
        return None

    def get_expression_components(self, expression: str) -> List[str]:
        """Extract all individual license IDs from an expression."""
        if not self._contains_operators(expression):
            return [expression.strip()]
        
        # Split on all operators and clean up
        components = []
        parts = re.split(r'\s+(?:AND|OR|WITH)\s+', expression, flags=re.IGNORECASE)
        
        for part in parts:
            part = part.strip().replace('(', '').replace(')', '')
            if part:
                components.append(part)
        
        return components


def test_parser():
    """Test the SPDX expression parser with aliases loaded from policy.json."""
    import logging
    import json
    import os
    
    logging.basicConfig(level=logging.DEBUG)
    
    # Load aliases from policy.json
    script_dir = os.path.dirname(os.path.abspath(__file__))
    policy_path = os.path.join(script_dir, 'policy.json')
    
    license_aliases = {}
    combined_aliases = {}
    
    try:
        with open(policy_path, 'r') as f:
            policy_data = json.load(f)
            license_aliases = policy_data.get('licenseAliases', {})
            combined_aliases = policy_data.get('combinedLicenseAliases', {})
            print(f"✅ Loaded {len(license_aliases)} license aliases and {len(combined_aliases)} combined aliases from policy.json")
    except Exception as e:
        print(f"⚠️ Could not load aliases from policy.json: {e}")
        print("   Using default fallback aliases")
    
    parser = SPDXExpressionParser(license_aliases=license_aliases, combined_aliases=combined_aliases)
    
    # Sample policies (mimicking real policy.json)
    policies = [
        {"id": "Apache-2.0", "usagePolicy": "allow"},
        {"id": "MIT", "usagePolicy": "allow"},
        {"id": "EPL-1.0", "usagePolicy": "allow"},
        {"id": "EPL-2.0", "usagePolicy": "allow"},
        {"id": "GPL-2.0-only", "usagePolicy": "allow"},
        {"id": "GPL-2.0-with-classpath-exception", "usagePolicy": "allow"},
        {"id": "CDDL-1.0", "usagePolicy": "allow"},
        {"id": "CDDL-1.1", "usagePolicy": "allow"},
        {"id": "EDL-1.0", "usagePolicy": "allow"},
        {"id": "BSD-3-Clause", "usagePolicy": "allow"},
    ]
    
    test_cases = [
        # Standard SPDX expressions
        "Apache-2.0",
        "Apache-2.0 AND MIT",
        "MIT OR Apache-2.0",
        "EPL-2.0 WITH Classpath-exception",
        
        # Non-standard expressions (from the bug report)
        "CDDL + GPLv2 with classpath exception",
        "EPL-2.0 AND Eclipse Distribution License v. 1.0",
        "EPL-2.0 AND GPL2 w/ CPE",
        
        # Additional non-standard variations
        "GPL2 w/ CPE",
        "gplv2 with classpath exception",
        "Eclipse Distribution License",
        "The Apache License, Version 2.0",
        "BSD License",
    ]
    
    print("\n" + "="*80)
    print("SPDX Expression Parser Test Results")
    print("="*80 + "\n")
    
    for expression in test_cases:
        policy, explanation = parser.parse_and_evaluate(expression, policies)
        status = "✅" if policy == "allow" else "❌" if policy == "deny" else "⚠️"
        print(f"{status} '{expression}'")
        print(f"   → {policy}: {explanation}\n")


if __name__ == "__main__":
    test_parser()
