#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
SPDX License Expression Parser
Handles complex SPDX license expressions with AND/OR operators.
"""

import re
import logging
from typing import List, Dict, Optional, Tuple

class SPDXExpressionParser:
    """Parser for SPDX license expressions with AND/OR logic."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
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
            
        # Handle simple single licenses first
        if not self._contains_operators(expression):
            policy = self._find_license_policy(expression, license_policies)
            if policy:
                return policy, f"Direct policy match for '{expression}'"
            return "needs-review", f"No policy found for '{expression}'"
        
        # Parse complex expressions
        try:
            result = self._evaluate_expression(expression, license_policies)
            return result
        except Exception as e:
            self.logger.warning(f"Failed to parse expression '{expression}': {e}")
            return "needs-review", f"Failed to parse license expression: {expression}"
    
    def _contains_operators(self, expression: str) -> bool:
        """Check if expression contains SPDX operators."""
        return any(op in expression.upper() for op in [' AND ', ' OR ', ' WITH '])
    
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
        
        # First try exact match
        policy = self._find_license_policy(expression, license_policies)
        if policy:
            return policy, f"Exact policy match for '{expression}'"
        
        # Split and check base license
        parts = re.split(r'\s+WITH\s+', expression, flags=re.IGNORECASE)
        if len(parts) == 2:
            base_license = parts[0].strip()
            exception = parts[1].strip()
            
            base_policy = self._find_license_policy(base_license, license_policies)
            if base_policy == "allow":
                return "allow", f"Base license '{base_license}' allows exceptions (WITH {exception})"
            elif base_policy == "deny":
                return "deny", f"Base license '{base_license}' is denied"
            else:
                return "needs-review", f"Base license '{base_license}' needs review (WITH {exception})"
        
        return "needs-review", f"Complex WITH expression needs review: {expression}"
    
    def _find_license_policy(self, license_id: str, license_policies: List[Dict]) -> Optional[str]:
        """Find policy for a single license ID."""
        license_id = license_id.strip()
        
        for policy in license_policies:
            if policy.get('id') == license_id:
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
    """Test the SPDX expression parser."""
    parser = SPDXExpressionParser()
    
    # Sample policies
    policies = [
        {"id": "Apache-2.0", "usagePolicy": "allow"},
        {"id": "MIT", "usagePolicy": "allow"},
        {"id": "EPL-1.0", "usagePolicy": "allow"},
        {"id": "EPL-2.0", "usagePolicy": "allow"},
        {"id": "GPL-2.0-only", "usagePolicy": "deny"},
        {"id": "GPL-2.0-with-classpath-exception", "usagePolicy": "allow"}
    ]
    
    test_cases = [
        "Apache-2.0",  # Simple
        "Apache-2.0 AND MIT",  # Both allowed
        "Apache-2.0 AND GPL-2.0-only",  # Mixed
        "MIT OR Apache-2.0",  # Both allowed
        "GPL-2.0-only OR GPL-3.0-only",  # Both denied/unknown
        "EPL-2.0 WITH Classpath-exception",  # With clause
        "Unknown-License",  # Unknown
    ]
    
    for expression in test_cases:
        policy, explanation = parser.parse_and_evaluate(expression, policies)
        print(f"'{expression}' → {policy}: {explanation}")


if __name__ == "__main__":
    test_parser()
