#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
SPDX License Expression Parser

Implements a parser for SPDX license expressions according to the SPDX spec v3.0.1:
https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/

ABNF Grammar (from spec):
    idstring              = 1*(ALPHA / DIGIT / "-" / ".")
    license-id            = <short form license identifier from SPDX License List>
    license-exception-id  = <short form license exception identifier from SPDX License List>
    license-ref           = ["DocumentRef-"idstring":"]"LicenseRef-"idstring
    addition-ref          = ["DocumentRef-"idstring":"]"AdditionRef-"idstring
    simple-expression     = license-id / license-id"+" / license-ref
    addition-expression   = license-exception-id / addition-ref
    compound-expression   = simple-expression /
                            simple-expression ("WITH" / "with") addition-expression /
                            compound-expression ("AND" / "and") compound-expression /
                            compound-expression ("OR" / "or") compound-expression /
                            "(" compound-expression ")"
    license-expression    = simple-expression / compound-expression

Operator Precedence (lowest to highest): OR < AND < WITH < +

Notes:
- License IDs are case-insensitive
- Operators must be exactly "AND"/"and", "OR"/"or", "WITH"/"with" (not mixed case)
- There must be whitespace around AND/OR, whitespace around WITH
- No whitespace between license-id and "+"
"""

import re
import logging
from typing import List, Dict, Optional, Tuple
from enum import Enum, auto


# Regex for valid SPDX idstring: 1*(ALPHA / DIGIT / "-" / ".")
IDSTRING_PATTERN = re.compile(r'^[A-Za-z0-9.\-]+$')

# Regex for LicenseRef with optional DocumentRef prefix
LICENSE_REF_PATTERN = re.compile(
    r'^(?:DocumentRef-([A-Za-z0-9.\-]+):)?LicenseRef-([A-Za-z0-9.\-]+)$'
)

# Regex for AdditionRef with optional DocumentRef prefix
ADDITION_REF_PATTERN = re.compile(
    r'^(?:DocumentRef-([A-Za-z0-9.\-]+):)?AdditionRef-([A-Za-z0-9.\-]+)$'
)


class TokenType(Enum):
    """Token types for the SPDX expression lexer."""
    LICENSE_ID = auto()      # License identifier (e.g., "MIT", "Apache-2.0")
    LICENSE_REF = auto()     # LicenseRef-xxx or DocumentRef-xxx:LicenseRef-xxx
    ADDITION_REF = auto()    # AdditionRef-xxx or DocumentRef-xxx:AdditionRef-xxx
    PLUS = auto()            # "+" suffix for "or later"
    AND = auto()             # "AND" or "and" (exact case)
    OR = auto()              # "OR" or "or" (exact case)
    WITH = auto()            # "WITH" or "with" (exact case)
    LPAREN = auto()          # "("
    RPAREN = auto()          # ")"
    EOF = auto()             # End of expression


class Token:
    """A token in the SPDX expression."""
    def __init__(self, type: TokenType, value: str, position: int):
        self.type = type
        self.value = value
        self.position = position
    
    def __repr__(self):
        return f"Token({self.type.name}, '{self.value}')"


class SPDXExpressionParser:
    """
    Parser for SPDX license expressions with proper operator precedence.
    
    Follows the SPDX specification for license expressions:
    - Operators: AND/and, OR/or, WITH/with (exact case only, not mixed)
    - Precedence: OR < AND < WITH < +
    - License IDs are case-insensitive
    - Supports LicenseRef-xxx and AdditionRef-xxx custom references
    - Supports DocumentRef-xxx: prefix for external document references
    - Supports parentheses for grouping
    """
    
    def __init__(self, license_aliases: Dict[str, str] = None, combined_aliases: Dict[str, str] = None):
        """
        Initialize the parser.
        
        Args:
            license_aliases: Mapping of non-standard license names to SPDX IDs.
            combined_aliases: Mapping of combined expressions to single licenses.
        """
        self.logger = logging.getLogger(__name__)
        self.license_aliases = license_aliases or {}
        self.combined_aliases = combined_aliases or {}
        
        # Remove _comment keys if present (from JSON)
        self.license_aliases = {k.lower(): v for k, v in self.license_aliases.items() if k != '_comment'}
        self.combined_aliases = {k.lower(): v for k, v in self.combined_aliases.items() if k != '_comment'}
        
        self.logger.debug(f"Initialized SPDXExpressionParser with {len(self.license_aliases)} license aliases "
                         f"and {len(self.combined_aliases)} combined aliases")
    
    def _is_valid_idstring(self, s: str) -> bool:
        """Check if string is a valid SPDX idstring (ALPHA / DIGIT / "-" / ".")"""
        return bool(IDSTRING_PATTERN.match(s))
    
    def _is_license_ref(self, s: str) -> bool:
        """Check if string is a LicenseRef (with optional DocumentRef prefix)."""
        return bool(LICENSE_REF_PATTERN.match(s))
    
    def _is_addition_ref(self, s: str) -> bool:
        """Check if string is an AdditionRef (with optional DocumentRef prefix)."""
        return bool(ADDITION_REF_PATTERN.match(s))
    
    def _tokenize(self, expression: str) -> List[Token]:
        """
        Tokenize an SPDX license expression according to the ABNF grammar.
        
        Handles:
        - Standard SPDX operators (AND/and, OR/or, WITH/with) - exact case only
        - Parentheses
        - License identifiers (idstring format)
        - LicenseRef-xxx and AdditionRef-xxx custom references
        - DocumentRef-xxx: prefix for external references
        - The + suffix for "or later" versions (no whitespace before +)
        - Non-standard: " + " as AND operator (legacy support)
        - Non-standard: "w/" as WITH (legacy support)
        """
        tokens = []
        pos = 0
        expression = expression.strip()
        had_whitespace = True  # Start of string counts as whitespace
        
        while pos < len(expression):
            # Skip whitespace and track if we did
            had_whitespace = False
            while pos < len(expression) and expression[pos].isspace():
                pos += 1
                had_whitespace = True
            
            if pos >= len(expression):
                break
            
            char = expression[pos]
            remaining = expression[pos:]
            
            # Check for parentheses
            if char == '(':
                tokens.append(Token(TokenType.LPAREN, '(', pos))
                pos += 1
                continue
            
            if char == ')':
                tokens.append(Token(TokenType.RPAREN, ')', pos))
                pos += 1
                continue
            
            # Handle + based on context:
            # - After whitespace and followed by whitespace: " + " = AND (non-standard)
            # - After whitespace and followed by non-whitespace: standalone + = PLUS (or-later for prev token)
            # - Directly after license ID (no whitespace): part of license-id+
            if char == '+':
                if had_whitespace:
                    # + after whitespace
                    if pos + 1 >= len(expression) or expression[pos + 1].isspace():
                        # " + " pattern = AND (non-standard syntax)
                        tokens.append(Token(TokenType.AND, '+', pos))
                    else:
                        # + followed by non-whitespace after whitespace = PLUS token
                        tokens.append(Token(TokenType.PLUS, '+', pos))
                else:
                    # + directly after license ID = or-later suffix
                    tokens.append(Token(TokenType.PLUS, '+', pos))
                pos += 1
                continue
            
            # Check for "w/" as WITH (non-standard but common)
            if remaining.lower().startswith('w/'):
                if len(remaining) == 2 or remaining[2].isspace():
                    tokens.append(Token(TokenType.WITH, 'w/', pos))
                    pos += 2
                    continue
            
            # Check for operators - SPDX spec requires exact case: AND/and, OR/or, WITH/with
            # (not And, aNd, etc.)
            for op_upper, op_lower, token_type in [
                ('AND', 'and', TokenType.AND),
                ('OR', 'or', TokenType.OR),
                ('WITH', 'with', TokenType.WITH)
            ]:
                if remaining.startswith(op_upper) or remaining.startswith(op_lower):
                    op_len = len(op_upper)
                    # Must be followed by whitespace, '(', or end of string
                    if op_len >= len(remaining) or remaining[op_len].isspace() or remaining[op_len] == '(':
                        tokens.append(Token(token_type, remaining[:op_len], pos))
                        pos += op_len
                        break
            else:
                # No operator matched - collect a license ID / ref
                # License IDs end at: whitespace, parentheses, or + (for or-later)
                id_start = pos
                
                while pos < len(expression):
                    c = expression[pos]
                    
                    # End at whitespace or parentheses
                    if c.isspace() or c in '()':
                        break
                    
                    # + ends the ID if followed by whitespace/end (or-later suffix)
                    if c == '+':
                        if pos + 1 >= len(expression) or expression[pos + 1].isspace():
                            break
                    
                    pos += 1
                
                if pos > id_start:
                    identifier = expression[id_start:pos]
                    
                    # Classify the identifier
                    if self._is_license_ref(identifier):
                        tokens.append(Token(TokenType.LICENSE_REF, identifier, id_start))
                    elif self._is_addition_ref(identifier):
                        tokens.append(Token(TokenType.ADDITION_REF, identifier, id_start))
                    else:
                        tokens.append(Token(TokenType.LICENSE_ID, identifier, id_start))
        
        tokens.append(Token(TokenType.EOF, '', len(expression)))
        return tokens
    
    def _normalize_license_id(self, license_id: str) -> str:
        """
        Normalize a license ID using the alias mapping.
        
        License IDs in SPDX are case-insensitive, so we do case-insensitive lookup.
        """
        if not license_id:
            return license_id
        
        license_id = license_id.strip()
        lookup_key = license_id.lower()
        
        if lookup_key in self.license_aliases:
            result = self.license_aliases[lookup_key]
            self.logger.debug(f"🔄 Normalized license ID '{license_id}' → '{result}'")
            return result
        
        return license_id
    
    def _apply_aliases_to_expression(self, expression: str) -> str:
        """
        Apply license aliases to the entire expression before tokenization.
        
        This handles non-standard license names with spaces like:
        - "Eclipse Distribution License v. 1.0" → "BSD-3-Clause"
        - "Public Domain" → "CC0-1.0"
        - "The Apache Software License, Version 2.0" → "Apache-2.0"
        
        Strategy:
        1. Only apply aliases that contain spaces (non-standard names)
        2. Apply longest-first to prevent partial matches
        3. Standard SPDX IDs without spaces are handled by _normalize_license_id
        """
        if not expression or not self.license_aliases:
            return expression
        
        # Only consider aliases that contain spaces or special chars (non-SPDX format)
        # Standard SPDX IDs (no spaces) are handled later by _normalize_license_id
        space_aliases = {
            k: v for k, v in self.license_aliases.items() 
            if ' ' in k or ',' in k or k != k.replace(' ', '')
        }
        
        if not space_aliases:
            return expression
        
        # Sort aliases by length (longest first) to avoid partial matches
        sorted_aliases = sorted(
            space_aliases.items(),
            key=lambda x: len(x[0]),
            reverse=True
        )
        
        result = expression
        
        for alias_lower, spdx_id in sorted_aliases:
            # Create pattern that matches the alias as a complete phrase
            # Boundaries: start/end of string, operators (AND/OR/WITH), parentheses, or other spaces
            # Use word boundary but allow for punctuation in aliases
            pattern = re.compile(
                r'(?:^|(?<=\s)|(?<=\()|(?<=\)))' + 
                re.escape(alias_lower) + 
                r'(?:$|(?=\s)|(?=\))|(?=\())',
                re.IGNORECASE
            )
            
            new_result = pattern.sub(spdx_id, result)
            if new_result != result:
                self.logger.debug(f"🔄 Applied alias in expression: '{alias_lower}' → '{spdx_id}'")
                result = new_result
        
        if result != expression:
            self.logger.debug(f"🔄 Expression after alias resolution: '{expression}' → '{result}'")
        
        return result
    
    def parse_and_evaluate(self, expression: str, license_policies: List[Dict]) -> Tuple[str, str]:
        """
        Parse and evaluate an SPDX license expression.
        
        Args:
            expression: SPDX license expression (e.g., "Apache-2.0 AND MIT")
            license_policies: List of license policy dictionaries with 'id' and 'usagePolicy'
            
        Returns:
            Tuple of (policy_result, explanation)
            policy_result is one of: "allow", "deny", "needs-review"
        """
        if not expression or expression in ['NO-LICENSE-FOUND', 'NOASSERTION', 'NONE']:
            return "needs-review", "No license found"
        
        expression = expression.strip()
        
        # Check combined aliases first (for complete expression matches)
        expr_lower = expression.lower()
        if expr_lower in self.combined_aliases:
            resolved = self.combined_aliases[expr_lower]
            self.logger.debug(f"🔄 Resolved combined alias '{expression}' → '{resolved}'")
            return self.parse_and_evaluate(resolved, license_policies)
        
        # Apply license aliases to the entire expression before tokenization
        # This handles non-standard license names with spaces like:
        # "Eclipse Distribution License v. 1.0" → "BSD-3-Clause"
        expression = self._apply_aliases_to_expression(expression)
        
        try:
            tokens = self._tokenize(expression)
            result = self._parse_expression(tokens, 0, license_policies)
            return result[0], result[1]
        except Exception as e:
            self.logger.warning(f"Failed to parse expression '{expression}': {e}")
            return "needs-review", f"Failed to parse license expression: {expression}"
    
    def _parse_expression(self, tokens: List[Token], pos: int, 
                         license_policies: List[Dict]) -> Tuple[str, str, int]:
        """
        Parse expression with correct operator precedence.
        
        Precedence (lowest to highest): OR < AND < WITH < +
        
        Returns: (policy, explanation, new_position)
        """
        return self._parse_or_expression(tokens, pos, license_policies)
    
    def _parse_or_expression(self, tokens: List[Token], pos: int,
                            license_policies: List[Dict]) -> Tuple[str, str, int]:
        """Parse OR expressions (lowest precedence)."""
        left_policy, left_expl, pos = self._parse_and_expression(tokens, pos, license_policies)
        
        results = [(left_policy, left_expl)]
        
        while pos < len(tokens) and tokens[pos].type == TokenType.OR:
            pos += 1  # consume OR
            right_policy, right_expl, pos = self._parse_and_expression(tokens, pos, license_policies)
            results.append((right_policy, right_expl))
        
        if len(results) == 1:
            return left_policy, left_expl, pos
        
        # OR: if any is "allow", result is "allow"
        policies = [r[0] for r in results]
        explanations = [r[1] for r in results]
        
        if any(p == "allow" for p in policies):
            return "allow", f"OR: at least one allowed ({'; '.join(explanations)})", pos
        elif all(p == "deny" for p in policies):
            return "deny", f"OR: all denied ({'; '.join(explanations)})", pos
        else:
            return "needs-review", f"OR: none allowed ({'; '.join(explanations)})", pos
    
    def _parse_and_expression(self, tokens: List[Token], pos: int,
                             license_policies: List[Dict]) -> Tuple[str, str, int]:
        """Parse AND expressions."""
        left_policy, left_expl, pos = self._parse_with_expression(tokens, pos, license_policies)
        
        results = [(left_policy, left_expl)]
        
        while pos < len(tokens) and tokens[pos].type == TokenType.AND:
            pos += 1  # consume AND
            right_policy, right_expl, pos = self._parse_with_expression(tokens, pos, license_policies)
            results.append((right_policy, right_expl))
        
        if len(results) == 1:
            return left_policy, left_expl, pos
        
        # AND: all must be "allow" for result to be "allow"
        policies = [r[0] for r in results]
        explanations = [r[1] for r in results]
        
        if all(p == "allow" for p in policies):
            return "allow", f"AND: all allowed ({'; '.join(explanations)})", pos
        elif any(p == "deny" for p in policies):
            return "deny", f"AND: at least one denied ({'; '.join(explanations)})", pos
        else:
            return "needs-review", f"AND: some need review ({'; '.join(explanations)})", pos
    
    def _parse_with_expression(self, tokens: List[Token], pos: int,
                              license_policies: List[Dict]) -> Tuple[str, str, int]:
        """
        Parse WITH expressions (license + exception).
        
        Grammar: simple-expression ("WITH" / "with") addition-expression
        """
        base_policy, base_expl, pos = self._parse_simple_expression(tokens, pos, license_policies)
        
        if pos < len(tokens) and tokens[pos].type == TokenType.WITH:
            pos += 1  # consume WITH
            
            # addition-expression = license-exception-id / addition-ref
            if pos < len(tokens) and tokens[pos].type in (TokenType.LICENSE_ID, TokenType.ADDITION_REF):
                exception_token = tokens[pos]
                exception_id = exception_token.value
                pos += 1
                
                # Extract base license ID from explanation
                base_id = base_expl.strip("'").split("'")[0] if "'" in base_expl else base_expl
                
                # Try to find policy for the combined form
                combined_policy = self._find_with_policy(base_id, exception_id, license_policies)
                
                if combined_policy:
                    return combined_policy, f"'{base_id} WITH {exception_id}'", pos
                
                # If base license is allowed, the WITH expression is allowed
                # (exceptions typically make licenses MORE permissive)
                if base_policy == "allow":
                    return "allow", f"'{base_id}' WITH '{exception_id}' (base allowed)", pos
                elif base_policy == "deny":
                    return "deny", f"'{base_id}' WITH '{exception_id}' (base denied)", pos
                else:
                    return "needs-review", f"'{base_id}' WITH '{exception_id}' (base needs review)", pos
        
        return base_policy, base_expl, pos
    
    def _parse_simple_expression(self, tokens: List[Token], pos: int,
                                 license_policies: List[Dict]) -> Tuple[str, str, int]:
        """
        Parse simple expressions.
        
        Grammar: simple-expression = license-id / license-id"+" / license-ref
        """
        if pos >= len(tokens) or tokens[pos].type == TokenType.EOF:
            return "needs-review", "Empty expression", pos
        
        token = tokens[pos]
        
        # Handle parentheses (compound expression)
        if token.type == TokenType.LPAREN:
            pos += 1  # consume (
            policy, expl, pos = self._parse_expression(tokens, pos, license_policies)
            
            # Expect closing paren
            if pos < len(tokens) and tokens[pos].type == TokenType.RPAREN:
                pos += 1  # consume )
            
            return policy, f"({expl})", pos
        
        # Handle license-ref (LicenseRef-xxx or DocumentRef-xxx:LicenseRef-xxx)
        if token.type == TokenType.LICENSE_REF:
            license_ref = token.value
            pos += 1
            
            # LicenseRef always needs review unless explicitly in policy
            policy = self._find_license_policy(license_ref, license_policies, False)
            if policy:
                return policy, f"'{license_ref}'", pos
            else:
                return "needs-review", f"'{license_ref}' (custom license reference)", pos
        
        # Handle license-id or license-id"+"
        if token.type == TokenType.LICENSE_ID:
            license_id = token.value
            pos += 1
            
            # Check for + suffix ("or later") - must be immediately after, no space
            or_later = False
            if pos < len(tokens) and tokens[pos].type == TokenType.PLUS:
                or_later = True
                pos += 1
            
            display_id = license_id + ('+' if or_later else '')
            
            # Find policy for this license
            policy = self._find_license_policy(license_id, license_policies, or_later)
            
            if policy:
                return policy, f"'{display_id}'", pos
            else:
                return "needs-review", f"'{display_id}' (no policy)", pos
        
        # Unexpected token
        return "needs-review", f"Unexpected token: {token}", pos
    
    def _find_license_policy(self, license_id: str, license_policies: List[Dict], 
                            or_later: bool = False) -> Optional[str]:
        """
        Find policy for a license ID.
        
        Tries:
        1. Exact match
        2. Normalized (via alias) match
        3. Case-insensitive match
        4. For "or later" (+), also check -only and -or-later variants
        """
        original_id = license_id.rstrip('+')
        
        # Normalize through aliases
        normalized_id = self._normalize_license_id(original_id)
        
        # Try exact match first
        for policy in license_policies:
            policy_id = policy.get('id', '')
            if policy_id == normalized_id or policy_id == original_id:
                return policy.get('usagePolicy')
        
        # Try case-insensitive match
        normalized_lower = normalized_id.lower()
        original_lower = original_id.lower()
        
        for policy in license_policies:
            policy_id_lower = policy.get('id', '').lower()
            if policy_id_lower == normalized_lower or policy_id_lower == original_lower:
                return policy.get('usagePolicy')
        
        # For "or later" licenses, also check variant forms
        if or_later:
            # E.g., for GPL-2.0+, also check GPL-2.0-only and GPL-2.0-or-later
            base = original_id.replace('-only', '').replace('-or-later', '')
            variants = [
                f"{base}-only",
                f"{base}-or-later",
                base,
            ]
            
            for variant in variants:
                for policy in license_policies:
                    if policy.get('id', '').lower() == variant.lower():
                        return policy.get('usagePolicy')
        
        return None
    
    def _find_with_policy(self, base_license: str, exception: str, 
                         license_policies: List[Dict]) -> Optional[str]:
        """
        Find policy for a license WITH exception combination.
        
        Tries various combined forms that might exist in the policy.
        """
        base_normalized = self._normalize_license_id(base_license)
        exception_normalized = self._normalize_license_id(exception)
        
        # Generate possible combined IDs
        combined_forms = [
            f"{base_normalized}-with-{exception_normalized}",
            f"{base_normalized} WITH {exception_normalized}",
        ]
        
        # Try without version numbers in exception (e.g., Classpath-exception-2.0 -> Classpath-exception)
        exception_base = re.sub(r'-\d+(\.\d+)*$', '', exception_normalized)
        if exception_base != exception_normalized:
            combined_forms.extend([
                f"{base_normalized}-with-{exception_base}",
                f"{base_normalized}-with-{exception_base}-exception",
            ])
        
        for combined in combined_forms:
            for policy in license_policies:
                if policy.get('id', '').lower() == combined.lower():
                    return policy.get('usagePolicy')
        
        return None
    
    def get_expression_components(self, expression: str) -> List[str]:
        """Extract all individual license IDs from an expression."""
        try:
            tokens = self._tokenize(expression)
            components = []
            
            for token in tokens:
                if token.type in (TokenType.LICENSE_ID, TokenType.LICENSE_REF):
                    components.append(token.value)
            
            return components
        except Exception:
            # Fallback: simple regex split
            parts = re.split(r'\s+(?:AND|OR|WITH|and|or|with)\s+', expression)
            return [p.strip().rstrip('+').replace('(', '').replace(')', '') for p in parts if p.strip()]


def test_parser():
    """Test the SPDX expression parser with aliases loaded from policy.json."""
    import json
    import os
    
    logging.basicConfig(level=logging.DEBUG)
    
    # Load aliases from policy.json
    script_dir = os.path.dirname(os.path.abspath(__file__))
    policy_path = os.path.join(script_dir, 'policy.json')
    
    license_aliases = {}
    combined_aliases = {}
    policies = []
    
    try:
        with open(policy_path, 'r') as f:
            policy_data = json.load(f)
            license_aliases = policy_data.get('licenseAliases', {})
            combined_aliases = policy_data.get('combinedLicenseAliases', {})
            policies = policy_data.get('policies', [])
            print(f"✅ Loaded {len(license_aliases)} license aliases, "
                  f"{len(combined_aliases)} combined aliases, "
                  f"and {len(policies)} policies from policy.json")
    except Exception as e:
        print(f"⚠️ Could not load from policy.json: {e}")
        # Fallback minimal policies for testing
        policies = [
            {"id": "Apache-2.0", "usagePolicy": "allow"},
            {"id": "MIT", "usagePolicy": "allow"},
            {"id": "EPL-1.0", "usagePolicy": "allow"},
            {"id": "EPL-2.0", "usagePolicy": "allow"},
            {"id": "GPL-2.0-only", "usagePolicy": "allow"},
            {"id": "GPL-2.0-with-classpath-exception", "usagePolicy": "allow"},
            {"id": "CDDL-1.0", "usagePolicy": "allow"},
            {"id": "CDDL-1.1", "usagePolicy": "allow"},
            {"id": "BSD-3-Clause", "usagePolicy": "allow"},
        ]
    
    parser = SPDXExpressionParser(license_aliases=license_aliases, combined_aliases=combined_aliases)
    
    test_cases = [
        # Standard SPDX expressions
        ("Apache-2.0", "allow"),
        ("MIT", "allow"),
        ("Apache-2.0 AND MIT", "allow"),
        ("MIT OR Apache-2.0", "allow"),
        ("GPL-2.0-only", "allow"),
        ("GPL-2.0-with-classpath-exception", "allow"),
        
        # The bug case: combined license with AND
        ("EPL-2.0 AND GPL-2.0-with-classpath-exception", "allow"),
        
        # WITH expressions
        ("EPL-2.0 WITH Classpath-exception-2.0", "allow"),
        ("GPL-2.0-only WITH Classpath-exception-2.0", "allow"),
        
        # Parentheses
        ("(MIT OR Apache-2.0) AND BSD-3-Clause", "allow"),
        ("MIT AND (Apache-2.0 OR BSD-3-Clause)", "allow"),
        
        # Or-later (+)
        ("GPL-2.0+", "allow"),
        
        # Non-standard expressions (resolved via aliases)
        ("CDDL + GPLv2 with classpath exception", "allow"),  # via combined alias
        ("GPL2 w/ CPE", "allow"),  # w/ = WITH, via alias
        ("gplv2 with classpath exception", "allow"),  # via alias
        
        # Case insensitivity
        ("apache-2.0", "allow"),
        ("APACHE-2.0", "allow"),
        ("mit AND apache-2.0", "allow"),
    ]
    
    print("\n" + "="*80)
    print("SPDX Expression Parser Test Results")
    print("="*80 + "\n")
    
    passed = 0
    failed = 0
    
    for expression, expected in test_cases:
        policy, explanation = parser.parse_and_evaluate(expression, policies)
        status = "✅" if policy == expected else "❌"
        
        if policy == expected:
            passed += 1
        else:
            failed += 1
        
        print(f"{status} '{expression}'")
        print(f"   Expected: {expected}, Got: {policy}")
        print(f"   Explanation: {explanation}\n")
    
    print("="*80)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*80)
    
    return failed == 0


if __name__ == "__main__":
    import sys
    success = test_parser()
    sys.exit(0 if success else 1)
