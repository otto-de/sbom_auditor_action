#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
License Resolver: Intelligent license name to SPDX-ID resolution
Resolves non-standard license names to SPDX identifiers using:
1. SPDX License List fuzzy matching
2. AI-powered license name recognition (fallback)
"""

import requests
import json
import re
import logging
from typing import Optional, Dict, List, Tuple
from difflib import SequenceMatcher
from functools import lru_cache

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LicenseResolver:
    """Resolves license names to SPDX identifiers using multiple strategies."""
    
    def __init__(self, api_key: Optional[str] = None, ai_provider: str = 'github'):
        """
        Initialize the License Resolver.
        
        Args:
            api_key: API key for AI-powered fallback
            ai_provider: AI provider to use ('github', 'openai', 'azure', 'aws')
        """
        self.api_key = api_key
        self.ai_provider = ai_provider
        self._spdx_licenses = None
        self._spdx_exceptions = None
        
    @lru_cache(maxsize=1)
    def _fetch_spdx_data(self) -> Tuple[Dict[str, Dict], Dict[str, Dict]]:
        """
        Fetch and cache SPDX license and exception data.
        
        Returns:
            Tuple of (licenses_dict, exceptions_dict)
        """
        logger.info("🔄 Fetching SPDX license data...")
        
        try:
            # Fetch licenses
            licenses_response = requests.get(
                'https://raw.githubusercontent.com/spdx/license-list-data/main/json/licenses.json',
                timeout=10
            )
            licenses_response.raise_for_status()
            licenses_data = licenses_response.json()
            
            # Fetch exceptions
            exceptions_response = requests.get(
                'https://raw.githubusercontent.com/spdx/license-list-data/main/json/exceptions.json', 
                timeout=10
            )
            exceptions_response.raise_for_status()
            exceptions_data = exceptions_response.json()
            
            # Create lookup dictionaries
            licenses_dict = {}
            for license_info in licenses_data.get('licenses', []):
                license_id = license_info['licenseId']
                licenses_dict[license_id] = {
                    'name': license_info['name'],
                    'id': license_id,
                    'deprecated': license_info.get('isDeprecatedLicenseId', False),
                    'osi_approved': license_info.get('isOsiApproved', False),
                    'see_also': license_info.get('seeAlso', [])
                }
                
            exceptions_dict = {}
            for exception_info in exceptions_data.get('exceptions', []):
                exception_id = exception_info['licenseExceptionId']
                exceptions_dict[exception_id] = {
                    'name': exception_info['name'],
                    'id': exception_id,
                    'deprecated': exception_info.get('isDeprecatedLicenseId', False)
                }
                
            logger.info(f"✅ Loaded {len(licenses_dict)} licenses and {len(exceptions_dict)} exceptions")
            return licenses_dict, exceptions_dict
            
        except Exception as e:
            logger.error(f"❌ Failed to fetch SPDX data: {e}")
            return {}, {}
    
    def _normalize_license_name(self, license_name: str) -> str:
        """
        Normalize license name for better matching.
        
        Args:
            license_name: Raw license name
            
        Returns:
            Normalized license name
        """
        if not license_name:
            return ""
            
        # Convert to lowercase and remove extra whitespace
        normalized = re.sub(r'\s+', ' ', license_name.strip().lower())
        
        # Remove common prefixes/suffixes
        normalized = re.sub(r'^(the\s+)', '', normalized)
        normalized = re.sub(r'\s+(license|licence)(\s*$)', ' license', normalized)
        
        # Normalize version patterns
        normalized = re.sub(r'\s*v\.?\s*', ' v', normalized)
        normalized = re.sub(r'\s*version\s+', ' v', normalized)
        
        # Remove punctuation that doesn't affect meaning
        normalized = re.sub(r'[,\(\)]', '', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized
    
    def _fuzzy_match_spdx(self, license_name: str, min_ratio: float = 0.8) -> Optional[str]:
        """
        Fuzzy match license name against SPDX license list.
        
        Args:
            license_name: License name to match
            min_ratio: Minimum similarity ratio (0.0-1.0)
            
        Returns:
            SPDX license ID if match found, None otherwise
        """
        if not license_name:
            return None
            
        if self._spdx_licenses is None:
            self._spdx_licenses, self._spdx_exceptions = self._fetch_spdx_data()
            
        if not self._spdx_licenses:
            return None
            
        normalized_input = self._normalize_license_name(license_name)
        best_match = None
        best_ratio = 0.0
        
        # Check exact matches first
        for license_id, license_info in self._spdx_licenses.items():
            # Check against license ID
            if normalized_input == license_id.lower():
                return license_id
                
            # Check against normalized name
            normalized_name = self._normalize_license_name(license_info['name'])
            if normalized_input == normalized_name:
                return license_id
        
        # Special pattern matching for common cases
        patterns = {
            r'apache.*software.*license.*v?\.?2\.?0?': 'Apache-2.0',
            r'apache.*license.*v?\.?2\.?0?': 'Apache-2.0',
            r'bsd.*3.*clause': 'BSD-3-Clause',
            r'bsd.*3': 'BSD-3-Clause',
            r'mit.*license': 'MIT',
            r'eclipse.*public.*license.*v?\.?2\.?0?': 'EPL-2.0',
            r'eclipse.*public.*license.*v?\.?1\.?0?': 'EPL-1.0',
            r'mozilla.*public.*license.*v?\.?2\.?0?': 'MPL-2.0',
            r'gnu.*general.*public.*license.*v?\.?3': 'GPL-3.0-only',
            r'gnu.*general.*public.*license.*v?\.?2': 'GPL-2.0-only',
            r'lgpl.*v?\.?3': 'LGPL-3.0-only',
            r'lgpl.*v?\.?2\.?1': 'LGPL-2.1-only'
        }
        
        for pattern, spdx_id in patterns.items():
            if re.search(pattern, normalized_input):
                if spdx_id in self._spdx_licenses:
                    logger.info(f"🎯 Pattern match: '{license_name}' → '{spdx_id}'")
                    return spdx_id
        
        # Fuzzy matching
        for license_id, license_info in self._spdx_licenses.items():
            normalized_name = self._normalize_license_name(license_info['name'])

            # Length-ratio guard: when the candidate name is significantly shorter
            # than the input, require a higher similarity score to avoid false
            # positives caused by short SPDX names being "almost substrings" of
            # longer inputs (e.g. "SL License" matching "SLF4J License").
            # We compute the fraction of the shorter string relative to the longer
            # one and boost the required ratio proportionally.
            if normalized_name:
                shorter_frac = min(len(normalized_input), len(normalized_name)) / max(
                    len(normalized_input), len(normalized_name), 1
                )
                # Boost required ratio: 0.5 * (1 - shorter_frac) added on top of
                # min_ratio.  E.g. for shorter_frac=0.77 the required ratio becomes
                # 0.8 + 0.5 * 0.23 ≈ 0.915, which rejects the SLF4J→SL false-positive
                # while still accepting legitimate close matches like EPL-2.0.
                effective_min_ratio = min_ratio + max(0.0, (1.0 - shorter_frac) * 0.5)
            else:
                effective_min_ratio = min_ratio

            # Compare against license name
            ratio = SequenceMatcher(None, normalized_input, normalized_name).ratio()
            if ratio > best_ratio and ratio >= effective_min_ratio:
                best_ratio = ratio
                best_match = license_id

            # Compare against license ID (lowercased)
            ratio = SequenceMatcher(None, normalized_input, license_id.lower()).ratio()
            id_shorter_frac = min(len(normalized_input), len(license_id)) / max(
                len(normalized_input), len(license_id), 1
            )
            id_effective_min = min_ratio + max(0.0, (1.0 - id_shorter_frac) * 0.5)
            if ratio > best_ratio and ratio >= id_effective_min:
                best_ratio = ratio
                best_match = license_id
        
        if best_match:
            logger.info(f"🎯 Fuzzy match: '{license_name}' → '{best_match}' (ratio: {best_ratio:.3f})")
            
        return best_match
    
    def _ai_resolve_license(self, license_name: str) -> Optional[str]:
        """
        Use AI to resolve license name to SPDX identifier.
        
        Args:
            license_name: License name to resolve
            
        Returns:
            SPDX license ID if resolved, None otherwise
        """
        if not self.api_key or not license_name:
            return None
            
        logger.info(f"🤖 Using AI to resolve: '{license_name}'")
        
        prompt = f"""You are an expert on open source licenses and SPDX identifiers. 

Given this license name: "{license_name}"

Please provide the correct SPDX license identifier. Respond ONLY with the SPDX ID (e.g., "EPL-2.0", "Apache-2.0", "MIT") or "UNKNOWN" if you cannot determine it.

Common examples:
- "Eclipse Public License v2.0" → "EPL-2.0"
- "Eclipse Public License - v 1.0" → "EPL-1.0"  
- "Apache License, Version 2.0" → "Apache-2.0"
- "MIT License" → "MIT"
- "GNU General Public License v3.0" → "GPL-3.0-only"

Response format: Just the SPDX ID or "UNKNOWN"."""

        try:
            if self.ai_provider == 'github':
                return self._github_models_resolve(prompt)
            elif self.ai_provider == 'openai':
                return self._openai_resolve(prompt)
            # Add other providers as needed
            else:
                logger.warning(f"⚠️ Unsupported AI provider: {self.ai_provider}")
                return None
                
        except Exception as e:
            logger.error(f"❌ AI resolution failed: {e}")
            return None
    
    def _github_models_resolve(self, prompt: str) -> Optional[str]:
        """Resolve using GitHub Models API."""
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'messages': [
                    {'role': 'user', 'content': prompt}
                ],
                'model': 'gpt-4o-mini',
                'max_tokens': 50,
                'temperature': 0.1
            }
            
            response = requests.post(
                'https://models.inference.ai.azure.com/chat/completions',
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content'].strip()
                
                if content and content != "UNKNOWN":
                    logger.info(f"🎯 AI resolved: '{content}'")
                    return content
                    
            else:
                logger.error(f"❌ GitHub Models API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ GitHub Models resolution failed: {e}")
            
        return None
    
    def _openai_resolve(self, prompt: str) -> Optional[str]:
        """Resolve using OpenAI API."""
        try:
            from openai import OpenAI
            
            client = OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=50,
                temperature=0.1
            )
            
            content = response.choices[0].message.content.strip()
            if content and content != "UNKNOWN":
                logger.info(f"🎯 AI resolved: '{content}'")
                return content
                
        except Exception as e:
            logger.error(f"❌ OpenAI resolution failed: {e}")
            
        return None
    
    def resolve_license(self, license_name: str) -> Dict[str, any]:
        """
        Resolve a license name to SPDX identifier using multiple strategies.
        
        Args:
            license_name: License name to resolve
            
        Returns:
            Dictionary with resolution results
        """
        if not license_name or license_name.strip() == "":
            return {
                'original': license_name,
                'resolved': None,
                'method': 'empty',
                'confidence': 0.0
            }
        
        logger.debug(f"🔍 Resolving license: '{license_name}'")
        
        # Strategy 1: SPDX fuzzy matching
        spdx_match = self._fuzzy_match_spdx(license_name, min_ratio=0.8)
        if spdx_match:
            return {
                'original': license_name,
                'resolved': spdx_match,
                'method': 'spdx_fuzzy',
                'confidence': 0.9
            }
        
        # Strategy 2: AI-powered resolution (fallback)
        ai_match = self._ai_resolve_license(license_name)
        if ai_match:
            return {
                'original': license_name,
                'resolved': ai_match,
                'method': 'ai_assisted',
                'confidence': 0.7
            }
        
        # No resolution found
        return {
            'original': license_name,
            'resolved': None,
            'method': 'unresolved',
            'confidence': 0.0
        }


def test_license_resolver():
    """Test the license resolver with common problematic cases."""
    
    # Test cases from real Maven Central data
    test_cases = [
        "Eclipse Public License v2.0",
        "Eclipse Public License - v 1.0", 
        "The Apache Software License, Version 2.0",
        "MIT License",
        "GNU General Public License, version 2 (GPL2), with the classpath exception",
        "Mozilla Public License Version 2.0",
        "BSD 3-Clause License",
        "Common Development and Distribution License 1.0"
    ]
    
    print("🧪 Testing License Resolver")
    print("=" * 50)
    
    # Test without AI (SPDX matching only)
    resolver = LicenseResolver()
    
    for test_case in test_cases:
        result = resolver.resolve_license(test_case)
        print(f"📝 '{test_case}'")
        print(f"   → {result['resolved']} ({result['method']}, confidence: {result['confidence']})")
        print()


if __name__ == '__main__':
    test_license_resolver()
