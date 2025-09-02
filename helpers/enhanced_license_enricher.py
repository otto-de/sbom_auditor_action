#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG  
# SPDX-License-Identifier: Apache-2.0

"""
Enhanced License Enrichment with Intelligent Resolution
Enriches SBOM data with resolved license information using SPDX matching and AI fallback.
"""

import json
import os
import sys
from typing import Dict, List, Optional, Set
import logging
from collections import defaultdict

# Add helpers to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from license_resolver import LicenseResolver

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EnhancedLicenseEnricher:
    """Enhanced license enricher with intelligent license resolution."""
    
    def __init__(self, policy_file: str = 'policy.json', ai_api_key: Optional[str] = None):
        """
        Initialize the enhanced enricher.
        
        Args:
            policy_file: Path to policy JSON file
            ai_api_key: API key for AI-powered resolution (optional)
        """
        self.policy_file = policy_file
        self.resolver = LicenseResolver(api_key=ai_api_key, ai_provider='github')
        self.policy = self._load_policy()
        self.resolution_stats = defaultdict(int)
        
    def _load_policy(self) -> Dict:
        """Load the license policy from file."""
        try:
            with open(self.policy_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"❌ Policy file not found: {self.policy_file}")
            return {'licenses': []}
        except json.JSONDecodeError as e:
            logger.error(f"❌ Invalid JSON in policy file: {e}")
            return {'licenses': []}
    
    def _get_license_policy(self, license_id: str) -> Optional[str]:
        """Get the usage policy for a license ID."""
        for license_entry in self.policy.get('licenses', []):
            if license_entry.get('id') == license_id:
                return license_entry.get('usagePolicy')
        return None
    
    def _is_known_license(self, license_id: str) -> bool:
        """Check if a license ID is in our policy."""
        return any(
            license_entry.get('id') == license_id 
            for license_entry in self.policy.get('licenses', [])
        )
    
    def resolve_unknown_license(self, license_name: str) -> Dict[str, any]:
        """
        Resolve an unknown license name using intelligent matching.
        
        Args:
            license_name: The license name to resolve
            
        Returns:
            Resolution result with recommended policy
        """
        if not license_name or license_name in ['non-standard', 'Weird unknown license']:
            return {
                'original': license_name,
                'resolved': None,
                'recommended_policy': 'needs-review',
                'reason': 'ambiguous_name'
            }
        
        # Try to resolve the license
        resolution = self.resolver.resolve_license(license_name)
        self.resolution_stats[resolution['method']] += 1
        
        if resolution['resolved']:
            resolved_id = resolution['resolved']
            
            # Check if the resolved license is in our policy
            if self._is_known_license(resolved_id):
                existing_policy = self._get_license_policy(resolved_id)
                return {
                    'original': license_name,
                    'resolved': resolved_id,
                    'recommended_policy': existing_policy,
                    'reason': f'resolved_to_known_license',
                    'resolution_method': resolution['method'],
                    'confidence': resolution['confidence']
                }
            else:
                # Resolved to a license not in our policy
                return {
                    'original': license_name,
                    'resolved': resolved_id,
                    'recommended_policy': 'needs-review',
                    'reason': 'resolved_to_unknown_license',
                    'resolution_method': resolution['method'],
                    'confidence': resolution['confidence']
                }
        else:
            # Could not resolve
            return {
                'original': license_name,
                'resolved': None,
                'recommended_policy': 'needs-review',
                'reason': 'unresolvable',
                'resolution_method': resolution['method'],
                'confidence': resolution['confidence']
            }
    
    def enrich_sbom_packages(self, sbom_data: Dict) -> Dict:
        """
        Enrich SBOM packages with resolved license information.
        
        Args:
            sbom_data: SBOM data dictionary
            
        Returns:
            Enriched SBOM data
        """
        logger.info("🔄 Starting enhanced license enrichment...")
        
        packages = sbom_data.get('packages', [])
        enriched_count = 0
        resolved_count = 0
        
        for package in packages:
            license_concluded = package.get('licenseConcluded')
            
            # Skip if already processed or no license info
            if not license_concluded or license_concluded == 'NOASSERTION':
                continue
                
            # Check if this is a license that needs resolution
            if license_concluded in ['non-standard', 'Weird unknown license'] or not self._is_known_license(license_concluded):
                
                # Try to get the original license name from package info
                original_license = None
                for external_ref in package.get('externalRefs', []):
                    if external_ref.get('referenceType') == 'purl':
                        # Could extract license info from package metadata if available
                        pass
                
                # If we have additional license info, use it; otherwise use the concluded license
                license_to_resolve = original_license or license_concluded
                
                # Resolve the license
                resolution_result = self.resolve_unknown_license(license_to_resolve)
                
                # Add enrichment metadata
                if 'enrichment' not in package:
                    package['enrichment'] = {}
                    
                package['enrichment']['licenseResolution'] = resolution_result
                
                # Update license if resolved
                if resolution_result['resolved']:
                    package['licenseConcluded'] = resolution_result['resolved']
                    resolved_count += 1
                    
                enriched_count += 1
                
                # Log interesting resolutions
                if resolution_result['resolved']:
                    logger.info(f"✅ Resolved: '{resolution_result['original']}' → '{resolution_result['resolved']}' "
                              f"({resolution_result['resolution_method']})")
                else:
                    logger.info(f"⚠️ Unresolved: '{resolution_result['original']}' → needs-review")
        
        # Log statistics
        logger.info(f"📊 Enhanced enrichment completed:")
        logger.info(f"   📦 Packages enriched: {enriched_count}")  
        logger.info(f"   🎯 Licenses resolved: {resolved_count}")
        logger.info(f"   📈 Resolution methods:")
        for method, count in self.resolution_stats.items():
            logger.info(f"      {method}: {count}")
        
        return sbom_data
    
    def print_resolution_report(self):
        """Print a summary report of license resolutions."""
        total = sum(self.resolution_stats.values())
        if total == 0:
            logger.info("📊 No license resolutions performed")
            return
            
        logger.info("📊 License Resolution Report:")
        logger.info("=" * 40)
        for method, count in sorted(self.resolution_stats.items()):
            percentage = (count / total) * 100
            logger.info(f"   {method}: {count} ({percentage:.1f}%)")
        logger.info(f"   Total: {total}")


def test_enhanced_enrichment():
    """Test enhanced enrichment with sample data."""
    
    print("🧪 Testing Enhanced License Enrichment")
    print("=" * 50)
    
    # Sample SBOM data with problematic licenses
    sample_sbom = {
        "packages": [
            {
                "name": "test-package-1",
                "licenseConcluded": "Eclipse Public License v2.0",
                "externalRefs": []
            },
            {
                "name": "test-package-2", 
                "licenseConcluded": "The Apache Software License, Version 2.0",
                "externalRefs": []
            },
            {
                "name": "test-package-3",
                "licenseConcluded": "non-standard",
                "externalRefs": []
            },
            {
                "name": "test-package-4",
                "licenseConcluded": "MIT License",
                "externalRefs": []
            }
        ]
    }
    
    # Test enrichment
    enricher = EnhancedLicenseEnricher()
    enriched_sbom = enricher.enrich_sbom_packages(sample_sbom)
    
    # Print results
    for package in enriched_sbom['packages']:
        print(f"📦 {package['name']}")
        print(f"   Original: {package.get('licenseConcluded', 'N/A')}")
        
        if 'enrichment' in package and 'licenseResolution' in package['enrichment']:
            resolution = package['enrichment']['licenseResolution']
            print(f"   Resolved: {resolution.get('resolved', 'None')}")
            print(f"   Method: {resolution.get('resolution_method', 'N/A')}")
            print(f"   Policy: {resolution.get('recommended_policy', 'N/A')}")
        print()
    
    enricher.print_resolution_report()


if __name__ == '__main__':
    test_enhanced_enrichment()
