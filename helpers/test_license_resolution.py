#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
Test Script for License Resolution
Tests the intelligent license resolution functionality.
"""

import json
import os
import tempfile
import sys
from license_resolver import LicenseResolver

def test_resolution_capabilities():
    """Test the license resolution capabilities."""
    
    print("🧪 Testing Intelligent License Resolution")
    print("=" * 50)
    
    # Test cases from real Maven Central data
    test_cases = [
        "Eclipse Public License v2.0",
        "Eclipse Public License - v 1.0", 
        "The Apache Software License, Version 2.0",
        "MIT License",
        "Mozilla Public License Version 2.0",
        "BSD 3-Clause License",
        "Common Development and Distribution License 1.0",
        "GNU General Public License, version 3",
        "non-standard",  # Should remain unresolved
        "Weird unknown license"  # Should remain unresolved
    ]
    
    # Test SPDX resolution (no AI needed)
    print("📋 Testing SPDX Pattern Matching:")
    resolver = LicenseResolver()
    
    resolved_count = 0
    for test_case in test_cases:
        result = resolver.resolve_license(test_case)
        status = "✅" if result['resolved'] else "❌"
        print(f"  {status} '{test_case}'")
        if result['resolved']:
            print(f"      → {result['resolved']} ({result['method']})")
            resolved_count += 1
        else:
            print(f"      → Unresolved ({result['method']})")
        print()
    
    print(f"📊 Resolution Summary: {resolved_count}/{len(test_cases)} licenses resolved")
    
    # Test integration with sample SBOM
    test_integration()


def test_integration():
    """Test integration with SBOM processing."""
    
    print("\n🔗 Testing SBOM Integration:")
    print("-" * 30)
    
    # Create a sample SBOM with problematic licenses
    sample_sbom = {
        "packages": [
            {
                "name": "eclipse-core",
                "versionInfo": "3.18.0",
                "licenseConcluded": "Eclipse Public License v2.0",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:maven/org.eclipse/core@3.18.0"}
                ]
            },
            {
                "name": "apache-commons",
                "versionInfo": "2.11.0", 
                "licenseConcluded": "The Apache Software License, Version 2.0",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:maven/org.apache.commons/commons-lang3@2.11.0"}
                ]
            },
            {
                "name": "mystery-lib",
                "versionInfo": "1.0.0",
                "licenseConcluded": "non-standard",
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:maven/com.example/mystery-lib@1.0.0"}
                ]
            }
        ]
    }
    
    # Test enhanced enrichment
    try:
        from enhanced_license_enricher import EnhancedLicenseEnricher
        
        enricher = EnhancedLicenseEnricher()
        result = enricher.enrich_sbom_packages(sample_sbom)
        
        print("📦 Sample SBOM Processing Results:")
        for pkg in result['packages']:
            print(f"  • {pkg['name']}: {pkg.get('licenseConcluded', 'N/A')}")
            if 'enrichment' in pkg and 'licenseResolution' in pkg['enrichment']:
                resolution = pkg['enrichment']['licenseResolution']
                if resolution['resolved']:
                    print(f"    Resolved: {resolution['original']} → {resolution['resolved']}")
                    print(f"    Method: {resolution['resolution_method']}")
        
    except ImportError as e:
        print(f"⚠️ Enhanced enricher not available: {e}")
    
    print("\n✅ Integration test completed!")


if __name__ == '__main__':
    test_resolution_capabilities()
