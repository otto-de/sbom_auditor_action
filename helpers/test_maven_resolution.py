#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
Test Script: Maven Non-Standard License Resolution
Tests the complete pipeline for resolving "non-standard" licenses from Maven packages.
"""

import json
import tempfile
import os
from enrich_sbom_enhanced import enrich_sbom_with_intelligent_resolution


def create_test_sbom_with_junit():
    """Create a test SBOM with junit-platform-commons that shows as non-standard in deps.dev."""
    
    test_sbom = {
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": "2025-09-02T10:00:00Z",
            "creators": ["Tool: test"]
        },
        "name": "Test SBOM with Non-Standard License",
        "packages": [
            {
                "SPDXID": "SPDXRef-junit-platform-commons",
                "name": "junit-platform-commons",
                "versionInfo": "1.10.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",  # Will be enriched
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:maven/org.junit.platform/junit-platform-commons@1.10.0"
                    }
                ]
            },
            {
                "SPDXID": "SPDXRef-commons-lang3",
                "name": "commons-lang3", 
                "versionInfo": "3.12.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
                    }
                ]
            }
        ]
    }
    
    return test_sbom


def test_maven_non_standard_resolution():
    """Test the complete non-standard license resolution pipeline."""
    
    print("🧪 Testing Maven Non-Standard License Resolution")
    print("=" * 60)
    
    # Create test SBOM
    test_sbom = create_test_sbom_with_junit()
    
    # Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(test_sbom, f, indent=2)
        input_file = f.name
    
    # Create output file
    output_file = input_file.replace('.json', '_enriched.json')
    
    try:
        print(f"📄 Input SBOM: {input_file}")
        print(f"📄 Output SBOM: {output_file}")
        print()
        
        # Test enrichment with license resolution
        print("🚀 Running enrichment with intelligent license resolution...")
        enrich_sbom_with_intelligent_resolution(
            input_file, 
            output_file, 
            cache_ttl_hours=1,  # Short cache for testing
            resolve_licenses=True
        )
        
        print()
        print("🔍 Analyzing results...")
        
        # Read the enriched SBOM
        with open(output_file, 'r') as f:
            enriched_sbom = json.load(f)
        
        # Check the results
        for package in enriched_sbom.get('packages', []):
            name = package.get('name')
            concluded_license = package.get('licenseConcluded', 'N/A')
            
            print(f"📦 Package: {name}")
            print(f"   License Concluded: {concluded_license}")
            
            # Check for enrichment metadata
            if 'enrichment' in package:
                enrichment = package['enrichment']
                
                if 'licenseResolutions' in enrichment:
                    print("   License Resolutions:")
                    for resolution in enrichment['licenseResolutions']:
                        original = resolution.get('original')
                        resolved = resolution.get('resolved')
                        method = resolution.get('method')
                        confidence = resolution.get('confidence')
                        
                        print(f"     • '{original}' → '{resolved}' ({method}, {confidence})")
            print()
        
        print("✅ Test completed successfully!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup temp files
        try:
            os.unlink(input_file)
            os.unlink(output_file)
        except:
            pass


def test_direct_license_extraction():
    """Test direct license extraction from Maven packages."""
    
    print("🔬 Testing Direct Maven License Extraction")
    print("=" * 50)
    
    test_packages = [
        ("org.junit.platform:junit-platform-commons", "1.10.0"),
        ("org.apache.commons:commons-lang3", "3.12.0"),
        ("org.springframework:spring-core", "5.3.21"),
        ("com.fasterxml.jackson.core:jackson-core", "2.13.3")
    ]
    
    from enrich_sbom_enhanced import get_maven_license_from_pom
    
    for package_name, version in test_packages:
        print(f"📦 Testing {package_name}:{version}")
        
        license_name = get_maven_license_from_pom(package_name, version)
        
        if license_name:
            print(f"   ✅ License: {license_name}")
            
            # Test resolution
            from license_resolver import LicenseResolver
            resolver = LicenseResolver()
            result = resolver.resolve_license(license_name)
            
            if result['resolved']:
                print(f"   🎯 Resolved: {result['resolved']} ({result['method']})")
            else:
                print(f"   ❌ Could not resolve: {license_name}")
        else:
            print(f"   ❌ No license found in POM")
        
        print()


if __name__ == '__main__':
    test_direct_license_extraction()
    print()
    test_maven_non_standard_resolution()
