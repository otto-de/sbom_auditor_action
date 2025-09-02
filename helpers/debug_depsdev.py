#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
Debug Script for deps.dev License Resolution
Debugs what deps.dev returns for specific packages and how our resolution handles it.
"""

import requests
import json
import sys
import os
from urllib.parse import quote
from license_resolver import LicenseResolver

def debug_depsdev_package(package_url):
    """
    Debug what deps.dev returns for a specific package.
    
    Args:
        package_url: Package URL to debug (e.g., 'pkg:maven/org.junit.platform/junit-platform-commons@1.10.0')
    """
    print(f"🔍 Debugging deps.dev response for: {package_url}")
    print("=" * 80)
    
    # Parse the package URL
    if not package_url.startswith('pkg:'):
        print(f"❌ Invalid package URL format: {package_url}")
        return
    
    # Extract components
    parts = package_url.split('/')
    if len(parts) < 3:
        print(f"❌ Cannot parse package URL: {package_url}")
        return
        
    ecosystem = parts[0].replace('pkg:', '')
    namespace = parts[1] if len(parts) > 2 else None
    name_with_version = parts[-1]
    name = name_with_version.split('@')[0]
    
    if namespace:
        full_name = f"{namespace}/{name}"
    else:
        full_name = name
    
    print(f"📦 Package Details:")
    print(f"   Ecosystem: {ecosystem}")
    print(f"   Namespace: {namespace}")
    print(f"   Name: {name}")
    print(f"   Full Name: {full_name}")
    print()
    
    # Query deps.dev API
    try:
        encoded_name = quote(full_name, safe='')
        url = f"https://api.deps.dev/v3/systems/{ecosystem}/packages/{encoded_name}"
        
        print(f"🌐 API URL: {url}")
        print()
        
        response = requests.get(url, timeout=10)
        print(f"📡 HTTP Response: {response.status_code}")
        
        if response.status_code != 200:
            print(f"❌ API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return
            
        data = response.json()
        
        # Pretty print the raw response
        print(f"📄 Raw API Response:")
        print(json.dumps(data, indent=2)[:2000] + "..." if len(json.dumps(data, indent=2)) > 2000 else json.dumps(data, indent=2))
        print()
        
        # Extract license information from versions
        versions = data.get('versions', [])
        print(f"🏷️  Found {len(versions)} versions")
        
        if versions:
            print(f"📋 License data from versions:")
            for i, version in enumerate(versions[:5]):  # Show first 5 versions
                version_num = version.get('version', f'Version {i+1}')
                licenses = version.get('licenses', [])
                
                print(f"   Version {version_num}:")
                print(f"     Raw licenses: {licenses}")
                
                if licenses:
                    for j, lic in enumerate(licenses):
                        print(f"     License {j+1}: {type(lic)} = {lic}")
                        
                        if isinstance(lic, dict):
                            for key, value in lic.items():
                                print(f"       {key}: {value}")
                print()
        
        # Test our license resolution on the found licenses
        print(f"🎯 Testing License Resolution:")
        print("-" * 40)
        
        resolver = LicenseResolver()
        
        for version in versions[:3]:  # Test first 3 versions
            version_num = version.get('version', 'Unknown')
            licenses = version.get('licenses', [])
            
            print(f"Version {version_num}:")
            
            if not licenses:
                print("   No licenses found")
                continue
                
            for lic in licenses:
                license_name = None
                
                if isinstance(lic, str):
                    license_name = lic
                elif isinstance(lic, dict):
                    license_name = lic.get('license') or lic.get('name') or str(lic)
                
                if license_name:
                    print(f"   Original: '{license_name}'")
                    
                    # Test resolution
                    result = resolver.resolve_license(license_name)
                    
                    if result['resolved']:
                        print(f"   ✅ Resolved: '{result['resolved']}' (method: {result['method']}, confidence: {result['confidence']})")
                    else:
                        print(f"   ❌ Unresolved (method: {result['method']})")
                    
                    print()
            
    except Exception as e:
        print(f"❌ Error querying deps.dev: {e}")
        import traceback
        traceback.print_exc()


def debug_junit_platform():
    """Debug the specific junit-platform-commons case."""
    
    print("🧪 Debugging JUnit Platform Commons")
    print("=" * 50)
    
    test_packages = [
        "pkg:maven/org.junit.platform/junit-platform-commons@1.10.0",
        "pkg:maven/org.junit.platform/junit-platform-commons@1.9.3",
        "pkg:maven/org.junit.platform/junit-platform-commons@1.8.2"
    ]
    
    for package_url in test_packages:
        debug_depsdev_package(package_url)
        print("=" * 80)
        print()


def debug_license_resolution_patterns():
    """Test various license name patterns that might appear in deps.dev."""
    
    print("🔬 Testing License Resolution Patterns")
    print("=" * 50)
    
    test_cases = [
        "Eclipse Public License v2.0",
        "Eclipse Public License - v 2.0", 
        "Eclipse Public License 2.0",
        "EPL-2.0",
        "The Eclipse Public License, Version 2.0",
        "Eclipse Public License (EPL) v2.0",
        "non-standard",
        '{"license": "Eclipse Public License v2.0"}',
        "Apache License 2.0",
        "Apache-2.0",
        "MIT License",
        "MIT"
    ]
    
    resolver = LicenseResolver()
    
    for test_case in test_cases:
        print(f"Testing: '{test_case}'")
        result = resolver.resolve_license(test_case)
        
        if result['resolved']:
            print(f"  ✅ → '{result['resolved']}' ({result['method']}, {result['confidence']})")
        else:
            print(f"  ❌ → Unresolved ({result['method']})")
        print()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Debug specific package from command line
        package_url = sys.argv[1]
        debug_depsdev_package(package_url)
    else:
        # Debug JUnit Platform by default
        debug_junit_platform()
        print()
        debug_license_resolution_patterns()
