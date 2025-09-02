#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
Upgrade Script: Enable Intelligent License Resolution
Upgrades the SBOM auditor to use intelligent license resolution.
"""

import os
import shutil
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def upgrade_to_intelligent_resolution():
    """Upgrade to enhanced versions with intelligent license resolution."""
    
    logger.info("🚀 Upgrading to Intelligent License Resolution")
    logger.info("=" * 50)
    
    helpers_dir = os.path.dirname(os.path.abspath(__file__))
    
    upgrades = [
        {
            'original': os.path.join(helpers_dir, 'enrich_sbom.py'),
            'enhanced': os.path.join(helpers_dir, 'enrich_sbom_enhanced.py'),
            'backup': os.path.join(helpers_dir, 'enrich_sbom.py.backup')
        },
        {
            'original': os.path.join(helpers_dir, 'audit_licenses.py'),
            'enhanced': os.path.join(helpers_dir, 'audit_licenses_enhanced.py'),
            'backup': os.path.join(helpers_dir, 'audit_licenses.py.backup')
        }
    ]
    
    for upgrade in upgrades:
        original_file = upgrade['original']
        enhanced_file = upgrade['enhanced']
        backup_file = upgrade['backup']
        
        if not os.path.exists(enhanced_file):
            logger.warning(f"⚠️ Enhanced version not found: {enhanced_file}")
            continue
            
        if os.path.exists(original_file):
            # Create backup
            logger.info(f"📋 Backing up {os.path.basename(original_file)}")
            shutil.copy2(original_file, backup_file)
            
            # Replace with enhanced version
            logger.info(f"🔄 Upgrading {os.path.basename(original_file)}")
            shutil.copy2(enhanced_file, original_file)
            
            logger.info(f"✅ Upgraded {os.path.basename(original_file)}")
        else:
            logger.warning(f"⚠️ Original file not found: {original_file}")
    
    # Create convenience scripts
    create_resolution_test_script()
    
    logger.info("=" * 50)
    logger.info("✅ Upgrade completed!")
    logger.info("")
    logger.info("🎯 New Features:")
    logger.info("  • Automatic SPDX license ID resolution")  
    logger.info("  • AI-powered license name recognition")
    logger.info("  • Pattern matching for common license variants")
    logger.info("  • Enhanced audit reporting with resolution details")
    logger.info("")
    logger.info("🔧 Usage:")
    logger.info("  • License resolution is enabled by default")
    logger.info("  • Use --no-resolve-licenses to disable")
    logger.info("  • Set GITHUB_TOKEN for AI-powered fallback")
    logger.info("")
    logger.info("🧪 Test the new functionality:")
    logger.info("  python test_license_resolution.py")


def create_resolution_test_script():
    """Create a test script for the new license resolution functionality."""
    
    helpers_dir = os.path.dirname(os.path.abspath(__file__))
    test_script_path = os.path.join(helpers_dir, 'test_license_resolution.py')
    
    test_script_content = '''#!/usr/bin/env python3
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
    
    print("\\n🔗 Testing SBOM Integration:")
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
    
    print("\\n✅ Integration test completed!")


if __name__ == '__main__':
    test_resolution_capabilities()
'''
    
    with open(test_script_path, 'w') as f:
        f.write(test_script_content)
    
    # Make executable
    os.chmod(test_script_path, 0o755)
    logger.info(f"📝 Created test script: {test_script_path}")


def rollback_upgrade():
    """Rollback to original versions."""
    
    logger.info("🔄 Rolling back upgrade")
    logger.info("=" * 30)
    
    helpers_dir = os.path.dirname(os.path.abspath(__file__))
    
    backup_files = [
        os.path.join(helpers_dir, 'enrich_sbom.py.backup'),
        os.path.join(helpers_dir, 'audit_licenses.py.backup')
    ]
    
    for backup_file in backup_files:
        if os.path.exists(backup_file):
            original_file = backup_file.replace('.backup', '')
            shutil.copy2(backup_file, original_file)
            logger.info(f"✅ Restored {os.path.basename(original_file)}")
        else:
            logger.warning(f"⚠️ Backup not found: {backup_file}")
    
    logger.info("✅ Rollback completed!")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--rollback':
        rollback_upgrade()
    else:
        upgrade_to_intelligent_resolution()
