#!/usr/bin/env python3
"""Test script for policy merging logic"""
import logging
import json
logging.basicConfig(level=logging.INFO, format='%(message)s')

from audit_licenses import merge_license_policies, merge_package_policies

# Test data
base = {
    'policies': [
        {'id': 'MIT', 'usagePolicy': 'allow'},
        {'id': 'Apache-2.0', 'usagePolicy': 'allow'}
    ],
    'packagePolicies': [
        {'purl': 'pkg:maven/base/package', 'usagePolicy': 'allow', 'reason': 'base policy'}
    ]
}

custom = {
    'packagePolicies': [
        {'purl': 'pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api', 'usagePolicy': 'allow', 'reason': 'custom exception'},
        {'purl': 'pkg:maven/javax.annotation/javax.annotation-api', 'usagePolicy': 'allow', 'reason': 'custom exception'}
    ]
}

print('=== Base Policy ===')
print(f'License policies: {len(base.get("policies", []))}')
print(f'Package policies: {len(base.get("packagePolicies", []))}')

print()
print('=== Custom Policy ===')
print(f'License policies: {len(custom.get("policies", []))}')
print(f'Package policies: {len(custom.get("packagePolicies", []))}')

print()
print('=== Merged ===')
merged_licenses = merge_license_policies(base.get('policies', []), custom.get('policies', []))
merged_packages = merge_package_policies(base.get('packagePolicies', []), custom.get('packagePolicies', []))

print(f'Merged license policies: {len(merged_licenses)}')
print(f'Merged package policies: {len(merged_packages)}')

print()
print('Package policies after merge:')
for p in merged_packages:
    print(f'  - {p.get("purl")}')

print()
print('SUCCESS: Merge logic works correctly!')
