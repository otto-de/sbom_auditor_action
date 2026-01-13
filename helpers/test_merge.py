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
print('=== PURL Matching Tests ===')
from audit_licenses import find_package_policy

test_cases = [
    ("pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@3.1.0?type=jar", 
     "pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api", True),
    ("pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@3.1.0", 
     "pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api", True),
    ("pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@2.0.0", 
     "pkg:maven/jakarta.ws.rs/jakarta.ws.rs-api@3.1.0", False),  # Different version
    ("pkg:maven/org.jboss/jboss-transaction-spi@1.0.0", 
     "pkg:maven/org.jboss/*", True),  # Wildcard
]

all_passed = True
for sbom_purl, policy_purl, expected in test_cases:
    policies = [{"purl": policy_purl, "usagePolicy": "allow"}]
    result = find_package_policy(sbom_purl, policies)
    matched = result is not None
    passed = matched == expected
    all_passed = all_passed and passed
    status = '✅' if passed else '❌'
    print(f'{status} SBOM: {sbom_purl}')
    print(f'   Policy: {policy_purl}')
    print(f'   Expected: {expected}, Got: {matched}')

print()
if all_passed:
    print('SUCCESS: All tests passed!')
else:
    print('FAILURE: Some tests failed!')
    exit(1)
