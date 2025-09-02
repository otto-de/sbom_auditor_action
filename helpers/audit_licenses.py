#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
Enhanced License Auditing with Intelligent Resolution
Audits SBOM licenses with automatic resolution of unknown/non-standard licenses.
"""

import json
import sys
import argparse
import logging
import re
import fnmatch
import os
from ai_summary import generate_summary
from license_resolver import LicenseResolver

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_json_file(file_path, file_type):
    """Loads a JSON file and returns its content."""
    logging.debug(f"Opening {file_type} file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"{file_type} file not found at {file_path}")
        print(f"Error: {file_type} file not found at {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding {file_type} JSON from {file_path}: {e}")
        print(f"Error decoding {file_type} JSON from {file_path}: {e}")
        sys.exit(1)


def extract_components(sbom_data):
    """Extracts components from SBOM data."""
    components = sbom_data.get('packages', []) or sbom_data.get('components', [])
    logging.debug(f"Found {len(components)} packages/components in SBOM.")
    return components


def get_purl(component):
    """Extracts PURL from a component."""
    if component.get('externalRefs'):
        for ref in component.get('externalRefs'):
            if ref.get('referenceType') == 'purl':
                return ref.get('referenceLocator')
    return "purl-not-found"


def find_package_policy(purl, package_policies):
    """Finds a matching package policy based on PURL and matcher logic."""
    normalized_purl = purl.split('?')[0]

    for policy in package_policies:
        policy_purl = policy.get('purl', '')
        normalized_policy_purl = policy_purl.split('?')[0] if policy_purl else ''

        if normalized_policy_purl:
            if fnmatch.fnmatch(normalized_purl, normalized_policy_purl):
                return policy
    return None


def find_license_policy(license_id, license_policies):
    """Finds the policy for a given license ID."""
    for policy in license_policies:
        if policy.get('id') == license_id:
            return policy.get('usagePolicy')
    return None


def audit_component_with_resolution(component, license_policies, package_policies, 
                                   license_resolver=None, internal_dependency_patterns=None):
    """
    Audits a single component with intelligent license resolution.
    
    Args:
        component: Component to audit
        license_policies: License policies from policy.json
        package_policies: Package-specific policies
        license_resolver: LicenseResolver instance (optional)
        internal_dependency_patterns: Patterns for internal dependencies
        
    Returns:
        List of audit results for the component
    """
    component_name = component.get('name')
    component_version = component.get('versionInfo')
    purl = get_purl(component)
    license_concluded = component.get('licenseConcluded')

    # Check if the component matches any of the internal dependency patterns
    if internal_dependency_patterns:
        for pattern in internal_dependency_patterns:
            if re.match(pattern, purl):
                logging.info(f"  Skipping internal dependency: {purl} (matches pattern: '{pattern}')")
                return [{"package": f"{component_name}@{component_version}", "purl": purl, "policy": "internal"}]
    
    logging.debug(f"Processing component: {component_name}@{component_version} ({purl})")
    logging.debug(f"  License concluded: {license_concluded}")

    # 1. Check for a specific package policy override
    package_policy = find_package_policy(purl, package_policies)
    if package_policy:
        policy = package_policy.get('usagePolicy')
        reason = package_policy.get('reason', 'N/A')
        logging.info(f"  PACKAGE POLICY OVERRIDE: {purl} -> {policy} (reason: {reason})")
        return [{
            "package": f"{component_name}@{component_version}",
            "purl": purl,
            "license": license_concluded or "N/A",
            "policy": f"{policy} (package policy)"
        }]

    # 2. Handle cases with no license
    if not license_concluded or license_concluded in ['NOASSERTION', 'NONE']:
        policy = "needs-review"
        if purl.startswith('pkg:githubactions/'):
            logging.info(f"  GitHub Action {component_name}@{component_version} has no license, but is allowed.")
            policy = "allow"
        else:
            logging.warning(f"  No license found for {component_name}@{component_version}. Marking for review.")
        
        return [{
            "package": f"{component_name}@{component_version}",
            "purl": purl,
            "license": "NO-LICENSE-FOUND",
            "policy": policy
        }]

    # 3. Try intelligent license resolution for unknown/problematic licenses
    original_license = license_concluded
    resolved_license = license_concluded
    resolution_info = None
    
    # Check if license needs resolution
    needs_resolution = (
        license_concluded in ['non-standard', 'Weird unknown license'] or
        find_license_policy(license_concluded, license_policies) is None
    )
    
    if needs_resolution and license_resolver:
        logging.info(f"🔍 Attempting to resolve unknown license: '{license_concluded}'")
        
        # Try to get the original license name from enrichment metadata
        original_license_name = license_concluded
        if 'enrichment' in component and 'licenseResolutions' in component['enrichment']:
            # This license might have been resolved during enrichment
            for res in component['enrichment']['licenseResolutions']:
                if res.get('resolved') == license_concluded:
                    original_license_name = res.get('original', license_concluded)
                    break
        
        resolution_result = license_resolver.resolve_license(original_license_name)
        
        if resolution_result['resolved']:
            resolved_license = resolution_result['resolved']
            resolution_info = {
                'original': original_license_name,
                'resolved': resolved_license,
                'method': resolution_result['method'],
                'confidence': resolution_result['confidence']
            }
            
            logging.info(f"✅ Resolved '{original_license_name}' → '{resolved_license}' "
                        f"({resolution_result['method']})")
            
            # Update component with resolution info
            if 'enrichment' not in component:
                component['enrichment'] = {}
            if 'auditResolution' not in component['enrichment']:
                component['enrichment']['auditResolution'] = resolution_info
        else:
            logging.warning(f"⚠️ Could not resolve license: '{original_license_name}'")

    # 4. Check policy for the (potentially resolved) license
    final_license = resolved_license
    license_policy = find_license_policy(final_license, license_policies)
    
    if license_policy:
        policy = license_policy
        logging.debug(f"  Found policy for {final_license}: {policy}")
    else:
        policy = "needs-review"
        logging.warning(f"  No policy found for license '{final_license}'. Marking for review.")

    # 5. Build audit result
    result = {
        "package": f"{component_name}@{component_version}",
        "purl": purl,
        "license": final_license,
        "policy": policy
    }
    
    # Add resolution info if license was resolved
    if resolution_info:
        result['resolution'] = resolution_info
        result['license_original'] = original_license
    
    return [result]


def audit_licenses_with_resolution(sbom_path, policy_path, package_policy_path=None, 
                                  internal_dependencies_file=None, resolve_licenses=True, 
                                  generate_ai_summary_flag=False):
    """
    Main function to audit licenses with intelligent resolution.
    
    Args:
        sbom_path: Path to SBOM file
        policy_path: Path to policy.json
        package_policy_path: Path to package policies (optional)
        internal_dependencies_file: Path to internal dependencies file (optional)
        resolve_licenses: Whether to use intelligent license resolution
        generate_ai_summary_flag: Whether to generate AI summary
        
    Returns:
        Dictionary with audit results
    """
    
    # Load data files
    sbom_data = load_json_file(sbom_path, "SBOM")
    policy_data = load_json_file(policy_path, "Policy")
    
    license_policies = policy_data.get('licenses', [])
    
    package_policies = []
    if package_policy_path:
        package_policy_data = load_json_file(package_policy_path, "Package Policy")
        package_policies = package_policy_data.get('packages', [])
    
    internal_dependency_patterns = []
    if internal_dependencies_file:
        internal_deps_data = load_json_file(internal_dependencies_file, "Internal Dependencies")
        internal_dependency_patterns = internal_deps_data.get('patterns', [])

    # Initialize license resolver if enabled
    license_resolver = None
    if resolve_licenses:
        ai_api_key = os.getenv('GITHUB_TOKEN')  # Use GitHub token for GitHub Models
        license_resolver = LicenseResolver(api_key=ai_api_key, ai_provider='github')
        logging.info("✨ Intelligent license resolution enabled")
    
    # Handle nested SBOM structure
    sbom_content = sbom_data.get("sbom", sbom_data)
    components = extract_components(sbom_content)
    
    logging.info(f"Starting audit of {len(components)} components...")
    
    # Audit components
    all_audit_results = []
    resolution_stats = {}
    
    for component in components:
        audit_results = audit_component_with_resolution(
            component, license_policies, package_policies, 
            license_resolver, internal_dependency_patterns
        )
        all_audit_results.extend(audit_results)
        
        # Track resolution statistics
        for result in audit_results:
            if 'resolution' in result:
                method = result['resolution']['method']
                resolution_stats[method] = resolution_stats.get(method, 0) + 1

    # Print resolution statistics
    if resolution_stats:
        logging.info("📊 License resolution statistics:")
        for method, count in sorted(resolution_stats.items()):
            logging.info(f"   {method}: {count}")

    # Generate compliance report
    policy_counts = {}
    for result in all_audit_results:
        policy = result.get('policy', 'unknown')
        # Clean up policy strings for counting
        clean_policy = policy.split(' (')[0]  # Remove " (package policy)" suffix
        policy_counts[clean_policy] = policy_counts.get(clean_policy, 0) + 1

    # Print summary
    print(f"✅ Audit completed. {len(all_audit_results)} components processed.")
    if resolution_stats:
        total_resolved = sum(resolution_stats.values())
        print(f"🎯 Licenses resolved: {total_resolved}")
    
    print("\n📊 License Policy Summary:")
    for policy, count in sorted(policy_counts.items()):
        print(f"  {policy}: {count}")

    # Prepare output
    output = {
        "audit_results": all_audit_results,
        "policy_summary": policy_counts,
        "total_components": len(all_audit_results),
        "resolution_stats": resolution_stats if resolution_stats else {}
    }
    
    # Generate AI summary if requested
    if generate_ai_summary_flag:
        logging.info("🤖 Generating AI compliance summary...")
        try:
            summary = generate_summary(output)
            output["ai_summary"] = summary
            print(f"\n🤖 AI Summary:\n{summary}")
        except Exception as e:
            logging.error(f"Failed to generate AI summary: {e}")
            output["ai_summary"] = f"Error generating summary: {str(e)}"
    
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit SBOM licenses with intelligent resolution")
    parser.add_argument("sbom", help="Input SPDX SBOM JSON file")
    parser.add_argument("policy", help="License policy JSON file")
    parser.add_argument("--package-policy", help="Package-specific policy JSON file (optional)")
    parser.add_argument("--internal-dependencies", help="Internal dependencies JSON file (optional)")
    parser.add_argument("--resolve-licenses", action="store_true", default=True,
                        help="Enable intelligent license resolution (default: enabled)")
    parser.add_argument("--no-resolve-licenses", dest="resolve_licenses", action="store_false",
                        help="Disable intelligent license resolution")
    parser.add_argument("--generate-summary", action="store_true", 
                        help="Generate AI-powered compliance summary")
    parser.add_argument("--output", help="Output JSON file (optional)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s', force=True)

    # Run audit
    results = audit_licenses_with_resolution(
        args.sbom, args.policy, args.package_policy, 
        args.internal_dependencies, args.resolve_licenses,
        args.generate_summary
    )

    # Save output if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Results saved to {args.output}")
    else:
        # Print detailed results to stdout
        print(f"\n📋 Detailed Results:")
        print(json.dumps(results, indent=2))
