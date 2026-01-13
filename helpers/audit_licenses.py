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
from spdx_expression_parser import SPDXExpressionParser

# Logging will be configured in main() based on debug flag


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


def merge_license_policies(base_policies, override_policies):
    """
    Merges two lists of license policies. Override policies take precedence
    over base policies when they have the same 'id'.
    
    Args:
        base_policies: List of base policy dictionaries (e.g., from default policy.json)
        override_policies: List of override policy dictionaries (e.g., from custom policy)
        
    Returns:
        List of merged policies where override entries replace base entries with same id
    """
    if not override_policies:
        return base_policies
    
    if not base_policies:
        return override_policies
    
    # Create a dict from base policies indexed by id
    merged = {policy.get('id'): policy for policy in base_policies if policy.get('id')}
    
    # Override/add with custom policies
    override_count = 0
    new_count = 0
    for policy in override_policies:
        policy_id = policy.get('id')
        if policy_id:
            if policy_id in merged:
                override_count += 1
                logging.debug(f"🔄 Overriding policy for '{policy_id}': {merged[policy_id].get('usagePolicy')} → {policy.get('usagePolicy')}")
            else:
                new_count += 1
                logging.debug(f"➕ Adding new policy for '{policy_id}': {policy.get('usagePolicy')}")
            merged[policy_id] = policy
    
    if override_count > 0 or new_count > 0:
        logging.info(f"📋 Policy merge: {override_count} overridden, {new_count} new policies added")
    
    return list(merged.values())


def merge_aliases(base_aliases, override_aliases):
    """
    Merges two dictionaries of aliases. Override aliases take precedence.
    
    Args:
        base_aliases: Base alias dictionary (e.g., from default policy.json)
        override_aliases: Override alias dictionary (e.g., from custom policy)
        
    Returns:
        Merged alias dictionary
    """
    if not override_aliases:
        return base_aliases or {}
    
    if not base_aliases:
        return override_aliases or {}
    
    merged = base_aliases.copy()
    merged.update(override_aliases)
    return merged


def merge_package_policies(base_policies, override_policies):
    """
    Merges two lists of package policies. Override policies take precedence
    over base policies when they have the same 'purl'.
    
    Args:
        base_policies: List of base package policy dictionaries
        override_policies: List of override package policy dictionaries
        
    Returns:
        List of merged package policies where override entries replace base entries with same purl
    """
    if not override_policies:
        return base_policies or []
    
    if not base_policies:
        return override_policies or []
    
    # Create a dict from base policies indexed by purl (normalized without query params)
    merged = {}
    for policy in base_policies:
        purl = policy.get('purl', '')
        if purl:
            normalized_purl = purl.split('?')[0]
            merged[normalized_purl] = policy
    
    # Override/add with custom policies
    override_count = 0
    new_count = 0
    for policy in override_policies:
        purl = policy.get('purl', '')
        if purl:
            normalized_purl = purl.split('?')[0]
            if normalized_purl in merged:
                override_count += 1
                logging.debug(f"🔄 Overriding package policy for '{purl}'")
            else:
                new_count += 1
                logging.debug(f"➕ Adding new package policy for '{purl}'")
            merged[normalized_purl] = policy
    
    if override_count > 0 or new_count > 0:
        logging.info(f"📦 Package policy merge: {override_count} overridden, {new_count} new policies added")
    
    return list(merged.values())


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


def find_license_policy(license_id, license_policies, license_aliases=None, combined_aliases=None):
    """Finds the policy for a given license ID with SPDX expression support."""
    # Initialize SPDX parser with aliases from policy
    parser = SPDXExpressionParser(license_aliases=license_aliases, combined_aliases=combined_aliases)
    
    # Parse and evaluate SPDX expression
    policy, explanation = parser.parse_and_evaluate(license_id, license_policies)
    
    logging.debug(f"License policy evaluation: '{license_id}' → {policy} ({explanation})")
    return policy


def generate_summary_table(total_packages, internal_packages, gh_actions_count, denied_count, needs_review_count, resolved_count=0, resolution_stats=None):
    """Generates a summary table and appends it to the GITHUB_STEP_SUMMARY file."""
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY')
    if not summary_file:
        logging.debug("GITHUB_STEP_SUMMARY environment variable not set. Skipping summary table generation.")
        return

    summary_content = f"""
### 📊 License Audit Summary

| Category | Count |
| :--- | :---: |
| Total Packages in SBOM | {total_packages} |
| Denied Packages | {denied_count} |
| Packages Needing Review | {needs_review_count} |
| Internal Packages Skipped | {internal_packages} |
| GitHub Actions | {gh_actions_count} |"""

    if resolved_count > 0:
        summary_content += f"""
| Licenses Resolved | {resolved_count} |"""

    summary_content += "\n\n"

    # Add License Resolution Statistics if available
    if resolution_stats and any(count > 0 for count in resolution_stats.values()):
        summary_content += """
### 🔧 License Resolution Statistics

| Resolution Method | Count | Description |
| :--- | :---: | :--- |"""

        # Resolution method descriptions
        method_descriptions = {
            'deps.dev': '🌐 Google deps.dev API',
            'spdx_fuzzy': '🎯 SPDX Fuzzy Matching', 
            'ai_assisted': '🤖 AI-Powered Resolution',
            'pom_fallback': '📄 Maven POM Analysis',
            'cache_hit': '💾 Cached Resolution',
            'expression_parser': '🧠 SPDX Expression Parser'
        }
        
        for method, count in sorted(resolution_stats.items()):
            if count > 0:
                description = method_descriptions.get(method, f'📋 {method.replace("_", " ").title()}')
                summary_content += f"""
| {description} | {count} | Advanced license resolution |"""
        
        summary_content += "\n\n"

    try:
        with open(summary_file, 'a', encoding='utf-8') as f:
            f.write(summary_content)
        logging.info(f"Successfully wrote audit summary to {summary_file}")
    except Exception as e:
        logging.error(f"Failed to write to GITHUB_STEP_SUMMARY file: {e}")


def audit_component_with_resolution(component, license_policies, package_policies, 
                                   license_resolver=None, internal_dependency_patterns=None,
                                   license_aliases=None, combined_aliases=None):
    """
    Audits a single component with intelligent license resolution.
    
    Args:
        component: Component to audit
        license_policies: License policies from policy.json
        package_policies: Package-specific policies
        license_resolver: LicenseResolver instance (optional)
        internal_dependency_patterns: Patterns for internal dependencies
        license_aliases: Mapping of non-standard license names to SPDX IDs
        combined_aliases: Mapping of combined license expressions to single license
        
    Returns:
        List of audit results for the component
    """
    component_name = component.get('name')
    component_version = component.get('versionInfo')
    purl = get_purl(component)
    license_concluded = component.get('licenseConcluded')

    # Check if the component matches any of the internal dependency patterns
    # No default internal patterns - must be explicitly configured
    if not internal_dependency_patterns:
        # No internal patterns configured - all packages will be audited
        pass
    
    if internal_dependency_patterns:
        for pattern in internal_dependency_patterns:
            # Check both PURL and component name
            if (purl and re.match(pattern, purl)) or (component_name and re.match(pattern, component_name)):
                logging.debug(f"  Skipping internal dependency: {purl or component_name} (matches pattern: '{pattern}')")
                return [{"package": f"{component_name}@{component_version}", "purl": purl, "policy": "internal"}]
    
    logging.debug(f"Processing component: {component_name}@{component_version} ({purl})")
    logging.debug(f"  License concluded: {license_concluded}")

    # 1. Check for a specific package policy override
    package_policy = find_package_policy(purl, package_policies)
    if package_policy:
        policy = package_policy.get('usagePolicy')
        reason = package_policy.get('reason', 'N/A')
        logging.debug(f"  PACKAGE POLICY OVERRIDE: {purl} -> {policy} (reason: {reason})")
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
            logging.debug(f"  GitHub Action {component_name}@{component_version} has no license, but is allowed.")
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
        find_license_policy(license_concluded, license_policies, license_aliases, combined_aliases) is None
    )
    
    if needs_resolution and license_resolver:
        logging.debug(f"🔍 Attempting to resolve unknown license: '{license_concluded}'")
        
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
            
            logging.debug(f"✅ Resolved '{original_license_name}' → '{resolved_license}' "
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
    license_policy = find_license_policy(final_license, license_policies, license_aliases, combined_aliases)
    
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
                                  generate_ai_summary_flag=False, openai_api_key=None, 
                                  ai_provider="openai", azure_endpoint=None, 
                                  azure_deployment=None, aws_region=None, 
                                  ai_model_name=None, internal_dependency_patterns=None,
                                  base_policy_path=None):
    """
    Main function to audit licenses with intelligent resolution.
    
    Args:
        sbom_path: Path to SBOM file
        policy_path: Path to policy.json (or custom override policy)
        package_policy_path: Path to package policies (optional)
        internal_dependencies_file: Path to internal dependencies file (optional)
        resolve_licenses: Whether to use intelligent license resolution
        generate_ai_summary_flag: Whether to generate AI summary
        base_policy_path: Path to base/default policy.json (optional, for merging)
        
    Returns:
        Dictionary with audit results
    """
    
    # Load data files
    sbom_data = load_json_file(sbom_path, "SBOM")
    policy_data = load_json_file(policy_path, "Policy")
    
    # Validate policy structure - info message for packagePolicies-only files
    if 'packagePolicies' in policy_data and 'policies' not in policy_data:
        logging.info(f"📦 Policy file '{policy_path}' contains package exceptions (packagePolicies). "
                    f"These will be merged with the default license policies.")
    
    if 'policies' not in policy_data and 'packagePolicies' not in policy_data:
        logging.warning(f"⚠️ Policy file '{policy_path}' contains neither 'policies' nor 'packagePolicies'. "
                       f"Expected structure: {{\"policies\": [...]}} and/or {{\"packagePolicies\": [...]}}")
    
    # Handle policy merging: if base_policy_path is provided, merge with custom policy
    # Merges both 'policies' (license-based) and 'packagePolicies' (PURL-based) from both files
    if base_policy_path and base_policy_path != policy_path:
        base_policy_data = load_json_file(base_policy_path, "Base Policy")
        
        # Merge license policies
        base_policies = base_policy_data.get('policies', [])
        override_policies = policy_data.get('policies', [])
        license_policies = merge_license_policies(base_policies, override_policies)
        
        # Merge package policies (PURL-based exceptions) from BOTH policy files
        base_package_policies = base_policy_data.get('packagePolicies', [])
        override_package_policies = policy_data.get('packagePolicies', [])
        package_policies = merge_package_policies(base_package_policies, override_package_policies)
        
        # Merge license aliases (custom aliases override base aliases)
        license_aliases = merge_aliases(
            base_policy_data.get('licenseAliases', {}),
            policy_data.get('licenseAliases', {})
        )
        combined_aliases = merge_aliases(
            base_policy_data.get('combinedLicenseAliases', {}),
            policy_data.get('combinedLicenseAliases', {})
        )
        
        logging.info(f"✅ Merged {len(base_policies)} base license policies with {len(override_policies)} custom → {len(license_policies)} total")
        if base_package_policies or override_package_policies:
            logging.info(f"✅ Merged {len(base_package_policies)} base package policies with {len(override_package_policies)} custom → {len(package_policies)} total")
        logging.debug(f"📋 Loaded {len(license_aliases)} license aliases and {len(combined_aliases)} combined aliases")
    else:
        license_policies = policy_data.get('policies', [])
        package_policies = policy_data.get('packagePolicies', [])
        license_aliases = policy_data.get('licenseAliases', {})
        combined_aliases = policy_data.get('combinedLicenseAliases', {})
        if license_aliases or combined_aliases:
            logging.debug(f"📋 Loaded {len(license_aliases)} license aliases and {len(combined_aliases)} combined aliases from policy")
    
    # Also load from separate package_policy_path if provided (backwards compatibility)
    if package_policy_path:
        package_policy_data = load_json_file(package_policy_path, "Package Policy")
        additional_package_policies = package_policy_data.get('packagePolicies', []) or package_policy_data.get('packages', [])
        if additional_package_policies:
            package_policies = merge_package_policies(package_policies, additional_package_policies)
            logging.info(f"📦 Added {len(additional_package_policies)} package policies from separate file")
    
    # Handle internal dependency patterns
    internal_dependency_patterns_list = []
    if internal_dependencies_file:
        internal_deps_data = load_json_file(internal_dependencies_file, "Internal Dependencies")
        internal_dependency_patterns_list = internal_deps_data.get('patterns', [])
    elif internal_dependency_patterns:
        # Parse newline-separated patterns from string
        internal_dependency_patterns_list = [p.strip() for p in internal_dependency_patterns.split('\n') if p.strip()]

    # Initialize license resolver if enabled
    license_resolver = None
    if resolve_licenses:
        # Use the provided API key or fallback to environment
        api_key = openai_api_key or os.getenv('GITHUB_TOKEN') if ai_provider == 'github' else openai_api_key
        license_resolver = LicenseResolver(api_key=api_key, ai_provider=ai_provider)
        logging.debug("✨ Intelligent license resolution enabled")
    
    # Handle nested SBOM structure
    sbom_content = sbom_data.get("sbom", sbom_data)
    components = extract_components(sbom_content)
    
    logging.info(f"Starting audit of {len(components)} components...")
    
    # Add summary info for non-debug mode
    if not logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.info("🔍 License resolution enabled - processing packages...")
    
    # Audit components
    all_audit_results = []
    resolution_stats = {}
    enrichment_stats = {}
    
    # First, collect enrichment statistics from SBOM
    for component in components:
        if 'enrichment' in component and 'licenseResolutions' in component['enrichment']:
            for resolution in component['enrichment']['licenseResolutions']:
                method = resolution.get('method', 'unknown')
                enrichment_stats[method] = enrichment_stats.get(method, 0) + 1
    
    for component in components:
        audit_results = audit_component_with_resolution(
            component, license_policies, package_policies, 
            license_resolver, internal_dependency_patterns_list,
            license_aliases, combined_aliases
        )
        all_audit_results.extend(audit_results)
        
        # Track resolution statistics from audit phase
        for result in audit_results:
            if 'resolution' in result:
                method = result['resolution']['method']
                resolution_stats[method] = resolution_stats.get(method, 0) + 1
    
    # Combine enrichment and audit resolution statistics
    combined_stats = enrichment_stats.copy()
    for method, count in resolution_stats.items():
        combined_stats[method] = combined_stats.get(method, 0) + count

    # Print resolution statistics
    if combined_stats:
        logging.debug("📊 Combined license resolution statistics:")
        for method, count in sorted(combined_stats.items()):
            logging.debug(f"   {method}: {count}")
            logging.debug(f"   {method}: {count}")

    # Generate compliance report
    policy_counts = {}
    denied = []
    needs_review = []
    allowed = []
    internal = []
    gh_actions_count = 0
    
    for result in all_audit_results:
        policy = result.get('policy', 'unknown')
        # Clean up policy strings for counting
        clean_policy = policy.split(' (')[0]  # Remove " (package policy)" suffix
        policy_counts[clean_policy] = policy_counts.get(clean_policy, 0) + 1
        
        # Categorize results for summary and reporting
        if clean_policy == 'deny':
            denied.append(result)
        elif clean_policy == 'needs-review':
            needs_review.append(result)
        elif clean_policy == 'internal':
            internal.append(result)
        elif clean_policy == 'allow':
            allowed.append(result)
            # Count GitHub Actions
            if result.get('purl', '').startswith('pkg:githubactions/'):
                gh_actions_count += 1

    # Generate GitHub Step Summary
    total_resolved = sum(combined_stats.values()) if combined_stats else 0
    generate_summary_table(
        len(all_audit_results), 
        len(internal), 
        gh_actions_count, 
        len(denied), 
        len(needs_review),
        total_resolved,
        combined_stats
    )

    # Print summary
    print(f"✅ Audit completed. {len(all_audit_results)} components processed.")
    if resolution_stats:
        total_resolved = sum(resolution_stats.values())
        print(f"🎯 Licenses resolved: {total_resolved}")
    
    print("\n📊 License Policy Summary:")
    for policy, count in sorted(policy_counts.items()):
        print(f"  {policy}: {count}")

    # Generate AI summary if requested
    ai_summary = None
    if generate_ai_summary_flag:
        logging.info("🤖 Generating AI compliance summary...")
        try:
            # Create summary data in the expected format
            summary_data = {
                "audit_results": all_audit_results,
                "policy_summary": policy_counts,
                "total_components": len(all_audit_results),
                "resolution_stats": resolution_stats if resolution_stats else {},
                "denied": denied,
                "needs_review": needs_review,
                "allowed": allowed,
                "internal": internal
            }
            
            # Use provided API key or fallback
            api_key = openai_api_key or os.getenv('GITHUB_TOKEN') if ai_provider == 'github' else openai_api_key
            
            ai_summary = generate_summary(
                api_key, 
                denied, 
                needs_review, 
                ai_provider, 
                azure_endpoint, 
                azure_deployment, 
                aws_region, 
                ai_model_name
            )
            logging.info(f"✅ AI summary generated successfully")
        except Exception as e:
            logging.error(f"Failed to generate AI summary: {e}")
            ai_summary = f"Error generating summary: {str(e)}"

    # Prepare output
    output = {
        "audit_results": all_audit_results,
        "policy_summary": policy_counts,
        "total_components": len(all_audit_results),
        "resolution_stats": resolution_stats if resolution_stats else {},
        "denied": denied,
        "needs_review": needs_review,
        "allowed": allowed,
        "internal": internal
    }
    
    if ai_summary:
        output["ai_summary"] = ai_summary
    
    return output


def generate_markdown_report(denied, needs_review, internal, allowed, ai_summary=None, resolution_stats=None):
    """Generates a markdown report for the audit results."""
    report = ""
    
    if ai_summary:
        report += f"{ai_summary}\n\n"
    
    if resolution_stats:
        report += "### 🎯 License Resolution Statistics\n\n"
        report += "| Resolution Method | Count |\n"
        report += "| :--- | :---: |\n"
        for method, count in sorted(resolution_stats.items()):
            report += f"| {method} | {count} |\n"
        report += "\n"
    
    report += "## License Audit Report\n\n"
    
    if denied:
        report += "### ❌ DENIED PACKAGES\n\n"
        report += "| Package | License | Policy | PURL |\n"
        report += "| :--- | :--- | :--- | :--- |\n"
        for item in denied:
            license_display = item.get('license_original', item.get('license', 'N/A'))
            if 'resolution' in item:
                license_display += f" → **{item['license']}**"
            report += f"| `{item['package']}` | `{license_display}` | **{item['policy']}** | `{item['purl']}` |\n"
        report += "\n"
    
    if needs_review:
        report += "### ⚠️ PACKAGES NEEDING REVIEW\n\n"
        report += "| Package | License | Policy | PURL |\n"
        report += "| :--- | :--- | :--- | :--- |\n"
        for item in needs_review:
            license_display = item.get('license_original', item.get('license', 'N/A'))
            if 'resolution' in item:
                license_display += f" → **{item['license']}**"
            report += f"| `{item['package']}` | `{license_display}` | {item['policy']} | `{item['purl']}` |\n"
        report += "\n"

    if internal:
        report += "### 🏠 SKIPPED INTERNAL PACKAGES\n\n"
        report += "| Package | PURL |\n"
        report += "| :--- | :--- |\n"
        for item in internal:
            report += f"| `{item['package']}` | `{item['purl']}` |\n"
        report += "\n"

    if not denied and not needs_review:
        report += "✅ **All packages conform to the license policy.**\n\n"
    
    print(report)


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
    parser.add_argument("--markdown", action="store_true", 
                        help="Output the report as a Markdown table")
    parser.add_argument("--openai-api-key", 
                        help="OpenAI API key for AI-powered summary generation")
    parser.add_argument("--ai-provider", default="openai",
                        help="AI provider (openai, azure, bedrock, github)")
    parser.add_argument("--azure-endpoint",
                        help="Azure OpenAI endpoint URL")
    parser.add_argument("--azure-deployment", 
                        help="Azure OpenAI deployment name")
    parser.add_argument("--aws-region",
                        help="AWS region for Bedrock")
    parser.add_argument("--ai-model-name",
                        help="Specific AI model name to use")
    parser.add_argument("--internal-dependency-pattern",
                        help="Regex patterns for internal dependencies (newline-separated)")
    parser.add_argument("--base-policy",
                        help="Base/default policy file to merge with. Custom policy overrides base policy entries with same id.")
    parser.add_argument("--output", help="Output JSON file (optional)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    
    # Check for internal patterns from environment variable if not provided as argument
    if not args.internal_dependency_pattern:
        args.internal_dependency_pattern = os.environ.get('INTERNAL_PATTERNS')

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s', force=True)

    # Run audit
    results = audit_licenses_with_resolution(
        args.sbom, args.policy, args.package_policy, 
        args.internal_dependencies, args.resolve_licenses,
        args.generate_summary, args.openai_api_key,
        args.ai_provider, args.azure_endpoint, 
        args.azure_deployment, args.aws_region, 
        args.ai_model_name, args.internal_dependency_pattern,
        args.base_policy
    )

    # Determine if we need to force markdown output
    force_markdown = args.markdown or hasattr(sys.stdout, 'isatty') and not sys.stdout.isatty()
    
    if force_markdown and not (args.output and not args.markdown):
        # Generate markdown report
        generate_markdown_report(
            results.get('denied', []),
            results.get('needs_review', []), 
            results.get('internal', []),
            results.get('allowed', []),
            results.get('ai_summary'),
            results.get('resolution_stats', {})
        )

    # Save output if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"💾 Results saved to {args.output}")
    elif not force_markdown:
        # Print detailed results to stdout only if not in markdown mode
        print(f"\n📋 Detailed Results:")
        print(json.dumps(results, indent=2))

    # Exit with appropriate status code based on audit results
    denied = results.get('denied', [])
    needs_review = results.get('needs_review', [])
    
    if denied or needs_review:
        logging.info("Found packages that are denied or need review. Exiting with status 1.")
        sys.exit(1)
    else:
        logging.info("All packages conform to the license policy.")
        sys.exit(0)
