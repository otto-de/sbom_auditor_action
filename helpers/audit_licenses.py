import json
import sys
import argparse
import logging
import re
import fnmatch

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
        matcher = policy.get('matcher', 'exact')
        normalized_policy_purl = policy_purl.split('?')[0]

        if matcher == 'exact':
            if normalized_purl == normalized_policy_purl:
                return policy
        elif matcher == 'all-versions':
            purl_without_version = normalized_purl.split('@')[0]
            policy_purl_without_version = normalized_policy_purl.split('@')[0]
            if purl_without_version == policy_purl_without_version:
                return policy
        elif matcher == 'wildcard':
            if fnmatch.fnmatch(normalized_purl, normalized_policy_purl):
                return policy
    return None

def audit_component(component, license_policies, package_policies):
    """Audits a single component and returns its single, most restrictive audit status."""
    component_name = component.get('name')
    component_version = component.get('versionInfo')
    purl = get_purl(component)
    license_concluded = component.get('licenseConcluded')
    
    logging.debug(f"Processing component: {component_name}@{component_version} ({purl})")

    # 1. Check for a specific package policy override
    package_policy = find_package_policy(purl, package_policies)
    if package_policy:
        policy = package_policy.get('usagePolicy')
        reason = package_policy.get('reason', 'N/A')
        logging.info(f"  Found package-specific policy for {purl} using '{package_policy.get('matcher', 'exact')}' matcher on '{package_policy.get('purl')}': '{policy}'. Reason: {reason}")
        return [{
            "package": f"{component_name}@{component_version}",
            "purl": purl,
            "license": license_concluded or "N/A",
            "policy": f"{policy} (package policy)"
        }]

    # 2. Continue with license-based audit if no package policy is found
    logging.debug(f"  License concluded: {license_concluded}")

    # Handle cases with no license
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

    # Corrected regex to split license expressions
    license_ids = re.split(r'\b(AND|OR|WITH)\b|\(|\)|,', license_concluded, flags=re.IGNORECASE)
    
    # Determine the most restrictive policy from all parts of the license expression
    most_restrictive_policy = "allow"
    final_license_id = license_concluded # Default to the full expression
    
    found_licenses = []

    for license_id in license_ids:
        license_id = license_id.strip()
        if not license_id:
            continue
        
        found_licenses.append(license_id)
        logging.debug(f"  Checking license: {license_id}")
        policy = license_policies.get(license_id)
        
        current_policy = "needs-review (not in policy)"
        if policy:
            current_policy = policy.get('usagePolicy')
            logging.debug(f"    Found policy for {license_id}: {current_policy}")
        else:
            logging.warning(f"    No policy found for license '{license_id}' for package {component_name}@{component_version}. Marking for review.")

        # Update most restrictive policy: deny > needs-review > allow
        if current_policy == 'deny':
            most_restrictive_policy = 'deny'
            final_license_id = license_id # This is the one causing denial
        elif 'needs-review' in str(current_policy) and most_restrictive_policy != 'deny':
            most_restrictive_policy = current_policy
            final_license_id = license_id # This one needs review
    
    # If after checking all licenses, none were found, it's an issue.
    if not found_licenses:
         logging.warning(f"    Could not parse any license from '{license_concluded}' for package {component_name}@{component_version}. Marking for review.")
         return [{
            "package": f"{component_name}@{component_version}",
            "purl": purl,
            "license": license_concluded,
            "policy": "needs-review (unparsable)"
        }]

    # If the overall policy is 'allow', we display the original full license string.
    # Otherwise, we display the specific license that caused the more restrictive policy.
    if most_restrictive_policy == 'allow':
        final_license_id = license_concluded

    result = {
        "package": f"{component_name}@{component_version}",
        "purl": purl,
        "license": final_license_id,
        "policy": most_restrictive_policy
    }
    
    return [result]

def generate_report(denied, needs_review, allowed, debug, markdown):
    """Generates and prints the license audit report."""
    if markdown:
        report = "## License Audit Report\n\n"
        if denied:
            report += "### DENIED PACKAGES\n\n"
            report += "| Package | License | Policy | PURL |\n"
            report += "| :--- | :--- | :--- | :--- |\n"
            for item in denied:
                report += f"| `{item['package']}` | `{item['license']}` | **{item['policy']}** | `{item['purl']}` |\n"
            report += "\n"
        
        if needs_review:
            report += "### PACKAGES NEEDING REVIEW\n\n"
            report += "| Package | License | Policy | PURL |\n"
            report += "| :--- | :--- | :--- | :--- |\n"
            for item in needs_review:
                report += f"| `{item['package']}` | `{item['license']}` | {item['policy']} | `{item['purl']}` |\n"
            report += "\n"

        if debug and allowed:
            report += "### ALLOWED PACKAGES (DEBUG)\n\n"
            report += "| Package | License | Policy | PURL |\n"
            report += "| :--- | :--- | :--- | :--- |\n"
            for item in allowed:
                report += f"| `{item['package']}` | `{item['license']}` | {item['policy']} | `{item['purl']}` |\n"
            report += "\n"

        if not denied and not needs_review:
            report += "\nAll packages conform to the license policy.\n"
        
        print(report)
    else:
        print("--- License Audit Report ---")
        
        if denied:
            print("\n--- DENIED PACKAGES ---")
            for item in denied:
                print(f"Package: {item['package']}\n  License: {item['license']}\n  Policy: {item['policy']}\n  PURL: {item['purl']}")

        if needs_review:
            print("\n--- PACKAGES NEEDING REVIEW ---")
            for item in needs_review:
                print(f"Package: {item['package']}\n  License: {item['license']}\n  Policy: {item['policy']}\n  PURL: {item['purl']}")

        if debug and allowed:
            print("\n--- ALLOWED PACKAGES (DEBUG) ---")
            for item in allowed:
                print(f"Package: {item['package']}\n  License: {item['license']}\n  Policy: {item['policy']}\n  PURL: {item['purl']}")

        if not denied and not needs_review:
            print("\nAll packages conform to the license policy.")

        print("\n--- End of Report ---")

def audit_licenses(sbom_path, policy_path, package_policy_path=None, debug=False, markdown=False):
    """
    Audits licenses in an SBOM file against a policy file.
    """
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.debug(f"Starting license audit with sbom: {sbom_path}, policy: {policy_path}")

    sbom_data = load_json_file(sbom_path, "SBOM")
    policy_data = load_json_file(policy_path, "Policy")
    license_policies = {policy['id']: policy for policy in policy_data['policies']}
    logging.debug(f"Loaded {len(license_policies)} license policies.")

    package_policies = []
    if package_policy_path:
        try:
            package_policy_data = load_json_file(package_policy_path, "Package Policy")
            package_policies = package_policy_data.get('packagePolicies', [])
            logging.debug(f"Loaded {len(package_policies)} package-specific policies.")
        except SystemExit:
            # A SystemExit is raised by load_json_file if the file is not found.
            # We can ignore this for the optional package policy file.
            logging.warning(f"Package policy file not found at {package_policy_path}, continuing without it.")
            pass

    needs_review = []
    denied = []
    allowed = []

    # Correctly access the nested SBOM data
    if 'sbom' in sbom_data:
        sbom_data = sbom_data['sbom']

    components = extract_components(sbom_data)
    for component in components:
        results = audit_component(component, license_policies, package_policies)
        for result in results:
            policy_str = result['policy'].lower()
            if 'needs-review' in policy_str or 'not in policy' in policy_str:
                needs_review.append(result)
            elif 'deny' in policy_str:
                denied.append(result)
            elif 'allow' in policy_str:
                allowed.append(result)

    logging.debug("Finished processing all components.")
    logging.debug(f"Denied: {len(denied)}, Needs Review: {len(needs_review)}, Allowed: {len(allowed)}")

    generate_report(denied, needs_review, allowed, debug, markdown)

    if denied or needs_review:
        logging.info("Found packages that are denied or need review. Exiting with status 1.")
        sys.exit(1)
    else:
        logging.info("All packages conform to the license policy.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Audits licenses in an SBOM file against a policy file.')
    parser.add_argument('sbom_path', help='Path to the enriched SBOM JSON file.')
    parser.add_argument('policy_path', help='Path to the policy JSON file.')
    parser.add_argument('--package-policy-path', help='Path to the optional package policy JSON file.')
    parser.add_argument('--debug', action='store_true', help='Enable debug reporting for allowed packages and verbose logging.')
    parser.add_argument('--markdown', action='store_true', help='Output the report as a Markdown table.')
    
    args = parser.parse_args()

    audit_licenses(args.sbom_path, args.policy_path, args.package_policy_path, args.debug, args.markdown)
