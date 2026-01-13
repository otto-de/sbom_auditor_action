#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

import json
import requests
import argparse
import re
from tqdm import tqdm

# Map common or problematic license IDs to the correct SPDX identifier
LICENSE_ID_MAP = {
    "LGPL-2.1": "LGPL-2.1-or-later",  # LGPL-2.1 is often ambiguous
    # Eclipse Distribution License variants
    "EDL 1.0": "BSD-3-Clause",  # EDL 1.0 is functionally BSD-3-Clause
    "Eclipse Distribution License - v 1.0": "BSD-3-Clause",
    "Eclipse Distribution License v. 1.0": "BSD-3-Clause",
    "Eclipse Distribution License 1.0": "BSD-3-Clause",
    # CDDL + GPL combinations (common in Java/GlassFish projects)
    "CDDL + GPLv2": "CDDL-1.1",  # Dual-licensed, use CDDL
    "CDDL+GPL": "CDDL-1.1",
    "CDDL + GPLv2 with classpath exception": "CDDL-1.1",
    "CDDL/GPLv2+CE": "CDDL-1.1",
    # GPL with Classpath Exception
    "GPL2 w/ CPE": "GPL-2.0-only WITH Classpath-exception-2.0",
    "GPLv2 with classpath exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    "GPL-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0",
    # Public Domain
    "Public Domain": "CC0-1.0",  # CC0 is the SPDX equivalent
    "Public domain": "CC0-1.0",
    "public domain": "CC0-1.0",
    "UNLICENSED": "Unlicense",
}

# SPDX expression operators and keywords to filter out
SPDX_OPERATORS = {'AND', 'OR', 'WITH', 'and', 'or', 'with'}


def parse_spdx_expression(expression):
    """
    Parses an SPDX license expression and extracts individual license IDs.
    
    Examples:
        "Apache-2.0 AND EPL-1.0" -> ["Apache-2.0", "EPL-1.0"]
        "MIT OR Apache-2.0" -> ["MIT", "Apache-2.0"]
        "GPL-2.0-only WITH Classpath-exception-2.0" -> ["GPL-2.0-only"]
    
    Returns:
        List of individual license IDs
    """
    if not expression:
        return []
    
    # Check if it's a simple license (no operators)
    if not any(f' {op} ' in expression for op in SPDX_OPERATORS):
        return [expression.strip()]
    
    # Split by SPDX operators (AND, OR, WITH)
    # Use regex to split while preserving case
    parts = re.split(r'\s+(?:AND|OR|WITH|and|or|with)\s+', expression)
    
    licenses = []
    for part in parts:
        # Clean up parentheses and whitespace
        cleaned = part.strip().strip('()')
        if cleaned and cleaned not in SPDX_OPERATORS:
            # Skip exception identifiers (they come after WITH)
            if not cleaned.lower().endswith('-exception') and 'exception' not in cleaned.lower():
                licenses.append(cleaned)
    
    return licenses


def get_license_text(license_id):
    """Fetches the license text from the SPDX license list details JSON."""
    if not license_id or license_id.lower() in ["internal", "not found", "non-standard", "noassertion", "none"]:
        return None
    
    # First, apply the license ID mapping
    spdx_id = LICENSE_ID_MAP.get(license_id, license_id)
    
    # If the mapped ID is itself an expression (e.g., "GPL-2.0-only WITH Classpath-exception-2.0"),
    # extract the base license (the part before WITH)
    fetch_id = spdx_id
    if ' WITH ' in spdx_id or ' with ' in spdx_id:
        fetch_id = re.split(r'\s+(?:WITH|with)\s+', spdx_id)[0].strip()
    
    # Fetch license details from the JSON file for better reliability
    url = f"https://raw.githubusercontent.com/spdx/license-list-data/main/json/details/{fetch_id}.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json().get("licenseText", "")
        else:
            # Only warn if it's not an expression (expressions are handled separately)
            if ' AND ' not in license_id and ' OR ' not in license_id:
                print(f"Warning: Could not fetch license JSON for {license_id} (tried {fetch_id}) (Status: {response.status_code})")
            return None
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"Warning: Request or JSON decode failed for {license_id} (tried {fetch_id}): {e}")
        return None

def collect_licenses(sbom_path, output_path):
    """Collects all unique licenses from an SBOM and writes them to a file."""
    with open(sbom_path, 'r') as f:
        sbom_data = json.load(f)

    # Handle SBOMs that have the content nested under an "sbom" key
    sbom_content = sbom_data.get("sbom", sbom_data)

    unique_licenses = set()
    license_expressions = set()  # Track original expressions for documentation
    
    components = sbom_content.get("packages", []) or sbom_content.get("components", [])
    for pkg in components:
        license_string = pkg.get("licenseConcluded")
        if license_string:
            # Handle comma-separated licenses
            licenses = license_string.split(',')
            for license_expr in licenses:
                license_expr = license_expr.strip()
                
                # Check if it's an SPDX expression (contains AND, OR, WITH)
                if any(f' {op} ' in license_expr for op in SPDX_OPERATORS):
                    license_expressions.add(license_expr)
                    # Extract individual licenses from expression
                    individual_licenses = parse_spdx_expression(license_expr)
                    for lic in individual_licenses:
                        unique_licenses.add(lic)
                else:
                    unique_licenses.add(license_expr)

    print(f"Found {len(unique_licenses)} unique licenses.")
    if license_expressions:
        print(f"  (including {len(license_expressions)} combined license expressions)")

    with open(output_path, 'w') as f:
        f.write("# Collected Licenses\n\n")
        f.write("This file contains the full text of all licenses found in the project's dependencies.\n\n")
        
        # Document combined license expressions
        if license_expressions:
            f.write("## Combined License Expressions\n\n")
            f.write("The following combined license expressions were found. ")
            f.write("Individual license texts are included below.\n\n")
            for expr in sorted(license_expressions):
                individual = parse_spdx_expression(expr)
                f.write(f"- `{expr}` → {', '.join(individual)}\n")
            f.write("\n---\n\n")

        sorted_licenses = sorted(list(unique_licenses))

        for license_id in tqdm(sorted_licenses, desc="Fetching Licenses"):
            license_text = get_license_text(license_id)
            if license_text:
                f.write(f"## {license_id}\n\n")
                f.write("```\n")
                f.write(license_text)
                f.write("\n```\n\n")
                f.write("---\n\n")

    print(f"✅ All license texts written to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Collect license texts from an enriched SPDX SBOM."
    )
    parser.add_argument(
        "input", 
        help="Input enriched SPDX SBOM JSON file (e.g., sbom_enriched.json)"
    )
    parser.add_argument(
        "output", 
        nargs='?',
        default="LICENSES.md",
        help="Output file for collected license texts (default: LICENSES.md)"
    )
    args = parser.parse_args()

    collect_licenses(args.input, args.output)
