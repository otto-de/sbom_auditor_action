#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: MIT

import json
import requests
import argparse
from tqdm import tqdm

# Map common or problematic license IDs to the correct SPDX identifier
LICENSE_ID_MAP = {
    "LGPL-2.1": "LGPL-2.1-or-later",  # LGPL-2.1 is often ambiguous
}

def get_license_text(license_id):
    """Fetches the license text from the SPDX license list details JSON."""
    if not license_id or license_id.lower() in ["internal", "not found", "non-standard"]:
        return None
    
    spdx_id = LICENSE_ID_MAP.get(license_id, license_id)
    
    # Fetch license details from the JSON file for better reliability
    url = f"https://raw.githubusercontent.com/spdx/license-list-data/main/json/details/{spdx_id}.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json().get("licenseText", "")
        else:
            print(f"Warning: Could not fetch license JSON for {license_id} (tried {spdx_id}) (Status: {response.status_code})")
            return None
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"Warning: Request or JSON decode failed for {license_id} (tried {spdx_id}): {e}")
        return None

def collect_licenses(sbom_path, output_path):
    """Collects all unique licenses from an SBOM and writes them to a file."""
    with open(sbom_path, 'r') as f:
        sbom_data = json.load(f)

    # Handle SBOMs that have the content nested under an "sbom" key
    sbom_content = sbom_data.get("sbom", sbom_data)

    unique_licenses = set()
    
    components = sbom_content.get("packages", []) or sbom_content.get("components", [])
    for pkg in components:
        license_string = pkg.get("licenseConcluded")
        if license_string:
            # Handle comma-separated licenses
            licenses = license_string.split(',')
            for license_id in licenses:
                unique_licenses.add(license_id.strip())

    print(f"Found {len(unique_licenses)} unique licenses.")

    with open(output_path, 'w') as f:
        f.write("# Collected Licenses\n\n")
        f.write("This file contains the full text of all licenses found in the project's dependencies.\n\n")

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
