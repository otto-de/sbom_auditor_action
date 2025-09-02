#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

"""
Enhanced SBOM Enrichment with Intelligent License Resolution
Enriches SBOM with license data from deps.dev and resolves unknown licenses using SPDX matching.
"""

import json
import requests
import argparse
import logging
import os
import sys
from tqdm import tqdm
import urllib.parse
from urllib.parse import quote
from cache_manager import SBOMCacheManager
from license_resolver import LicenseResolver

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def enrich_sbom_with_intelligent_resolution(input_sbom_path, output_sbom_path, cache_ttl_hours=168, resolve_licenses=True):
    """
    Enrich SBOM with license data and intelligent license resolution.
    
    Args:
        input_sbom_path: Path to input SBOM file
        output_sbom_path: Path to output enriched SBOM file  
        cache_ttl_hours: Cache TTL in hours
        resolve_licenses: Whether to use intelligent license resolution
    """
    
    # Initialize components
    github_token = os.getenv('GITHUB_TOKEN')
    ai_api_key = os.getenv('GITHUB_TOKEN')  # Use same token for GitHub Models
    
    cache_manager = SBOMCacheManager(cache_ttl_hours=cache_ttl_hours, github_token=github_token)
    license_resolver = LicenseResolver(api_key=ai_api_key, ai_provider='github') if resolve_licenses else None
    
    cache_stats = cache_manager.get_cache_stats()
    logging.info(f"Cache initialized: {cache_stats['valid_entries']} valid entries, {cache_stats['expired_entries']} expired")
    
    if resolve_licenses:
        logging.info("✨ Intelligent license resolution enabled")
    
    with open(input_sbom_path, 'r') as f:
        sbom = json.load(f)

    enriched = 0
    license_resolved = 0
    skipped = 0
    resolution_stats = {}
    
    skipped_packages = {
        "internal": [],
        "github_actions": [],
        "not_found": [],
        "no_purl": [],
        "exception": []
    }

    # Handle SBOMs that have the package list nested under an "sbom" key
    sbom_content = sbom.get("sbom", sbom)
    packages_to_process = sbom_content.get("packages", []) or sbom_content.get("components", [])

    for pkg in tqdm(packages_to_process, desc="Enriching SBOM with license resolution"):
        # Extract purl from externalRefs
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break

        if not purl:
            skipped += 1
            if pkg.get('name', 'Unknown') not in skipped_packages["no_purl"]:
                skipped_packages["no_purl"].append(pkg.get('name', 'Unknown'))
            continue

        # Parse package URL for deps.dev query
        try:
            parsed_purl = urllib.parse.urlparse(purl)
            path_parts = parsed_purl.path.split('/')
            ecosystem = path_parts[0] if path_parts else ''
            
            # Skip internal and GitHub Actions packages
            if 'github.com' in purl and 'github.com/actions' not in purl:
                skipped += 1
                if purl not in skipped_packages["internal"]:
                    skipped_packages["internal"].append(purl)
                continue
                    
            if 'github.com/actions' in purl:
                skipped += 1
                if purl not in skipped_packages["github_actions"]:
                    skipped_packages["github_actions"].append(purl)
                continue

            # Clean purl for deps.dev (remove version constraints)
            clean_purl = purl.split('@')[0] if '@' in purl else purl
            
            # Check cache first
            cache_key = f"depsdev:{clean_purl}"
            cached_result = cache_manager.get_cached_result(cache_key)
            
            if cached_result:
                license_data = cached_result.get('license_data')
                logging.debug(f"CACHE HIT: {clean_purl}")
            else:
                # Query deps.dev API
                encoded_purl = quote(clean_purl, safe='')
                url = f"https://api.deps.dev/v3/systems/{ecosystem}/packages/{quote(path_parts[-1], safe='')}"
                
                response = requests.get(url, timeout=10)
                license_data = None
                
                if response.status_code == 200:
                    data = response.json()
                    versions = data.get('versions', [])
                    
                    if versions:
                        # Get the latest version's license info
                        latest_version = versions[0]
                        license_data = latest_version.get('licenses', [])
                        
                        # Cache the result
                        cache_manager.cache_result(cache_key, {
                            'license_data': license_data,
                            'source': 'deps.dev'
                        })
                        logging.debug(f"API CALL: {clean_purl} -> {response.status_code}")

            # Process license information
            if license_data:
                licenses = []
                raw_license_names = []
                
                for lic in license_data:
                    if isinstance(lic, str):
                        licenses.append(lic)
                        raw_license_names.append(lic)
                    elif isinstance(lic, dict):
                        license_name = lic.get('license') or lic.get('name')
                        if license_name:
                            licenses.append(license_name)
                            raw_license_names.append(license_name)

                # Apply intelligent license resolution if enabled
                resolved_licenses = []
                if resolve_licenses and license_resolver:
                    for orig_license in licenses:
                        resolution_result = license_resolver.resolve_license(orig_license)
                        
                        if resolution_result['resolved']:
                            resolved_licenses.append(resolution_result['resolved'])
                            license_resolved += 1
                            
                            # Track resolution statistics
                            method = resolution_result['method']
                            resolution_stats[method] = resolution_stats.get(method, 0) + 1
                            
                            logging.info(f"🎯 RESOLVED: '{orig_license}' → '{resolution_result['resolved']}' ({method})")
                            
                            # Add resolution metadata to package
                            if 'enrichment' not in pkg:
                                pkg['enrichment'] = {}
                            if 'licenseResolutions' not in pkg['enrichment']:
                                pkg['enrichment']['licenseResolutions'] = []
                                
                            pkg['enrichment']['licenseResolutions'].append({
                                'original': orig_license,
                                'resolved': resolution_result['resolved'],
                                'method': resolution_result['method'],
                                'confidence': resolution_result['confidence']
                            })
                        else:
                            resolved_licenses.append(orig_license)  # Keep original if can't resolve
                else:
                    resolved_licenses = licenses

                # Set the concluded license
                if resolved_licenses:
                    if len(resolved_licenses) == 1:
                        pkg["licenseConcluded"] = resolved_licenses[0]
                    else:
                        # Multiple licenses - create SPDX expression
                        pkg["licenseConcluded"] = " AND ".join(resolved_licenses)
                    
                    logging.info(f"ENRICHED: {clean_purl} -> {pkg['licenseConcluded']}")
                    enriched += 1
                else:
                    logging.warning(f"NO LICENSE FOUND: {clean_purl} -> UNKNOWN")
                    skipped += 1
                    if purl not in skipped_packages["not_found"]:
                        skipped_packages["not_found"].append(purl)
            else:
                logging.warning(f"NO LICENSE FOUND: {clean_purl} -> UNKNOWN")
                skipped += 1
                if purl not in skipped_packages["not_found"]:
                    skipped_packages["not_found"].append(purl)

        except Exception as e:
            skipped += 1
            logging.warning(f"Exception processing {purl}: {e}")
            if purl not in skipped_packages["exception"]:
                skipped_packages["exception"].append(purl)

    # Cleanup expired cache entries
    cleaned_entries = cache_manager.cleanup_expired_cache()
    final_cache_stats = cache_manager.get_cache_stats()
    
    # Print results
    print(f"✅ Enriched {enriched} packages. Skipped {skipped}.")
    
    if resolve_licenses:
        print(f"🎯 Licenses resolved: {license_resolved}")
        if resolution_stats:
            print("📊 Resolution methods:")
            for method, count in sorted(resolution_stats.items()):
                print(f"   {method}: {count}")
    
    print(f"📦 Cache: {final_cache_stats['valid_entries']} entries, cleaned {cleaned_entries} expired")

    print("\n--- Skipped Packages Summary ---")
    for reason, pkgs in skipped_packages.items():
        if pkgs:
            print(f"\n{reason.replace('_', ' ').title()} ({len(pkgs)}):")
            for p in pkgs[:10]:  # Show first 10 to avoid too much output
                print(f"  - {p}")
            if len(pkgs) > 10:
                print(f"  ... and {len(pkgs) - 10} more")
    print("\n------------------------------")

    with open(output_sbom_path, 'w') as f:
        json.dump(sbom, f, indent=2)
    print(f"💾 Output written to {output_sbom_path}")


# Keep the original function for backward compatibility
def enrich_sbom_with_depsdev(input_sbom_path, output_sbom_path, cache_ttl_hours=168):
    """Legacy function - calls enhanced version with license resolution disabled."""
    return enrich_sbom_with_intelligent_resolution(
        input_sbom_path, output_sbom_path, cache_ttl_hours, resolve_licenses=False
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enrich an SPDX SBOM with license data from deps.dev and intelligent license resolution"
    )
    parser.add_argument("input", help="Input SPDX SBOM JSON file")
    parser.add_argument("output", help="Output enriched SPDX JSON file")
    parser.add_argument("--cache-ttl-hours", type=int, default=168, 
                        help="Cache TTL in hours (default: 168 = 7 days)")
    parser.add_argument("--resolve-licenses", action="store_true", default=True,
                        help="Enable intelligent license resolution (default: enabled)")
    parser.add_argument("--no-resolve-licenses", dest="resolve_licenses", action="store_false",
                        help="Disable intelligent license resolution")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    enrich_sbom_with_intelligent_resolution(
        args.input, args.output, args.cache_ttl_hours, args.resolve_licenses
    )
