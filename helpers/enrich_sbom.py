#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

import json
import requests
import argparse
import logging
import os
from tqdm import tqdm
import urllib.parse
from urllib.parse import quote
from cache_manager import SBOMCacheManager

def enrich_sbom_with_depsdev(input_sbom_path, output_sbom_path, cache_ttl_hours=168):
    # Initialize cache manager with GitHub token for org-wide caching
    github_token = os.getenv('GITHUB_TOKEN')
    cache_manager = SBOMCacheManager(cache_ttl_hours=cache_ttl_hours, github_token=github_token)
    cache_stats = cache_manager.get_cache_stats()
    logging.info(f"Cache initialized: {cache_stats['valid_entries']} valid entries, {cache_stats['expired_entries']} expired")
    
    with open(input_sbom_path, 'r') as f:
        sbom = json.load(f)

    enriched = 0
    skipped = 0
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

    for pkg in tqdm(packages_to_process, desc="Enriching SBOM"):
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

        # Check for internal packages
        if (purl.startswith("pkg:maven/de.otto.hellfish") or 
                purl.startswith("pkg:maven/de.otto") or
                purl.startswith("pkg:github/otto-ec/hellfish_serviceorder_management")):
            pkg["licenseConcluded"] = "internal"
            if purl not in skipped_packages["internal"]:
                skipped_packages["internal"].append(purl)
            continue

        # Check for GitHub Actions
        if purl.startswith("pkg:githubactions"):
            skipped += 1
            if purl not in skipped_packages["github_actions"]:
                skipped_packages["github_actions"].append(purl)
            continue

        try:
            licenses = []
            clean_purl = purl.split('?')[0]
            
            # If the PURL doesn't have a version, try to add it from versionInfo
            if '@' not in clean_purl and pkg.get('versionInfo'):
                clean_purl = f"{clean_purl}@{pkg['versionInfo']}"

            # Check cache first
            cached_data = cache_manager.get_cached_package_info(clean_purl)
            if cached_data:
                licenses = cached_data.get('licenses', [])
                pkg["licenseConcluded"] = licenses[0] if licenses else "UNKNOWN"
                
                # Add detailed logging for cache hits
                if licenses:
                    logging.debug(f"CACHE HIT: {clean_purl} -> {licenses[0]} (from cache)")
                    enriched += 1
                else:
                    logging.warning(f"CACHE HIT BUT NO LICENSE: {clean_purl} -> UNKNOWN (cached but no license data)")
                    skipped += 1
                    if clean_purl not in skipped_packages["not_found"]:
                        skipped_packages["not_found"].append(clean_purl)
                continue

            # Cache miss - fetch from API
            encoded_purl = quote(clean_purl, safe='')
            api_url = f"https://api.deps.dev/v3alpha/purl/{encoded_purl}"
            logging.debug(f"CACHE MISS: {clean_purl} -> fetching from API")
            resp = requests.get(api_url)
            
            # A versioned PURL response has a "version" key. A package-level response has a "package" key.
            if resp.status_code == 200:
                data = resp.json()
                if "version" in data:
                    licenses = data.get("version", {}).get("licenses", [])
                    logging.debug(f"API RESPONSE: {clean_purl} -> {licenses} (version endpoint)")
            
            # If we still have no licenses, trigger the fallback.
            if not licenses:
                # We need package-level info. If the first call was for a version, we need to make a new call for the package.
                if '@' in clean_purl:
                    purl_no_version = clean_purl.split('@')[0]
                    encoded_purl_no_version = quote(purl_no_version, safe='')
                    package_api_url = f"https://api.deps.dev/v3alpha/purl/{encoded_purl_no_version}"
                    logging.debug(f"FALLBACK: {clean_purl} -> trying package endpoint {purl_no_version}")
                    package_resp = requests.get(package_api_url)
                else:
                    # The first call was already for the package, so we can reuse the response.
                    package_resp = resp
                    purl_no_version = clean_purl

                if package_resp.status_code == 200:
                    package_data = package_resp.json()
                    versions = package_data.get("package", {}).get("versions", [])
                    if versions:
                        latest_version = max(versions, key=lambda v: v.get("publishedAt", "0"))
                        latest_version_number = latest_version.get("versionKey", {}).get("version")
                        
                        if latest_version_number:
                            versioned_purl = f"{purl_no_version}@{latest_version_number}"
                            encoded_versioned_purl = quote(versioned_purl, safe='')
                            versioned_api_url = f"https://api.deps.dev/v3alpha/purl/{encoded_versioned_purl}"
                            
                            versioned_resp = requests.get(versioned_api_url)
                            if versioned_resp.status_code == 200:
                                versioned_data = versioned_resp.json()
                                licenses = versioned_data.get("version", {}).get("licenses", [])
                                logging.debug(f"LATEST VERSION: {clean_purl} -> {licenses} (latest: {versioned_purl})")

            # Cache the result
            cache_data = {
                'licenses': licenses,
                'fetched_from': 'deps.dev',
                'api_calls': 1 if resp.status_code == 200 else 0
            }
            cache_manager.cache_package_info(clean_purl, cache_data)
            logging.debug(f"CACHED: {clean_purl} -> {licenses}")

            if licenses:
                pkg["licenseConcluded"] = ",".join(licenses)
                logging.info(f"ENRICHED: {clean_purl} -> {','.join(licenses)}")
                enriched += 1
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
    
    print(f"✅ Enriched {enriched} packages. Skipped {skipped}.")
    print(f"📦 Cache: {final_cache_stats['valid_entries']} entries, cleaned {cleaned_entries} expired")

    print("\n--- Skipped Packages Summary ---")
    for reason, pkgs in skipped_packages.items():
        if pkgs:
            print(f"\n{reason.replace('_', ' ').title()} ({len(pkgs)}):")
            for p in pkgs:
                print(f"  - {p}")
    print("\n------------------------------")

    with open(output_sbom_path, 'w') as f:
        json.dump(sbom, f, indent=2)
    print(f"💾 Output written to {output_sbom_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enrich an SPDX SBOM with license data from deps.dev"
    )
    parser.add_argument("input", help="Input SPDX SBOM JSON file")
    parser.add_argument("output", help="Output enriched SPDX JSON file")
    parser.add_argument("--cache-ttl-hours", type=int, default=168, 
                        help="Cache TTL in hours (default: 168 = 7 days)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    enrich_sbom_with_depsdev(args.input, args.output, args.cache_ttl_hours)
