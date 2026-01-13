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
import xml.etree.ElementTree as ET
from tqdm import tqdm
import urllib.parse
from urllib.parse import quote
from cache_manager import SBOMCacheManager
from license_resolver import LicenseResolver

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def get_maven_license_from_pom(package_name, version=None):
    """
    Try to get the real license from a Maven package's POM file.
    
    Args:
        package_name: Maven package name (e.g., 'org.junit.platform:junit-platform-commons')
        version: Package version (optional, will use latest if not provided)
        
    Returns:
        License name from POM or None if not found
    """
    try:
        # Convert package name to path format
        group_id, artifact_id = package_name.split(':')
        group_path = group_id.replace('.', '/')
        
        # If no version provided, we need to find the latest
        if not version:
            # Get the latest version from Maven Central metadata
            metadata_url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/maven-metadata.xml"
            metadata_resp = requests.get(metadata_url, timeout=10)
            
            if metadata_resp.status_code == 200:
                try:
                    root = ET.fromstring(metadata_resp.text)
                    latest_elem = root.find('.//latest')
                    if latest_elem is not None:
                        version = latest_elem.text
                    else:
                        # Fallback to last version in versions list
                        versions_elem = root.find('.//versions')
                        if versions_elem is not None:
                            version_elems = versions_elem.findall('version')
                            if version_elems:
                                version = version_elems[-1].text
                except ET.ParseError:
                    logging.warning(f"Could not parse metadata XML for {package_name}")
                    return None
            else:
                logging.warning(f"Could not fetch metadata for {package_name}")
                return None
        
        if not version:
            return None
        
        # Download the POM file
        pom_url = f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{version}/{artifact_id}-{version}.pom"
        pom_resp = requests.get(pom_url, timeout=10)
        
        if pom_resp.status_code == 200:
            try:
                root = ET.fromstring(pom_resp.text)
                
                # Look for license information in the POM
                # Handle XML namespaces - Maven POM might have default namespace
                namespaces = {'m': 'http://maven.apache.org/POM/4.0.0'} if 'xmlns' in pom_resp.text else {}
                
                # Try with namespace first, then without
                license_paths = [
                    './/m:licenses/m:license/m:name',  # With namespace
                    './/licenses/license/name'        # Without namespace
                ]
                
                for path in license_paths:
                    if namespaces:
                        license_elem = root.find(path, namespaces)
                    else:
                        license_elem = root.find(path)
                        
                    if license_elem is not None and license_elem.text:
                        license_name = license_elem.text.strip()
                        logging.debug(f"Found license in POM for {package_name}:{version}: {license_name}")
                        return license_name
                
                # If no license found in direct elements, check parent POM
                parent_elem = root.find('.//parent') if not namespaces else root.find('.//m:parent', namespaces)
                if parent_elem is not None:
                    parent_group_id = None
                    parent_artifact_id = None
                    parent_version = None
                    
                    for child in parent_elem:
                        tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag  # Remove namespace
                        if tag == 'groupId':
                            parent_group_id = child.text
                        elif tag == 'artifactId':
                            parent_artifact_id = child.text
                        elif tag == 'version':
                            parent_version = child.text
                    
                    if parent_group_id and parent_artifact_id and parent_version:
                        parent_package = f"{parent_group_id}:{parent_artifact_id}"
                        logging.debug(f"Checking parent POM: {parent_package}:{parent_version}")
                        return get_maven_license_from_pom(parent_package, parent_version)
                
            except ET.ParseError as e:
                logging.warning(f"Could not parse POM XML for {package_name}:{version}: {e}")
                return None
        else:
            logging.debug(f"Could not fetch POM for {package_name}:{version} (status: {pom_resp.status_code})")
            return None
            
    except Exception as e:
        logging.debug(f"Error getting license from POM for {package_name}: {e}")
        return None


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

            # Parse PURL components
            purl_parts = purl.split('/')
            if len(purl_parts) < 2:
                continue
                
            ecosystem = purl_parts[0].replace('pkg:', '')
            
            # Handle Maven packages specially (use : format for deps.dev)
            if ecosystem == 'maven':
                if len(purl_parts) < 3:
                    continue
                namespace = purl_parts[1] 
                name_version = purl_parts[2]
                name = name_version.split('@')[0]
                package_name = f"{namespace}:{name}"
                
                # Get version if specified
                version = None
                if '@' in name_version:
                    version = name_version.split('@')[1]
            else:
                # Other ecosystems 
                if len(purl_parts) >= 3:
                    package_name = f"{purl_parts[1]}/{purl_parts[2].split('@')[0]}"
                else:
                    package_name = purl_parts[1].split('@')[0]
                
                version = None
                if '@' in purl_parts[-1]:
                    version = purl_parts[-1].split('@')[1]
            
            # Check cache first
            cache_key = f"depsdev:{ecosystem}:{package_name}"
            if version:
                cache_key += f":{version}"
                
            cached_result = cache_manager.get_cached_package_info(cache_key)
            
            if cached_result:
                license_data = cached_result.get('license_data')
                logging.debug(f"CACHE HIT: {package_name}")
            else:
                # Query deps.dev API with correct format
                encoded_package = quote(package_name, safe='')
                
                if version:
                    # Get specific version
                    url = f"https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{encoded_package}/versions/{version}"
                else:
                    # Get package info (latest versions)  
                    url = f"https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{encoded_package}"
                
                response = requests.get(url, timeout=10)
                license_data = None
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if version:
                        # Direct version response
                        license_data = data.get('licenses', [])
                        
                        # Check for detailed license information
                        license_details = data.get('licenseDetails', [])
                        if license_details:
                            # Use detailed license information if available
                            detailed_licenses = []
                            for detail in license_details:
                                license_name = detail.get('license')
                                if license_name:
                                    detailed_licenses.append(license_name)
                                    logging.debug(f"Found detailed license: {license_name} (SPDX: {detail.get('spdx')})")
                            
                            if detailed_licenses:
                                license_data = detailed_licenses
                                logging.debug(f"🔍 Using detailed license info from deps.dev for {package_name}: {detailed_licenses}")
                    else:
                        # Package response - get from latest version
                        versions = data.get('versions', [])
                        if versions:
                            # Try to get license from the first (usually latest) version
                            latest_version_info = versions[0]
                            version_to_fetch = latest_version_info.get('versionKey', {}).get('version')
                            
                            if version_to_fetch:
                                version_url = f"https://api.deps.dev/v3alpha/systems/{ecosystem}/packages/{encoded_package}/versions/{version_to_fetch}"
                                version_response = requests.get(version_url, timeout=10)
                                
                                if version_response.status_code == 200:
                                    version_data = version_response.json()
                                    license_data = version_data.get('licenses', [])
                                    
                                    # Check for detailed license information
                                    license_details = version_data.get('licenseDetails', [])
                                    if license_details:
                                        detailed_licenses = []
                                        for detail in license_details:
                                            license_name = detail.get('license')
                                            if license_name:
                                                detailed_licenses.append(license_name)
                                                logging.debug(f"Found detailed license: {license_name}")
                                        
                                        if detailed_licenses:
                                            license_data = detailed_licenses
                                            logging.debug(f"🔍 Using detailed license info from deps.dev for {package_name}: {detailed_licenses}")
                    
                    # Cache the result
                    cache_manager.cache_package_info(cache_key, {
                        'license_data': license_data,
                        'source': 'deps.dev'
                    })
                    logging.debug(f"API CALL: {package_name} -> {response.status_code}")
                else:
                    logging.debug(f"API ERROR: {package_name} -> {response.status_code}")
                    # Cache empty result to avoid repeated failures
                    cache_manager.cache_package_info(cache_key, {
                        'license_data': None,
                        'source': 'deps.dev_error'
                    })

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
                        # Special handling for "non-standard" - try Maven POM fallback only if deps.dev didn't provide details
                        if orig_license == "non-standard" and ecosystem == "maven":
                            # Only use POM fallback if deps.dev didn't already provide the detailed license
                            if not any("Eclipse Public License" in str(lic) for lic in licenses):
                                real_license = get_maven_license_from_pom(package_name, version)
                                if real_license:
                                    logging.info(f"🔍 Found real license in POM for {package_name}: {real_license}")
                                    orig_license = real_license
                        
                        resolution_result = license_resolver.resolve_license(orig_license)
                        
                        if resolution_result['resolved']:
                            resolved_licenses.append(resolution_result['resolved'])
                            license_resolved += 1
                            
                            # Track resolution statistics
                            method = resolution_result['method']
                            resolution_stats[method] = resolution_stats.get(method, 0) + 1
                            
                            logging.debug(f"🎯 RESOLVED: '{orig_license}' → '{resolution_result['resolved']}' ({method})")
                            
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
                    
                    logging.debug(f"ENRICHED: {package_name} -> {pkg['licenseConcluded']}")
                    enriched += 1
                else:
                    logging.warning(f"NO LICENSE FOUND: {package_name} -> UNKNOWN")
                    skipped += 1
                    if purl not in skipped_packages["not_found"]:
                        skipped_packages["not_found"].append(purl)
            else:
                logging.warning(f"NO LICENSE FOUND: {package_name} -> UNKNOWN")
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
