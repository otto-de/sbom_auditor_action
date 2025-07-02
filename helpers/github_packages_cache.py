#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

import os
import json
import hashlib
import logging
import requests
import tarfile
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any

class GitHubPackagesCacheManager:
    """
    Enhanced cache manager using GitHub Packages for organization-wide cache sharing.
    
    This approach uploads/downloads cache as GitHub Packages, enabling true
    cross-repository cache sharing within an organization.
    """
    
    def __init__(self, github_token: str, organization: str, cache_ttl_hours: int = 168):
        """
        Initialize GitHub Packages-based cache manager.
        
        Args:
            github_token: GitHub token with packages:read and packages:write permissions
            organization: GitHub organization name
            cache_ttl_hours: Time-to-live for cache entries in hours
        """
        self.github_token = github_token
        self.organization = organization
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.local_cache_dir = Path("./sbom_cache")
        self.local_cache_dir.mkdir(exist_ok=True)
        
        # GitHub Packages API endpoints
        self.packages_api_base = f"https://api.github.com/orgs/{organization}/packages"
        self.registry_base = f"https://npm.pkg.github.com/{organization}"
        
        logging.info(f"GitHub Packages cache manager initialized for org: {organization}")
    
    def _get_cache_package_name(self) -> str:
        """Generate package name for cache storage."""
        date_key = datetime.now().strftime("%Y-%m-%d")
        return f"sbom-cache-{date_key}"
    
    def _download_cache_package(self, package_name: str) -> bool:
        """
        Download cache package from GitHub Packages.
        
        Returns:
            True if cache was successfully downloaded and extracted
        """
        try:
            # Download the package tarball
            download_url = f"{self.registry_base}/{package_name}/-/{package_name}-1.0.0.tgz"
            headers = {
                "Authorization": f"Bearer {self.github_token}",
                "Accept": "application/vnd.npm.install-v1+json"
            }
            
            response = requests.get(download_url, headers=headers, stream=True)
            if response.status_code != 200:
                logging.debug(f"Cache package {package_name} not found or not accessible")
                return False
            
            # Extract cache to local directory
            with tempfile.NamedTemporaryFile(suffix='.tgz') as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()
                
                with tarfile.open(temp_file.name, 'r:gz') as tar:
                    tar.extractall(path=self.local_cache_dir.parent)
            
            logging.info(f"Successfully downloaded and extracted cache package: {package_name}")
            return True
            
        except Exception as e:
            logging.warning(f"Failed to download cache package {package_name}: {e}")
            return False
    
    def _upload_cache_package(self, package_name: str) -> bool:
        """
        Upload local cache as a GitHub Package.
        
        Returns:
            True if cache was successfully uploaded
        """
        try:
            # Create package tarball
            with tempfile.NamedTemporaryFile(suffix='.tgz') as temp_file:
                with tarfile.open(temp_file.name, 'w:gz') as tar:
                    tar.add(self.local_cache_dir, arcname='sbom_cache')
                
                # Create package.json for npm package
                package_json = {
                    "name": f"@{self.organization}/{package_name}",
                    "version": "1.0.0",
                    "description": "SBOM enrichment cache for organization",
                    "private": True,
                    "repository": {
                        "type": "git",
                        "url": f"https://github.com/{self.organization}/sbom-cache"
                    }
                }
                
                # Upload to GitHub Packages (npm registry)
                upload_url = f"{self.registry_base}/{package_name}"
                headers = {
                    "Authorization": f"Bearer {self.github_token}",
                    "Content-Type": "application/x-compressed"
                }
                
                temp_file.seek(0)
                response = requests.put(upload_url, headers=headers, data=temp_file.read())
                
                if response.status_code in [200, 201]:
                    logging.info(f"Successfully uploaded cache package: {package_name}")
                    return True
                else:
                    logging.warning(f"Failed to upload cache package: {response.status_code} - {response.text}")
                    return False
                
        except Exception as e:
            logging.error(f"Failed to upload cache package {package_name}: {e}")
            return False
    
    def load_organizational_cache(self) -> bool:
        """
        Load cache from GitHub Packages for the organization.
        
        Returns:
            True if organizational cache was successfully loaded
        """
        package_name = self._get_cache_package_name()
        
        # Try today's cache first
        if self._download_cache_package(package_name):
            return True
        
        # Try previous days as fallback
        for days_back in range(1, 8):  # Last 7 days
            fallback_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
            fallback_package = f"sbom-cache-{fallback_date}"
            
            if self._download_cache_package(fallback_package):
                logging.info(f"Loaded fallback cache from {days_back} days ago")
                return True
        
        logging.info("No organizational cache found, starting fresh")
        return False
    
    def save_organizational_cache(self) -> bool:
        """
        Save current cache to GitHub Packages for organization sharing.
        
        Returns:
            True if cache was successfully saved
        """
        package_name = self._get_cache_package_name()
        return self._upload_cache_package(package_name)
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get statistics about the current local cache."""
        cache_files = list(self.local_cache_dir.glob("*.json"))
        valid_files = 0
        
        for cache_file in cache_files:
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                cached_time = datetime.fromisoformat(cache_data.get('cached_at', '1970-01-01'))
                if datetime.now() - cached_time < self.cache_ttl:
                    valid_files += 1
            except (json.JSONDecodeError, ValueError, KeyError):
                continue
        
        return {
            'total_entries': len(cache_files),
            'valid_entries': valid_files,
            'expired_entries': len(cache_files) - valid_files
        }
