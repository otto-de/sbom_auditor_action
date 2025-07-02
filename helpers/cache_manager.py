#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

import os
import json
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any

class SBOMCacheManager:
    """
    Manages caching for SBOM enrichment data with organizational-level sharing.
    
    Supports multiple cache strategies:
    - Local filesystem cache
    - GitHub Actions cache integration (per-repository)
    - Organization-wide cache sharing via GitHub API
    """
    
    def __init__(self, cache_dir: str = None, cache_ttl_hours: int = 168, github_token: str = None):
        """
        Initialize the cache manager.
        
        Args:
            cache_dir: Directory for cache storage. Defaults to ./sbom_cache
            cache_ttl_hours: Time-to-live for cache entries in hours
            github_token: GitHub token for organization-wide cache sharing
        """
        self.cache_dir = Path(cache_dir or "./sbom_cache")
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.cache_dir.mkdir(exist_ok=True)
        
        # GitHub Actions cache integration
        self.github_cache_enabled = os.getenv('GITHUB_ACTIONS') == 'true'
        self.organization = os.getenv('GITHUB_REPOSITORY_OWNER', '')
        self.repository = os.getenv('GITHUB_REPOSITORY', '')
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        
        # Organization-wide cache settings
        self.org_cache_enabled = bool(self.github_token and self.organization)
        if self.org_cache_enabled:
            self.cache_repo = f"{self.organization}/sbom-cache"
            self.api_base = f"https://api.github.com/repos/{self.cache_repo}/contents"
        
        logging.info(f"Cache manager initialized: dir={self.cache_dir}, ttl={cache_ttl_hours}h, org={self.organization}, org_cache={self.org_cache_enabled}")
        
        # Load organizational cache on initialization
        if self.org_cache_enabled:
            self._load_organizational_cache()
    
    def _get_cache_key(self, purl: str) -> str:
        """Generate a stable cache key for a PURL."""
        # Normalize PURL and create a hash for filename safety
        clean_purl = purl.lower().strip()
        return hashlib.sha256(clean_purl.encode()).hexdigest()[:16]
    
    def _get_cache_file_path(self, cache_key: str) -> Path:
        """Get the full path for a cache file."""
        return self.cache_dir / f"{cache_key}.json"
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if a cache file is still valid based on TTL."""
        if not cache_file.exists():
            return False
        
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            cached_time = datetime.fromisoformat(cache_data.get('cached_at', '1970-01-01'))
            return datetime.now() - cached_time < self.cache_ttl
        except (json.JSONDecodeError, ValueError, KeyError):
            return False
    
    def get_cached_package_info(self, purl: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached package information for a PURL.
        
        Args:
            purl: Package URL to look up
            
        Returns:
            Cached package data or None if not found/expired
        """
        cache_key = self._get_cache_key(purl)
        cache_file = self._get_cache_file_path(cache_key)
        
        if not self._is_cache_valid(cache_file):
            logging.debug(f"Cache miss for {purl} (key: {cache_key})")
            return None
        
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            logging.debug(f"Cache hit for {purl} (key: {cache_key})")
            return cache_data.get('package_data')
        except (json.JSONDecodeError, FileNotFoundError):
            logging.warning(f"Invalid cache file for {purl}, removing...")
            cache_file.unlink(missing_ok=True)
            return None
    
    def cache_package_info(self, purl: str, package_data: Dict[str, Any]) -> None:
        """
        Cache package information for a PURL.
        
        Args:
            purl: Package URL 
            package_data: Package information to cache
        """
        cache_key = self._get_cache_key(purl)
        cache_file = self._get_cache_file_path(cache_key)
        
        cache_entry = {
            'purl': purl,
            'package_data': package_data,
            'cached_at': datetime.now().isoformat(),
            'organization': self.organization,
            'repository': self.repository,
            'cache_version': '1.0'
        }
        
        try:
            # Save to local cache
            with open(cache_file, 'w') as f:
                json.dump(cache_entry, f, indent=2)
            
            logging.debug(f"Cached package info for {purl} (key: {cache_key})")
            
            # Also save to organizational cache (async)
            if self.org_cache_enabled:
                self._save_to_organizational_cache(cache_key, cache_entry)
                
        except Exception as e:
            logging.warning(f"Failed to cache package info for {purl}: {e}")
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get statistics about the current cache."""
        cache_files = list(self.cache_dir.glob("*.json"))
        valid_files = sum(1 for f in cache_files if self._is_cache_valid(f))
        
        return {
            'total_entries': len(cache_files),
            'valid_entries': valid_files,
            'expired_entries': len(cache_files) - valid_files
        }
    
    def cleanup_expired_cache(self) -> int:
        """Remove expired cache entries and return the number of files removed."""
        removed = 0
        for cache_file in self.cache_dir.glob("*.json"):
            if not self._is_cache_valid(cache_file):
                try:
                    cache_file.unlink()
                    removed += 1
                    logging.debug(f"Removed expired cache file: {cache_file.name}")
                except Exception as e:
                    logging.warning(f"Failed to remove expired cache file {cache_file}: {e}")
        
        if removed > 0:
            logging.info(f"Cleaned up {removed} expired cache entries")
        
        return removed
    
    def export_cache_for_github_actions(self) -> str:
        """
        Export cache directory path for GitHub Actions cache.
        
        Returns:
            Cache directory path for use with actions/cache
        """
        return str(self.cache_dir)
    
    def get_cache_key_for_github_actions(self) -> str:
        """
        Generate a cache key for GitHub Actions cache.
        
        Returns:
            Cache key based on organization and date
        """
        # Include organization and date to enable org-wide sharing with daily rotation
        date_key = datetime.now().strftime("%Y-%m-%d")
        org_key = self.organization or "default"
        return f"sbom-cache-{org_key}-{date_key}"
    
    def get_restore_keys_for_github_actions(self) -> list:
        """
        Generate restore keys for GitHub Actions cache fallback.
        
        Returns:
            List of restore keys for cache fallback
        """
        org_key = self.organization or "default"
        
        # Try previous days as fallback
        restore_keys = []
        for days_back in range(1, 8):  # Last 7 days
            date_key = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
            restore_keys.append(f"sbom-cache-{org_key}-{date_key}")
        
        # Fallback to any cache from this org
        restore_keys.append(f"sbom-cache-{org_key}-")
        
        return restore_keys
    
    def _load_organizational_cache(self) -> int:
        """
        Load cache entries from organization-wide cache repository.
        
        Returns:
            Number of cache entries loaded
        """
        if not self.org_cache_enabled:
            return 0
        
        try:
            import requests
            import base64
            
            loaded = 0
            # Try to load recent cache entries
            for days_back in range(7):  # Last 7 days
                date_prefix = (datetime.now() - timedelta(days=days_back)).strftime("%Y/%m")
                cache_dir_path = f"cache/{date_prefix}"
                
                headers = {
                    "Authorization": f"Bearer {self.github_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
                
                try:
                    response = requests.get(f"{self.api_base}/{cache_dir_path}", headers=headers, timeout=10)
                    if response.status_code == 200:
                        files = response.json()
                        for file_info in files:
                            if file_info['name'].endswith('.json'):
                                # Download and cache locally
                                file_content = base64.b64decode(file_info['content']).decode('utf-8')
                                cache_data = json.loads(file_content)
                                
                                # Check if still valid
                                cached_time = datetime.fromisoformat(cache_data.get('cached_at', '1970-01-01'))
                                if datetime.now() - cached_time < self.cache_ttl:
                                    local_file = self.cache_dir / file_info['name']
                                    with open(local_file, 'w') as f:
                                        json.dump(cache_data, f, indent=2)
                                    loaded += 1
                except requests.RequestException:
                    # Skip failed requests, continue with local cache
                    continue
            
            if loaded > 0:
                logging.info(f"Loaded {loaded} cache entries from organizational cache")
            return loaded
            
        except Exception as e:
            logging.warning(f"Failed to load organizational cache: {e}")
            return 0
    
    def _save_to_organizational_cache(self, cache_key: str, cache_entry: Dict[str, Any]) -> None:
        """
        Save cache entry to organization-wide cache repository.
        
        Args:
            cache_key: Cache key for the entry
            cache_entry: Cache data to save
        """
        if not self.org_cache_enabled:
            return
        
        try:
            import requests
            import base64
            
            # Generate path in shared repository
            date_prefix = datetime.now().strftime("%Y/%m")
            cache_path = f"cache/{date_prefix}/{cache_key}.json"
            
            content = json.dumps(cache_entry, indent=2)
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            
            headers = {
                "Authorization": f"Bearer {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # Check if file exists
            existing_response = requests.get(f"{self.api_base}/{cache_path}", headers=headers, timeout=10)
            
            data = {
                "message": f"Update SBOM cache for {cache_entry.get('purl', 'unknown')}",
                "content": encoded_content,
                "branch": "main"
            }
            
            if existing_response.status_code == 200:
                data["sha"] = existing_response.json()["sha"]
            
            # Upload to shared repository
            response = requests.put(f"{self.api_base}/{cache_path}", headers=headers, json=data, timeout=30)
            
            if response.status_code in [200, 201]:
                logging.debug(f"Saved cache entry to organizational repository: {cache_path}")
            
        except Exception as e:
            logging.debug(f"Failed to save to organizational cache: {e}")
            # Don't fail the main operation if org cache fails
