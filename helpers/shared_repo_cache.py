#!/usr/bin/env python3
# Copyright (c) 2025 Otto GmbH & Co KG
# SPDX-License-Identifier: Apache-2.0

import os
import json
import base64
import logging
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any

class SharedRepositoryCacheManager:
    """
    Cache manager using a dedicated repository for organization-wide cache sharing.
    
    This approach uses a shared repository (e.g., otto-de/sbom-cache) to store
    cache files, enabling true cross-repository access within an organization.
    """
    
    def __init__(self, github_token: str, cache_repo: str, cache_ttl_hours: int = 168):
        """
        Initialize shared repository cache manager.
        
        Args:
            github_token: GitHub token with repo access to cache repository
            cache_repo: Repository for cache storage (e.g., "otto-de/sbom-cache")
            cache_ttl_hours: Time-to-live for cache entries in hours
        """
        self.github_token = github_token
        self.cache_repo = cache_repo
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.local_cache_dir = Path("./sbom_cache")
        self.local_cache_dir.mkdir(exist_ok=True)
        
        # GitHub API endpoints
        self.api_base = f"https://api.github.com/repos/{cache_repo}/contents"
        
        logging.info(f"Shared repository cache manager initialized: {cache_repo}")
    
    def _get_cache_file_path(self, package_purl: str) -> str:
        """Generate cache file path in the shared repository."""
        import hashlib
        cache_key = hashlib.sha256(package_purl.lower().encode()).hexdigest()[:16]
        date_prefix = datetime.now().strftime("%Y/%m")
        return f"cache/{date_prefix}/{cache_key}.json"
    
    def get_cached_package_info(self, package_purl: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached package information from shared repository.
        
        Args:
            package_purl: Package URL to look up
            
        Returns:
            Cached package data or None if not found/expired
        """
        try:
            cache_path = self._get_cache_file_path(package_purl)
            
            # First check local cache
            local_cache_file = self.local_cache_dir / f"{cache_path.replace('/', '_').replace('cache_', '')}"
            if local_cache_file.exists():
                with open(local_cache_file, 'r') as f:
                    cache_data = json.load(f)
                    cached_time = datetime.fromisoformat(cache_data.get('cached_at', '1970-01-01'))
                    if datetime.now() - cached_time < self.cache_ttl:
                        logging.debug(f"Local cache hit for {package_purl}")
                        return cache_data.get('package_data')
            
            # Check shared repository cache
            headers = {
                "Authorization": f"Bearer {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            response = requests.get(f"{self.api_base}/{cache_path}", headers=headers)
            
            if response.status_code == 200:
                file_data = response.json()
                content = base64.b64decode(file_data['content']).decode('utf-8')
                cache_data = json.loads(content)
                
                cached_time = datetime.fromisoformat(cache_data.get('cached_at', '1970-01-01'))
                if datetime.now() - cached_time < self.cache_ttl:
                    # Cache to local for faster subsequent access
                    with open(local_cache_file, 'w') as f:
                        json.dump(cache_data, f, indent=2)
                    
                    logging.debug(f"Shared repository cache hit for {package_purl}")
                    return cache_data.get('package_data')
            
            logging.debug(f"Cache miss for {package_purl}")
            return None
            
        except Exception as e:
            logging.warning(f"Failed to retrieve cache for {package_purl}: {e}")
            return None
    
    def cache_package_info(self, package_purl: str, package_data: Dict[str, Any]) -> None:
        """
        Cache package information to both local and shared repository.
        
        Args:
            package_purl: Package URL 
            package_data: Package information to cache
        """
        try:
            cache_entry = {
                'purl': package_purl,
                'package_data': package_data,
                'cached_at': datetime.now().isoformat(),
                'cache_version': '1.0'
            }
            
            # Save to local cache
            cache_path = self._get_cache_file_path(package_purl)
            local_cache_file = self.local_cache_dir / f"{cache_path.replace('/', '_').replace('cache_', '')}"
            
            with open(local_cache_file, 'w') as f:
                json.dump(cache_entry, f, indent=2)
            
            # Upload to shared repository (async/batch for performance)
            self._queue_for_shared_upload(cache_path, cache_entry)
            
            logging.debug(f"Cached package info for {package_purl}")
            
        except Exception as e:
            logging.warning(f"Failed to cache package info for {package_purl}: {e}")
    
    def _queue_for_shared_upload(self, cache_path: str, cache_entry: Dict[str, Any]) -> None:
        """Queue cache entry for upload to shared repository."""
        # In a production implementation, this would batch uploads for efficiency
        # For now, we'll upload immediately but this could be optimized
        try:
            content = json.dumps(cache_entry, indent=2)
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            
            headers = {
                "Authorization": f"Bearer {self.github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # Check if file exists to get SHA for update
            existing_response = requests.get(f"{self.api_base}/{cache_path}", headers=headers)
            
            data = {
                "message": f"Cache update for {cache_entry['purl']}",
                "content": encoded_content,
                "branch": "main"
            }
            
            if existing_response.status_code == 200:
                # File exists, need SHA for update
                data["sha"] = existing_response.json()["sha"]
            
            # Upload/update file
            response = requests.put(f"{self.api_base}/{cache_path}", headers=headers, json=data)
            
            if response.status_code in [200, 201]:
                logging.debug(f"Successfully uploaded cache to shared repository: {cache_path}")
            else:
                logging.warning(f"Failed to upload to shared repository: {response.status_code}")
                
        except Exception as e:
            logging.warning(f"Failed to upload cache to shared repository: {e}")
    
    def sync_from_shared_repository(self) -> int:
        """
        Sync recent cache entries from shared repository to local cache.
        
        Returns:
            Number of entries synced
        """
        try:
            # Get recent cache entries (last 7 days)
            synced = 0
            for days_back in range(7):
                date_prefix = (datetime.now() - timedelta(days=days_back)).strftime("%Y/%m")
                cache_dir_path = f"cache/{date_prefix}"
                
                headers = {
                    "Authorization": f"Bearer {self.github_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
                
                response = requests.get(f"{self.api_base}/{cache_dir_path}", headers=headers)
                
                if response.status_code == 200:
                    files = response.json()
                    for file_info in files:
                        if file_info['name'].endswith('.json'):
                            # Download and cache locally
                            file_response = requests.get(file_info['download_url'])
                            if file_response.status_code == 200:
                                cache_data = file_response.json()
                                local_file = self.local_cache_dir / file_info['name']
                                with open(local_file, 'w') as f:
                                    json.dump(cache_data, f, indent=2)
                                synced += 1
            
            logging.info(f"Synced {synced} cache entries from shared repository")
            return synced
            
        except Exception as e:
            logging.warning(f"Failed to sync from shared repository: {e}")
            return 0
