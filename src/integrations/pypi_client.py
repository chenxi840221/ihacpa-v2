"""
PyPI API Client for IHACPA v2.0

Provides comprehensive PyPI integration with async support, caching,
and enhanced package information retrieval.
"""

import aiohttp
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
import logging
from pathlib import Path
import json

from ..utils.version_utils import VersionUtils


class PyPIPackageInfo:
    """Structured package information from PyPI"""
    
    def __init__(self, data: Dict[str, Any]):
        self.raw_data = data
        self.info = data.get('info', {})
        self.releases = data.get('releases', {})
        
        # Basic information
        self.name = self.info.get('name', '')
        self.version = self.info.get('version', '')
        self.summary = self.info.get('summary', '')
        self.description = self.info.get('description', '')
        self.author = self.info.get('author', '')
        self.author_email = self.info.get('author_email', '')
        self.maintainer = self.info.get('maintainer', '')
        self.license = self.info.get('license', '')
        self.home_page = self.info.get('home_page', '')
        self.keywords = self.info.get('keywords', '')
        self.classifiers = self.info.get('classifiers', [])
        
        # URLs
        self.project_urls = self.info.get('project_urls', {}) or {}
        self.package_url = self.info.get('package_url', '')
        
        # Dependencies
        self.requires_dist = self.info.get('requires_dist', []) or []
        
        # Parse release information
        self.latest_release_date = self._parse_latest_release_date()
        self.github_url = self._extract_github_url()
        self.dependencies = self._parse_dependencies()
        
    def _parse_latest_release_date(self) -> Optional[datetime]:
        """Parse the latest release date"""
        if not self.version or self.version not in self.releases:
            return None
        
        release_files = self.releases[self.version]
        if not release_files:
            return None
        
        upload_time = release_files[0].get('upload_time_iso_8601', '')
        if upload_time:
            try:
                # Handle timezone info
                upload_time = upload_time.replace('Z', '+00:00')
                return datetime.fromisoformat(upload_time)
            except ValueError:
                return None
        
        return None
    
    def _extract_github_url(self) -> Optional[str]:
        """Extract GitHub URL from project URLs or homepage"""
        # Check project URLs first
        for key, url in self.project_urls.items():
            if url and ('github.com' in str(url).lower() or 'github' in key.lower()):
                return str(url)
        
        # Check homepage
        if self.home_page and 'github.com' in self.home_page.lower():
            return self.home_page
        
        return None
    
    def _parse_dependencies(self) -> List[str]:
        """Parse dependencies from requires_dist"""
        dependencies = []
        
        for req in self.requires_dist:
            if isinstance(req, str):
                # Extract package name (before any version specifiers or conditions)
                dep_name = req.split('(')[0].split('[')[0].split(';')[0]
                dep_name = dep_name.split('=')[0].split('<')[0].split('>')[0].split('!')[0]
                dep_name = dep_name.strip()
                
                if dep_name and dep_name not in dependencies:
                    dependencies.append(dep_name)
        
        return dependencies
    
    def get_version_info(self, version: str) -> Optional[Dict[str, Any]]:
        """Get information for a specific version"""
        if version not in self.releases:
            return None
        
        release_files = self.releases[version]
        if not release_files:
            return None
        
        first_file = release_files[0]
        upload_time = first_file.get('upload_time_iso_8601', '')
        release_date = None
        
        if upload_time:
            try:
                upload_time = upload_time.replace('Z', '+00:00')
                release_date = datetime.fromisoformat(upload_time)
            except ValueError:
                pass
        
        return {
            'version': version,
            'release_date': release_date,
            'files': len(release_files),
            'python_version': first_file.get('python_version', ''),
            'requires_python': first_file.get('requires_python', ''),
            'size': first_file.get('size', 0),
            'upload_time': upload_time
        }
    
    def get_all_versions(self) -> List[str]:
        """Get all available versions"""
        return list(self.releases.keys())
    
    def get_latest_version(self) -> str:
        """Get the latest version of the package"""
        return self.version
    
    def get_dependencies(self) -> List[str]:
        """Get package dependencies"""
        return self.dependencies
    
    def get_classifiers(self) -> List[str]:
        """Get package classifiers"""
        return self.classifiers
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'version': self.version,
            'summary': self.summary,
            'description': self.description,
            'author': self.author,
            'author_email': self.author_email,
            'maintainer': self.maintainer,
            'license': self.license,
            'home_page': self.home_page,
            'github_url': self.github_url,
            'keywords': self.keywords,
            'classifiers': self.classifiers,
            'project_urls': self.project_urls,
            'dependencies': self.dependencies,
            'requires_dist': self.requires_dist,
            'latest_release_date': self.latest_release_date.isoformat() if self.latest_release_date else None,
            'all_versions': self.get_all_versions(),
            'pypi_url': f"https://pypi.org/project/{self.name}/",
            'pypi_json_url': f"https://pypi.org/pypi/{self.name}/json"
        }


class PyPIClient:
    """Advanced PyPI API client with async support and caching"""
    
    BASE_URL = "https://pypi.org/pypi"
    
    def __init__(self, 
                 timeout: int = 30,
                 max_retries: int = 3,
                 retry_delay: float = 1.0,
                 enable_caching: bool = True,
                 cache_dir: Optional[Union[str, Path]] = None):
        """
        Initialize PyPI client.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            enable_caching: Whether to enable response caching
            cache_dir: Directory for cache files
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.enable_caching = enable_caching
        
        # Setup caching
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.cwd() / '.cache' / 'pypi'
        
        if self.enable_caching:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # HTTP session (will be created when needed)
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Logger
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'requests_made': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0,
            'retries': 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def _ensure_session(self):
        """Ensure HTTP session is available"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    'User-Agent': 'IHACPA-v2-PyPI-Client/2.0',
                    'Accept': 'application/json'
                }
            )
    
    async def get_package_info(self, package_name: str, use_cache: bool = True) -> Optional[PyPIPackageInfo]:
        """
        Get comprehensive package information.
        
        Args:
            package_name: Name of the package
            use_cache: Whether to use cached response if available
            
        Returns:
            PyPIPackageInfo object if successful, None otherwise
        """
        # Check cache first
        if use_cache and self.enable_caching:
            cached_data = await self._get_cached_response(package_name)
            if cached_data:
                self.stats['cache_hits'] += 1
                return PyPIPackageInfo(cached_data)
        
        self.stats['cache_misses'] += 1
        
        # Make API request
        url = f"{self.BASE_URL}/{package_name}/json"
        data = await self._make_request(url)
        
        if data:
            # Cache the response
            if self.enable_caching:
                await self._cache_response(package_name, data)
            
            return PyPIPackageInfo(data)
        
        return None
    
    async def get_package_version_info(self, package_name: str, version: str) -> Optional[Dict[str, Any]]:
        """
        Get information for a specific package version.
        
        Args:
            package_name: Name of the package
            version: Specific version
            
        Returns:
            Version information dictionary if successful, None otherwise
        """
        url = f"{self.BASE_URL}/{package_name}/{version}/json"
        data = await self._make_request(url)
        
        if data:
            package_info = PyPIPackageInfo(data)
            return package_info.get_version_info(version)
        
        return None
    
    async def search_packages(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search for packages (Note: PyPI search is limited).
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of package information dictionaries
        """
        # Note: PyPI's search API is no longer available
        # This is a placeholder for potential future implementation
        # or integration with alternative search services
        self.logger.warning("Package search not implemented - PyPI search API unavailable")
        return []
    
    async def check_package_exists(self, package_name: str) -> bool:
        """
        Check if a package exists on PyPI.
        
        Args:
            package_name: Name of the package to check
            
        Returns:
            True if package exists, False otherwise
        """
        url = f"{self.BASE_URL}/{package_name}/json"
        
        try:
            await self._ensure_session()
            async with self.session.get(url) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def get_package_versions(self, package_name: str) -> List[str]:
        """
        Get all available versions for a package.
        
        Args:
            package_name: Name of the package
            
        Returns:
            List of version strings
        """
        package_info = await self.get_package_info(package_name)
        if package_info:
            return package_info.get_all_versions()
        return []
    
    async def compare_versions(self, package_name: str, current_version: str) -> Optional[Dict[str, Any]]:
        """
        Compare current version with latest available.
        
        Args:
            package_name: Name of the package
            current_version: Current version to compare
            
        Returns:
            Comparison result dictionary if successful, None otherwise
        """
        package_info = await self.get_package_info(package_name)
        if not package_info:
            return None
        
        latest_version = package_info.version
        
        try:
            comparison = VersionUtils.compare_versions(current_version, latest_version)
            
            return {
                'package_name': package_name,
                'current_version': current_version,
                'latest_version': latest_version,
                'is_outdated': comparison['is_outdated'],
                'is_same': comparison['is_same'],
                'is_newer': comparison['is_newer'],
                'needs_update': comparison['needs_update'],
                'current_release_date': package_info.get_version_info(current_version),
                'latest_release_date': package_info.latest_release_date,
                'github_url': package_info.github_url
            }
            
        except Exception as e:
            self.logger.error(f"Version comparison failed for {package_name}: {e}")
            return None
    
    async def get_development_status(self, package_name: str) -> str:
        """
        Get development status from classifiers.
        
        Args:
            package_name: Name of the package
            
        Returns:
            Development status string
        """
        package_info = await self.get_package_info(package_name)
        if not package_info:
            return "Unknown"
        
        for classifier in package_info.classifiers:
            if 'Development Status' in classifier:
                # Extract status like "4 - Beta" from "Development Status :: 4 - Beta"
                status = classifier.split('::')[-1].strip()
                return status
        
        return "Unknown"
    
    async def _make_request(self, url: str) -> Optional[Dict[str, Any]]:
        """Make HTTP request with retry logic"""
        await self._ensure_session()
        
        for attempt in range(self.max_retries):
            try:
                self.stats['requests_made'] += 1
                
                async with self.session.get(url) as response:
                    if response.status == 404:
                        self.logger.debug(f"Package not found: {url}")
                        return None
                    
                    if response.status == 200:
                        data = await response.json()
                        self.logger.debug(f"Successfully fetched: {url}")
                        return data
                    
                    # Handle other status codes
                    self.logger.warning(f"HTTP {response.status} for {url}")
                    if response.status >= 500:  # Server error, retry
                        raise aiohttp.ClientError(f"Server error: {response.status}")
                    else:  # Client error, don't retry
                        return None
            
            except asyncio.TimeoutError:
                self.logger.warning(f"Timeout on attempt {attempt + 1} for {url}")
                if attempt == self.max_retries - 1:
                    self.stats['errors'] += 1
                    self.logger.error(f"Max retries exceeded for {url}")
                    return None
            
            except Exception as e:
                self.logger.warning(f"Request error on attempt {attempt + 1} for {url}: {e}")
                if attempt == self.max_retries - 1:
                    self.stats['errors'] += 1
                    return None
            
            # Wait before retry
            if attempt < self.max_retries - 1:
                self.stats['retries'] += 1
                await asyncio.sleep(self.retry_delay * (2 ** attempt))  # Exponential backoff
        
        return None
    
    async def _get_cached_response(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Get cached response for package"""
        if not self.enable_caching:
            return None
        
        cache_file = self.cache_dir / f"{package_name.lower()}.json"
        
        try:
            if cache_file.exists():
                # Check if cache is still valid (24 hours)
                cache_age = datetime.now().timestamp() - cache_file.stat().st_mtime
                if cache_age < 24 * 3600:  # 24 hours
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
                else:
                    # Cache expired, remove it
                    cache_file.unlink()
        except Exception as e:
            self.logger.debug(f"Cache read error for {package_name}: {e}")
        
        return None
    
    async def _cache_response(self, package_name: str, data: Dict[str, Any]):
        """Cache response for package"""
        if not self.enable_caching:
            return
        
        cache_file = self.cache_dir / f"{package_name.lower()}.json"
        
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, default=str, indent=2)
        except Exception as e:
            self.logger.debug(f"Cache write error for {package_name}: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        total_requests = self.stats['requests_made']
        cache_total = self.stats['cache_hits'] + self.stats['cache_misses']
        
        return {
            **self.stats,
            'cache_hit_rate': (self.stats['cache_hits'] / max(1, cache_total)) * 100,
            'error_rate': (self.stats['errors'] / max(1, total_requests)) * 100,
            'retry_rate': (self.stats['retries'] / max(1, total_requests)) * 100
        }
    
    async def clear_cache(self):
        """Clear all cached responses"""
        if not self.enable_caching or not self.cache_dir.exists():
            return
        
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
            self.logger.info("PyPI cache cleared")
        except Exception as e:
            self.logger.error(f"Error clearing cache: {e}")
    
    async def close(self):
        """Close HTTP session and clean up resources"""
        if self.session:
            await self.session.close()
            self.session = None