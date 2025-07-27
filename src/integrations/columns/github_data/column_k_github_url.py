"""
Column K: GitHub URL Processor

Extracts GitHub repository URL from PyPI metadata.
Enhanced based on retired version's comprehensive approach.
"""

import logging
import re
from typing import Dict, Any, Optional
from ....integrations.pypi_client import PyPIClient


class GitHubURLProcessor:
    """Processor for Column K - GitHub URL"""
    
    def __init__(self, pypi_client: PyPIClient):
        """
        Initialize processor.
        
        Args:
            pypi_client: PyPI client for API calls
        """
        self.pypi_client = pypi_client
        self.logger = logging.getLogger(__name__)
    
    async def process(self, package_name: str, current_version: str = None) -> Dict[str, Any]:
        """
        Process Column K: GitHub URL
        
        Extracts GitHub repository URL from PyPI metadata.
        Based on retired version's comprehensive URL extraction.
        
        Args:
            package_name: Name of the Python package
            current_version: Current version (not used for this column)
            
        Returns:
            Dictionary with GitHub URL information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column K (github_url) for {package_name}")
            
            # Get package info from PyPI
            package_info = await self.pypi_client.get_package_info(package_name)
            if not package_info:
                return {
                    'value': 'Package not found',
                    'color': 'not_available',
                    'font': 'not_available',
                    'note': f'Package {package_name} not found on PyPI'
                }
            
            # Extract GitHub URL using comprehensive approach
            github_url = await self._extract_github_url_comprehensive(package_info)
            
            if github_url:
                # Clean and validate GitHub URL
                clean_url = self._clean_github_url(github_url)
                return {
                    'value': clean_url,
                    'color': 'github_added',
                    'font': 'github_added',
                    'note': 'GitHub repository found',
                    'hyperlink': clean_url,
                    'url_source': self._determine_url_source(github_url, package_info)
                }
            else:
                return {
                    'value': 'No GitHub repo',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': 'No GitHub repository URL found in package metadata'
                }
            
        except Exception as e:
            self.logger.error(f"Error processing Column K for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error retrieving GitHub URL: {str(e)}'
            }
    
    async def _extract_github_url_comprehensive(self, package_info) -> Optional[str]:
        """
        Extract GitHub URL using comprehensive approach from multiple sources.
        
        Based on retired version's multi-source extraction logic.
        """
        # Method 1: Direct GitHub URL from package info
        github_url = package_info.github_url
        if github_url:
            return github_url
        
        # Method 2: Check project URLs
        project_urls = package_info.project_urls or {}
        for key, url in project_urls.items():
            if url and 'github.com' in str(url).lower():
                return str(url)
        
        # Method 3: Check homepage
        homepage = package_info.home_page
        if homepage and 'github.com' in homepage.lower():
            return homepage
        
        # Method 4: Search in description
        description = package_info.description or ''
        github_match = re.search(r'https?://github\.com/[^\s\)]+', description)
        if github_match:
            return github_match.group()
        
        # Method 5: Search in summary/long description
        summary = package_info.summary or ''
        github_match = re.search(r'https?://github\.com/[^\s\)]+', summary)
        if github_match:
            return github_match.group()
        
        return None
    
    def _clean_github_url(self, url: str) -> str:
        """
        Clean and standardize GitHub URL.
        
        Based on retired version's URL cleaning logic.
        """
        # Remove trailing slashes and .git
        url = url.rstrip('/').rstrip('.git')
        
        # Ensure https
        if url.startswith('http://'):
            url = url.replace('http://', 'https://')
        elif not url.startswith('https://'):
            url = f"https://{url}"
        
        # Remove extra path components that might not be the main repo
        # But preserve /tree/ or /blob/ paths if they look like legitimate references
        github_match = re.match(r'(https://github\.com/[^/]+/[^/]+)', url)
        if github_match:
            return github_match.group(1)
        
        return url
    
    def _determine_url_source(self, url: str, package_info) -> str:
        """Determine where the GitHub URL was found for debugging purposes."""
        if package_info.github_url == url:
            return "direct_github_url"
        elif package_info.home_page == url:
            return "homepage"
        elif url in str(package_info.project_urls):
            return "project_urls"
        elif url in str(package_info.description):
            return "description"
        else:
            return "other"