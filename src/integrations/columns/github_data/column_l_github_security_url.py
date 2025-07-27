"""
Column L: GitHub Security URL Processor

Generates GitHub Security Advisories URL from GitHub repository URL.
Enhanced based on retired version's approach.
"""

import logging
import re
from typing import Dict, Any, Optional
from ....integrations.pypi_client import PyPIClient


class GitHubSecurityURLProcessor:
    """Processor for Column L - GitHub Security URL"""
    
    def __init__(self, pypi_client: PyPIClient):
        """
        Initialize processor.
        
        Args:
            pypi_client: PyPI client for API calls
        """
        self.pypi_client = pypi_client
        self.logger = logging.getLogger(__name__)
    
    async def process(self, package_name: str, github_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Process Column L: GitHub Security URL
        
        Generates GitHub Security Advisories URL from repository URL.
        
        Args:
            package_name: Name of the Python package
            github_url: Optional GitHub URL (if not provided, will be extracted)
            
        Returns:
            Dictionary with GitHub security URL information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column L (github_security_url) for {package_name}")
            
            if not github_url:
                # Get GitHub URL from package info
                package_info = await self.pypi_client.get_package_info(package_name)
                if package_info:
                    github_url = package_info.github_url
            
            if not github_url or github_url in ['No GitHub repo', 'Package not found', 'Error']:
                return {
                    'value': 'No GitHub repo',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': 'Cannot generate security URL without GitHub repository'
                }
            
            # Extract owner/repo from GitHub URL
            repo_match = re.search(r'github\.com/([^/]+)/([^/]+)', github_url)
            if not repo_match:
                return {
                    'value': 'Invalid GitHub URL',
                    'color': 'critical',
                    'font': 'critical',
                    'note': f'Could not parse GitHub repository from URL: {github_url}'
                }
            
            owner, repo = repo_match.groups()
            # Remove .git suffix if present
            repo = repo.rstrip('.git')
            
            security_url = f"https://github.com/{owner}/{repo}/security/advisories"
            
            return {
                'value': security_url,
                'color': 'github_added',
                'font': 'github_added',
                'note': f'GitHub Security Advisories for {owner}/{repo}',
                'hyperlink': security_url,
                'owner': owner,
                'repo': repo
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column L for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error generating GitHub security URL: {str(e)}'
            }