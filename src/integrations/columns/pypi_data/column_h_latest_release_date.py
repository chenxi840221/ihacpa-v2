"""
Column H: Latest Version Release Date Processor

Gets the release date of the LATEST version available on PyPI,
not the current installed version (that's Column E).
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
from ....integrations.pypi_client import PyPIClient


class LatestReleaseDateProcessor:
    """Processor for Column H - Latest Version Release Date"""
    
    def __init__(self, pypi_client: PyPIClient):
        """
        Initialize processor.
        
        Args:
            pypi_client: PyPI client for API calls
        """
        self.pypi_client = pypi_client
        self.logger = logging.getLogger(__name__)
    
    async def process(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Process Column H: Latest Version Release Date
        
        Gets the release date of the latest available version on PyPI.
        This is different from Column E which gets the current version's date.
        
        Args:
            package_name: Name of the Python package
            current_version: Current version (not used for this column)
            
        Returns:
            Dictionary with latest release date information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column H (latest_release_date) for {package_name}")
            
            # Get package info from PyPI
            package_info = await self.pypi_client.get_package_info(package_name)
            if not package_info:
                return {
                    'value': 'Package not found',
                    'color': 'critical',
                    'font': 'critical', 
                    'note': f'Package {package_name} not found on PyPI'
                }
            
            # Get latest version
            latest_version = package_info.get_latest_version()
            if not latest_version:
                return {
                    'value': 'Latest version unknown',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': f'Could not determine latest version for {package_name}'
                }
            
            # Get release date for the LATEST version
            latest_release_date = await self._get_latest_version_release_date(package_info, latest_version)
            
            if not latest_release_date:
                return {
                    'value': 'Date not available',
                    'color': 'version_update', 
                    'font': 'version_update',
                    'note': f'Release date not available for latest version {latest_version}'
                }
            
            # Format date for display
            formatted_date = latest_release_date.strftime('%Y-%m-%d')
            
            # Determine color based on age of latest release
            days_old = (datetime.now() - latest_release_date.replace(tzinfo=None)).days
            if days_old <= 30:  # Very recent release
                color = 'new_data'
                font = 'new_data'
            elif days_old <= 90:  # Recent release
                color = 'updated'
                font = 'updated'
            elif days_old <= 365:  # Within last year
                color = 'version_update'
                font = 'version_update'
            else:  # Old release
                color = 'security_risk'
                font = 'security_risk'
            
            return {
                'value': formatted_date,
                'color': color,
                'font': font,
                'note': f'Latest version {latest_version} released {days_old} days ago',
                'raw_date': latest_release_date,
                'days_old': days_old,
                'latest_version': latest_version
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column H for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical', 
                'note': f'Error retrieving latest release date: {str(e)}'
            }
    
    async def _get_latest_version_release_date(self, package_info, latest_version: str) -> Optional[datetime]:
        """
        Extract release date for the latest version from package info.
        
        Based on the retired version's extract_version_date_from_package_info method.
        """
        try:
            # Get version info for the latest version
            version_info = package_info.get_version_info(latest_version)
            if version_info and version_info.get('release_date'):
                return version_info['release_date']
            
            # Fallback: get from package info directly
            return package_info.latest_release_date
            
        except Exception as e:
            self.logger.warning(f"Could not extract latest version release date: {e}")
            return None