"""
Column F: Latest Version Processor

Gets the latest available version from PyPI and compares with current version.
Enhanced based on retired version's sophisticated approach.
"""

import logging
from typing import Dict, Any
from ....integrations.pypi_client import PyPIClient


class LatestVersionProcessor:
    """Processor for Column F - Latest Version"""
    
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
        Process Column F: Latest Version
        
        Gets latest version from PyPI and compares with current version.
        Based on retired version's approach with enhanced comparison logic.
        
        Args:
            package_name: Name of the Python package
            current_version: Current installed version
            
        Returns:
            Dictionary with latest version information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column F (latest_version) for {package_name} v{current_version}")
            
            # Get package info from PyPI
            package_info = await self.pypi_client.get_package_info(package_name)
            if not package_info:
                return {
                    'value': 'Not available',
                    'color': 'not_available',
                    'font': 'not_available',
                    'note': f'Unable to retrieve version information for {package_name}'
                }
            
            # Get latest version
            latest_version = package_info.get_latest_version()
            if not latest_version:
                return {
                    'value': 'Unknown',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': f'Could not determine latest version for {package_name}'
                }
            
            # Compare versions following retired version's pattern
            comparison_result = await self.pypi_client.compare_versions(package_name, current_version)
            
            if comparison_result:
                is_same = comparison_result.get('is_same', False)
                is_outdated = comparison_result.get('is_outdated', False)
                
                # Determine formatting based on version comparison (retired version's logic)
                if is_same:
                    color = 'new_data'
                    font = 'new_data'
                    note = 'Using latest version'
                elif is_outdated:
                    color = 'version_update'
                    font = 'version_update'
                    note = f'Update available: {current_version} → {latest_version}'
                else:
                    # Using newer version than latest (unusual case)
                    color = 'updated'
                    font = 'updated'
                    note = f'Using newer version than latest: {current_version} > {latest_version}'
            else:
                # Fallback comparison if detailed comparison fails
                if current_version == latest_version:
                    color = 'new_data'
                    font = 'new_data'
                    note = 'Using latest version'
                else:
                    color = 'version_update'
                    font = 'version_update'
                    note = f'Update may be available: {current_version} vs {latest_version}'
            
            return {
                'value': latest_version,
                'color': color,
                'font': font,
                'note': note,
                'is_outdated': comparison_result.get('is_outdated', False) if comparison_result else False,
                'current_version': current_version,
                'pypi_url': f"https://pypi.org/project/{package_name}/{latest_version}/"
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column F for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error retrieving latest version: {str(e)}'
            }