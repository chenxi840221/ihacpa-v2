"""
Column I: Requirements Processor

Extracts package dependencies and requirements.
Based on retired version's approach.
"""

import logging
from typing import Dict, Any, List
from ....integrations.pypi_client import PyPIClient


class RequirementsProcessor:
    """Processor for Column I - Requirements/Dependencies"""
    
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
        Process Column I: Requirements
        
        Extracts package dependencies and requirements.
        Following retired version's approach with dependency limiting.
        
        Args:
            package_name: Name of the Python package
            current_version: Current installed version
            
        Returns:
            Dictionary with requirements information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column I (requires) for {package_name}")
            
            # Get package info from PyPI
            package_info = await self.pypi_client.get_package_info(package_name)
            if not package_info:
                return {
                    'value': 'Package not found',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': f'Package {package_name} not found on PyPI'
                }
            
            # Get dependencies following retired version's pattern
            dependencies = package_info.get_dependencies()
            
            if not dependencies:
                return {
                    'value': 'No dependencies',
                    'color': 'new_data',
                    'font': 'new_data',
                    'note': f'{package_name} has no external dependencies'
                }
            
            # Following retired version's logic: limit to first 5 dependencies for readability
            limited_deps = dependencies[:5]
            deps_text = ', '.join(limited_deps)
            
            # Add indication if more dependencies exist
            if len(dependencies) > 5:
                deps_text += f", ... ({len(dependencies)} total)"
                note = f'{len(dependencies)} total dependencies (showing first 5)'
            else:
                note = f'{len(dependencies)} dependencies'
            
            # Color coding based on dependency count
            if len(dependencies) == 0:
                color = 'new_data'
                font = 'new_data'
            elif len(dependencies) <= 3:
                color = 'updated'
                font = 'updated'
            elif len(dependencies) <= 10:
                color = 'version_update'
                font = 'version_update'
            else:
                color = 'security_risk'  # Many dependencies could indicate complexity
                font = 'security_risk'
            
            return {
                'value': deps_text,
                'color': color,
                'font': font,
                'note': note,
                'total_dependencies': len(dependencies),
                'full_dependencies': dependencies
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column I for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error retrieving requirements: {str(e)}'
            }