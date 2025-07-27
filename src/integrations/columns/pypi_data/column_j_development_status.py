"""
Column J: Development Status Processor

Extracts development status from package classifiers.
Based on retired version's _extract_dev_status method.
"""

import logging
from typing import Dict, Any, List
from ....integrations.pypi_client import PyPIClient


class DevelopmentStatusProcessor:
    """Processor for Column J - Development Status"""
    
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
        Process Column J: Development Status
        
        Extracts development status from package classifiers.
        Following retired version's _extract_dev_status logic.
        
        Args:
            package_name: Name of the Python package
            current_version: Current installed version
            
        Returns:
            Dictionary with development status information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column J (development_status) for {package_name}")
            
            # Get package info from PyPI
            package_info = await self.pypi_client.get_package_info(package_name)
            if not package_info:
                return {
                    'value': 'Package not found',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': f'Package {package_name} not found on PyPI'
                }
            
            # Get classifiers
            classifiers = package_info.get_classifiers()
            
            # Extract development status using retired version's logic
            dev_status = self._extract_dev_status(classifiers)
            
            # Enhanced status analysis
            status_analysis = self._analyze_development_status(dev_status)
            
            return {
                'value': dev_status,
                'color': status_analysis['color'],
                'font': status_analysis['font'],
                'note': status_analysis['note'],
                'status_level': status_analysis['level'],
                'classifiers_count': len(classifiers)
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column J for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error retrieving development status: {str(e)}'
            }
    
    def _extract_dev_status(self, classifiers: List[str]) -> str:
        """
        Extract development status from classifiers.
        
        Based on retired version's _extract_dev_status method.
        """
        for classifier in classifiers:
            if 'Development Status' in classifier:
                return classifier.split('::')[-1].strip()
        return "Unknown"
    
    def _analyze_development_status(self, status: str) -> Dict[str, Any]:
        """
        Analyze development status and provide color coding and notes.
        
        Based on PyPI development status classifiers.
        """
        status_lower = status.lower()
        
        # Stable and mature statuses
        if any(keyword in status_lower for keyword in ['5 - production/stable', 'stable', 'production']):
            return {
                'color': 'new_data',
                'font': 'new_data',
                'note': 'Stable production release',
                'level': 'stable'
            }
        
        # Mature status
        elif any(keyword in status_lower for keyword in ['6 - mature', 'mature']):
            return {
                'color': 'new_data',
                'font': 'new_data', 
                'note': 'Mature stable package',
                'level': 'mature'
            }
        
        # Beta/Pre-release statuses
        elif any(keyword in status_lower for keyword in ['4 - beta', 'beta']):
            return {
                'color': 'updated',
                'font': 'updated',
                'note': 'Beta release - may have issues',
                'level': 'beta'
            }
        
        # Alpha/Development statuses
        elif any(keyword in status_lower for keyword in ['3 - alpha', 'alpha', '2 - pre-alpha', 'pre-alpha']):
            return {
                'color': 'version_update',
                'font': 'version_update',
                'note': 'Alpha/development release - use with caution',
                'level': 'alpha'
            }
        
        # Planning stage
        elif any(keyword in status_lower for keyword in ['1 - planning', 'planning']):
            return {
                'color': 'security_risk',
                'font': 'security_risk',
                'note': 'Planning stage - not ready for use',
                'level': 'planning'
            }
        
        # Inactive/unsupported
        elif any(keyword in status_lower for keyword in ['7 - inactive', 'inactive']):
            return {
                'color': 'security_risk',
                'font': 'security_risk',
                'note': 'Inactive project - consider alternatives',
                'level': 'inactive'
            }
        
        # Unknown status
        else:
            return {
                'color': 'version_update',
                'font': 'version_update',
                'note': 'Development status unknown',
                'level': 'unknown'
            }