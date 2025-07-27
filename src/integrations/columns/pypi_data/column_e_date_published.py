"""
Column E: Date Published Processor

Gets the publication date of the CURRENT installed version,
based on the retired version's sophisticated approach.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
from ....integrations.pypi_client import PyPIClient


class DatePublishedProcessor:
    """Processor for Column E - Date Published (Current Version)"""
    
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
        Process Column E: Date Published (Current Version)
        
        Gets the publication date of the currently installed version.
        Based on retired version's extract_version_date_from_package_info logic.
        
        Args:
            package_name: Name of the Python package
            current_version: Current installed version
            
        Returns:
            Dictionary with publication date information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column E (date_published) for {package_name} v{current_version}")
            
            # Get package info from PyPI
            package_info = await self.pypi_client.get_package_info(package_name)
            if not package_info:
                return {
                    'value': 'Package not found',
                    'color': 'not_available',
                    'font': 'not_available',
                    'note': f'Package {package_name} not found on PyPI'
                }
            
            # Extract date for current version using retired version's logic
            current_version_date = await self._extract_version_date_from_package_info(
                package_info, current_version
            )
            
            if not current_version_date:
                # Following retired version's pattern: return "Not Available" if date can't be found
                return {
                    'value': 'Not Available',
                    'color': 'not_available',
                    'font': 'not_available', 
                    'note': f'Publication date not available for {package_name} v{current_version}'
                }
            
            # Format date following retired version's _format_date_for_excel pattern
            formatted_date = self._format_date_for_excel(current_version_date)
            
            # Determine color based on age (following retired version's logic)
            days_old = (datetime.now() - current_version_date.replace(tzinfo=None)).days
            if days_old > 365:  # Over a year old
                color = 'version_update'
                font = 'version_update'
            elif days_old > 180:  # Over 6 months old  
                color = 'updated'
                font = 'updated'
            else:  # Recent
                color = 'new_data'
                font = 'new_data'
            
            return {
                'value': formatted_date,
                'color': color,
                'font': font,
                'note': f'Published {days_old} days ago',
                'raw_date': current_version_date,
                'days_old': days_old
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column E for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error retrieving publication date: {str(e)}'
            }
    
    async def _extract_version_date_from_package_info(self, package_info, version: str) -> Optional[datetime]:
        """
        Extract publication date for specific version from package info.
        
        Based on retired version's extract_version_date_from_package_info method.
        """
        try:
            self.logger.debug(f"Searching for version {version} in package releases")
            
            # Get version info for the specific version
            version_info = package_info.get_version_info(version)
            if version_info and version_info.get('release_date'):
                result = version_info['release_date']
                self.logger.debug(f"Successfully found date for version {version}: {result}")
                return result
            
            self.logger.debug(f"Version {version} not found in releases")
            return None
            
        except Exception as e:
            self.logger.warning(f"Error extracting version date: {e}")
            return None
    
    def _format_date_for_excel(self, date_obj) -> str:
        """
        Format datetime object for Excel display.
        
        Based on retired version's _format_date_for_excel method.
        """
        if not date_obj:
            return "Not Available"
        
        try:
            # Handle different datetime formats
            if hasattr(date_obj, 'strftime'):
                # Convert timezone-aware datetime to naive if needed
                if hasattr(date_obj, 'tzinfo') and date_obj.tzinfo is not None:
                    date_obj = date_obj.replace(tzinfo=None)
                # Remove microseconds for cleaner display
                clean_date = date_obj.replace(microsecond=0)
                return clean_date.strftime('%Y-%m-%d')
            elif isinstance(date_obj, str):
                # Try to parse string dates
                try:
                    parsed_date = datetime.fromisoformat(date_obj.replace('Z', '+00:00'))
                    if hasattr(parsed_date, 'tzinfo') and parsed_date.tzinfo is not None:
                        parsed_date = parsed_date.replace(tzinfo=None)
                    return parsed_date.strftime('%Y-%m-%d')
                except ValueError:
                    return date_obj
            else:
                return str(date_obj)
        except Exception as e:
            self.logger.warning(f"Error formatting date {date_obj}: {e}")
            return "Not Available"