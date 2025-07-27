"""
Enhanced Version Utilities for IHACPA v2.0

Provides advanced version checking with better version range parsing
and vulnerability version matching.
"""

import re
from typing import List, Tuple, Optional, Dict
from packaging import version
import logging


class EnhancedVersionChecker:
    """Enhanced version checking with vulnerability-specific logic"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_version_range(self, version_range: str) -> Dict[str, any]:
        """
        Parse various version range formats.
        
        Examples:
            "< 1.2.3" -> {"operator": "<", "version": "1.2.3"}
            ">= 2.0.0, < 3.0.0" -> {"min": "2.0.0", "max": "3.0.0"}
            "[1.0.0, 2.0.0)" -> {"min_inclusive": "1.0.0", "max_exclusive": "2.0.0"}
            
        Returns:
            Dictionary with parsed version constraints
        """
        range_info = {
            "raw": version_range,
            "constraints": []
        }
        
        # Handle common patterns
        patterns = [
            # Single constraint: < 1.2.3, >= 2.0.0, etc.
            (r'([<>=!]+)\s*(\d+(?:\.\d+)*(?:\.\*)?)', 'single'),
            # Range: [1.0.0, 2.0.0)
            (r'\[(\d+(?:\.\d+)*)\s*,\s*(\d+(?:\.\d+)*)\)', 'range_inclusive_exclusive'),
            # Range: (1.0.0, 2.0.0]
            (r'\((\d+(?:\.\d+)*)\s*,\s*(\d+(?:\.\d+)*)\]', 'range_exclusive_inclusive'),
            # All versions
            (r'all\s+versions?', 'all'),
            # Specific version
            (r'^(\d+(?:\.\d+)*)$', 'exact')
        ]
        
        for pattern, pattern_type in patterns:
            matches = re.findall(pattern, version_range, re.IGNORECASE)
            if matches:
                if pattern_type == 'single':
                    for match in matches:
                        range_info['constraints'].append({
                            'operator': match[0],
                            'version': match[1]
                        })
                elif pattern_type == 'range_inclusive_exclusive':
                    range_info['min_inclusive'] = matches[0][0]
                    range_info['max_exclusive'] = matches[0][1]
                elif pattern_type == 'range_exclusive_inclusive':
                    range_info['min_exclusive'] = matches[0][0]
                    range_info['max_inclusive'] = matches[0][1]
                elif pattern_type == 'all':
                    range_info['all_versions'] = True
                elif pattern_type == 'exact':
                    range_info['exact_version'] = matches[0]
        
        return range_info
    
    def is_version_affected(self, current_version: str, version_range: str) -> Tuple[bool, str]:
        """
        Check if a version is affected by a vulnerability.
        
        Args:
            current_version: The version to check
            version_range: The affected version range
            
        Returns:
            Tuple of (is_affected, explanation)
        """
        try:
            current = version.parse(current_version)
            range_info = self.parse_version_range(version_range)
            
            # All versions affected
            if range_info.get('all_versions'):
                return True, "All versions are affected"
            
            # Exact version match
            if 'exact_version' in range_info:
                exact = version.parse(range_info['exact_version'])
                is_affected = current == exact
                return is_affected, f"Only version {range_info['exact_version']} is affected"
            
            # Check constraints
            for constraint in range_info.get('constraints', []):
                op = constraint['operator']
                ver = version.parse(constraint['version'])
                
                if op == '<' and current >= ver:
                    return False, f"Current version {current_version} is >= {constraint['version']} (safe)"
                elif op == '<=' and current > ver:
                    return False, f"Current version {current_version} is > {constraint['version']} (safe)"
                elif op == '>' and current <= ver:
                    return False, f"Current version {current_version} is <= {constraint['version']} (safe)"
                elif op == '>=' and current < ver:
                    return False, f"Current version {current_version} is < {constraint['version']} (safe)"
                elif op == '==' and current != ver:
                    return False, f"Current version {current_version} != {constraint['version']} (safe)"
            
            # Range checks
            if 'min_inclusive' in range_info and 'max_exclusive' in range_info:
                min_ver = version.parse(range_info['min_inclusive'])
                max_ver = version.parse(range_info['max_exclusive'])
                if current < min_ver or current >= max_ver:
                    return False, f"Current version {current_version} is outside range [{range_info['min_inclusive']}, {range_info['max_exclusive']})"
                return True, f"Current version {current_version} is in affected range [{range_info['min_inclusive']}, {range_info['max_exclusive']})"
            
            # If we have constraints but didn't return False, assume affected
            if range_info.get('constraints'):
                return True, f"Version {current_version} matches vulnerability criteria"
            
            # No clear version info - needs manual review
            return None, "Version information unclear - manual review recommended"
            
        except Exception as e:
            self.logger.warning(f"Version parsing failed: {e}")
            return None, f"Could not parse version information: {str(e)}"
    
    def get_safe_versions(self, affected_ranges: List[str], latest_version: str) -> Dict[str, any]:
        """
        Determine safe versions based on affected ranges.
        
        Returns:
            Dictionary with safe version recommendations
        """
        recommendations = {
            'latest_is_safe': True,
            'safe_versions': [],
            'update_recommended': False,
            'explanation': ''
        }
        
        try:
            latest = version.parse(latest_version)
            
            for range_str in affected_ranges:
                is_affected, explanation = self.is_version_affected(latest_version, range_str)
                if is_affected:
                    recommendations['latest_is_safe'] = False
                    recommendations['update_recommended'] = True
                    recommendations['explanation'] = f"Latest version {latest_version} is affected: {explanation}"
                    break
            
            if recommendations['latest_is_safe']:
                recommendations['explanation'] = f"Latest version {latest_version} is not affected by known vulnerabilities"
                recommendations['safe_versions'].append(latest_version)
            
        except Exception as e:
            self.logger.error(f"Error determining safe versions: {e}")
            recommendations['explanation'] = "Could not determine safe versions"
        
        return recommendations
    
    def extract_version_from_cpe(self, cpe_string: str) -> Optional[str]:
        """
        Extract version from CPE string.
        
        Example: cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*
        """
        parts = cpe_string.split(':')
        if len(parts) >= 5:
            version_part = parts[4]
            if version_part and version_part != '*' and version_part != '-':
                return version_part
        return None