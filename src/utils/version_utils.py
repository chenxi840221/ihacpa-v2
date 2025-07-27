"""
Version Utilities for IHACPA v2.0

Provides version comparison and parsing utilities for Python packages.
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from packaging import version
from packaging.version import InvalidVersion
import logging


class VersionUtils:
    """Utility class for version comparison and analysis"""
    
    @staticmethod
    def compare_versions(current_version: str, latest_version: str) -> Dict[str, Any]:
        """
        Compare two version strings with enhanced error handling.
        
        Args:
            current_version: Current version string
            latest_version: Latest version string
            
        Returns:
            Dictionary with comparison results
        """
        logger = logging.getLogger(__name__)
        
        # Handle None or non-string inputs
        if not current_version or not latest_version:
            logger.warning(f"Invalid version inputs: current='{current_version}', latest='{latest_version}'")
            return {
                'is_outdated': False,
                'is_same': False,
                'is_newer': False,
                'needs_update': False,
                'current_version': str(current_version) if current_version else 'unknown',
                'latest_version': str(latest_version) if latest_version else 'unknown',
                'error': 'Invalid version inputs'
            }
        
        # Convert to strings if not already
        current_str = str(current_version).strip()
        latest_str = str(latest_version).strip()
        
        if not current_str or not latest_str:
            logger.warning(f"Empty version strings: current='{current_str}', latest='{latest_str}'")
            return {
                'is_outdated': False,
                'is_same': False,
                'is_newer': False,
                'needs_update': False,
                'current_version': current_str or 'unknown',
                'latest_version': latest_str or 'unknown',
                'error': 'Empty version strings'
            }
        
        try:
            current_ver = version.parse(current_str)
            latest_ver = version.parse(latest_str)
            
            is_outdated = current_ver < latest_ver
            is_same = current_ver == latest_ver
            is_newer = current_ver > latest_ver
            
            return {
                'is_outdated': is_outdated,
                'is_same': is_same,
                'is_newer': is_newer,
                'needs_update': is_outdated,
                'current_version': current_str,
                'latest_version': latest_str,
                'version_difference': VersionUtils._calculate_version_difference(current_ver, latest_ver)
            }
            
        except (InvalidVersion, TypeError, AttributeError) as e:
            logger.warning(f"Version comparison failed for '{current_str}' vs '{latest_str}': {e}")
            return {
                'is_outdated': False,
                'is_same': False,
                'is_newer': False,
                'needs_update': False,
                'current_version': current_version,
                'latest_version': latest_version,
                'version_difference': 'unknown',
                'error': f"Invalid version format: {e}"
            }
    
    @staticmethod
    def _calculate_version_difference(current_ver: version.Version, latest_ver: version.Version) -> str:
        """Calculate the type of version difference"""
        if current_ver == latest_ver:
            return 'same'
        
        if current_ver > latest_ver:
            return 'newer'
        
        # For outdated versions, determine the level of difference
        current_parts = current_ver.release
        latest_parts = latest_ver.release
        
        # Pad shorter version to compare
        max_len = max(len(current_parts), len(latest_parts))
        current_padded = list(current_parts) + [0] * (max_len - len(current_parts))
        latest_padded = list(latest_parts) + [0] * (max_len - len(latest_parts))
        
        # Check major version difference
        if len(current_padded) > 0 and len(latest_padded) > 0:
            if current_padded[0] < latest_padded[0]:
                return 'major'
        
        # Check minor version difference
        if len(current_padded) > 1 and len(latest_padded) > 1:
            if (current_padded[0] == latest_padded[0] and 
                current_padded[1] < latest_padded[1]):
                return 'minor'
        
        # Check patch version difference
        if len(current_padded) > 2 and len(latest_padded) > 2:
            if (current_padded[0] == latest_padded[0] and 
                current_padded[1] == latest_padded[1] and
                current_padded[2] < latest_padded[2]):
                return 'patch'
        
        return 'outdated'
    
    @staticmethod
    def parse_version_string(version_str: str) -> Optional[Dict[str, Any]]:
        """
        Parse a version string into components.
        
        Args:
            version_str: Version string to parse
            
        Returns:
            Dictionary with version components or None if invalid
        """
        try:
            parsed = version.parse(version_str)
            
            return {
                'raw': version_str,
                'normalized': str(parsed),
                'major': parsed.major if hasattr(parsed, 'major') else None,
                'minor': parsed.minor if hasattr(parsed, 'minor') else None,
                'micro': parsed.micro if hasattr(parsed, 'micro') else None,
                'release': parsed.release,
                'pre': parsed.pre,
                'post': parsed.post,
                'dev': parsed.dev,
                'local': parsed.local,
                'is_prerelease': parsed.is_prerelease,
                'is_postrelease': parsed.is_postrelease,
                'is_devrelease': parsed.is_devrelease,
                'base_version': parsed.base_version,
                'public': parsed.public
            }
            
        except InvalidVersion:
            return None
    
    @staticmethod
    def get_latest_stable_version(versions: List[str]) -> Optional[str]:
        """
        Get the latest stable version from a list of versions.
        
        Args:
            versions: List of version strings
            
        Returns:
            Latest stable version string or None
        """
        if not versions:
            return None
        
        stable_versions = []
        
        for ver_str in versions:
            try:
                parsed = version.parse(ver_str)
                # Only include stable versions (no pre/dev/post releases)
                if not (parsed.is_prerelease or parsed.is_devrelease):
                    stable_versions.append((parsed, ver_str))
            except InvalidVersion:
                continue
        
        if not stable_versions:
            return None
        
        # Sort by version and return the latest
        stable_versions.sort(key=lambda x: x[0], reverse=True)
        return stable_versions[0][1]
    
    @staticmethod
    def filter_versions_by_pattern(versions: List[str], pattern: str) -> List[str]:
        """
        Filter versions by a regex pattern.
        
        Args:
            versions: List of version strings
            pattern: Regex pattern to match
            
        Returns:
            List of matching version strings
        """
        try:
            regex = re.compile(pattern)
            return [ver for ver in versions if regex.match(ver)]
        except re.error:
            logging.warning(f"Invalid regex pattern: {pattern}")
            return versions
    
    @staticmethod
    def get_security_relevant_versions(current_version: str, all_versions: List[str]) -> Dict[str, List[str]]:
        """
        Categorize versions for security analysis.
        
        Args:
            current_version: Current version being analyzed
            all_versions: All available versions
            
        Returns:
            Dictionary categorizing versions by security relevance
        """
        try:
            current_ver = version.parse(current_version)
        except InvalidVersion:
            return {
                'newer_versions': [],
                'patch_versions': [],
                'minor_versions': [],
                'major_versions': [],
                'prereleases': []
            }
        
        newer_versions = []
        patch_versions = []
        minor_versions = []
        major_versions = []
        prereleases = []
        
        for ver_str in all_versions:
            try:
                ver = version.parse(ver_str)
                
                if ver <= current_ver:
                    continue
                
                if ver.is_prerelease or ver.is_devrelease:
                    prereleases.append(ver_str)
                    continue
                
                newer_versions.append(ver_str)
                
                # Categorize by version type
                if (hasattr(ver, 'major') and hasattr(current_ver, 'major') and
                    ver.major == current_ver.major):
                    if (hasattr(ver, 'minor') and hasattr(current_ver, 'minor') and
                        ver.minor == current_ver.minor):
                        patch_versions.append(ver_str)
                    else:
                        minor_versions.append(ver_str)
                else:
                    major_versions.append(ver_str)
                    
            except InvalidVersion:
                continue
        
        return {
            'newer_versions': sorted(newer_versions, key=lambda x: version.parse(x), reverse=True),
            'patch_versions': sorted(patch_versions, key=lambda x: version.parse(x), reverse=True),
            'minor_versions': sorted(minor_versions, key=lambda x: version.parse(x), reverse=True),
            'major_versions': sorted(major_versions, key=lambda x: version.parse(x), reverse=True),
            'prereleases': sorted(prereleases, key=lambda x: version.parse(x), reverse=True)
        }
    
    @staticmethod
    def is_version_in_range(version_str: str, min_version: Optional[str] = None, 
                           max_version: Optional[str] = None) -> bool:
        """
        Check if a version is within a specified range.
        
        Args:
            version_str: Version to check
            min_version: Minimum version (inclusive)
            max_version: Maximum version (inclusive)
            
        Returns:
            True if version is in range, False otherwise
        """
        try:
            ver = version.parse(version_str)
            
            if min_version:
                min_ver = version.parse(min_version)
                if ver < min_ver:
                    return False
            
            if max_version:
                max_ver = version.parse(max_version)
                if ver > max_ver:
                    return False
            
            return True
            
        except InvalidVersion:
            return False
    
    @staticmethod
    def calculate_version_age_score(version_str: str, all_versions: List[str]) -> float:
        """
        Calculate a score representing how outdated a version is.
        
        Args:
            version_str: Version to analyze
            all_versions: All available versions for comparison
            
        Returns:
            Score from 0.0 (latest) to 1.0 (very outdated)
        """
        try:
            current_ver = version.parse(version_str)
            parsed_versions = []
            
            for v in all_versions:
                try:
                    parsed = version.parse(v)
                    if not (parsed.is_prerelease or parsed.is_devrelease):
                        parsed_versions.append(parsed)
                except InvalidVersion:
                    continue
            
            if not parsed_versions:
                return 0.0
            
            # Sort versions
            parsed_versions.sort()
            
            # Find position of current version
            try:
                current_index = parsed_versions.index(current_ver)
                # Calculate score: 0 for latest, 1 for oldest
                score = 1.0 - (current_index + 1) / len(parsed_versions)
                return max(0.0, min(1.0, score))
            except ValueError:
                # Version not found in list, assume it's very new
                return 0.0
            
        except InvalidVersion:
            return 0.5  # Unknown versions get medium score
    
    @staticmethod
    def get_version_recommendations(current_version: str, all_versions: List[str]) -> Dict[str, Any]:
        """
        Get version upgrade recommendations.
        
        Args:
            current_version: Current version
            all_versions: All available versions
            
        Returns:
            Dictionary with upgrade recommendations
        """
        try:
            current_ver = version.parse(current_version)
        except InvalidVersion:
            return {
                'recommended_version': None,
                'urgency': 'unknown',
                'reason': 'Invalid current version format'
            }
        
        # Get categorized versions
        categorized = VersionUtils.get_security_relevant_versions(current_version, all_versions)
        
        # Calculate age score
        age_score = VersionUtils.calculate_version_age_score(current_version, all_versions)
        
        # Determine recommendation
        if categorized['patch_versions']:
            recommended = categorized['patch_versions'][0]
            urgency = 'high' if age_score > 0.7 else 'medium'
            reason = f"Patch updates available ({len(categorized['patch_versions'])} versions)"
        elif categorized['minor_versions']:
            recommended = categorized['minor_versions'][0]
            urgency = 'medium' if age_score > 0.5 else 'low'
            reason = f"Minor updates available ({len(categorized['minor_versions'])} versions)"
        elif categorized['major_versions']:
            recommended = categorized['major_versions'][0]
            urgency = 'low'  # Major updates require more consideration
            reason = f"Major updates available ({len(categorized['major_versions'])} versions)"
        else:
            recommended = None
            urgency = 'none'
            reason = "No newer stable versions available"
        
        return {
            'recommended_version': recommended,
            'urgency': urgency,
            'reason': reason,
            'age_score': age_score,
            'available_updates': {
                'patch': len(categorized['patch_versions']),
                'minor': len(categorized['minor_versions']),
                'major': len(categorized['major_versions'])
            }
        }