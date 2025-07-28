"""
Version Matcher Agent for IHACPA v2.0

Provides AI-powered version matching and analysis for vulnerability scanning.
"""

from typing import Dict, List, Optional, Any
import logging


class VersionMatcher:
    """AI agent for intelligent version matching and vulnerability analysis"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize version matcher.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
    
    def match_versions(self, package_name: str, current_version: str, 
                      vulnerability_versions: List[str]) -> Dict[str, Any]:
        """
        Match current version against vulnerable versions.
        
        Args:
            package_name: Name of the package
            current_version: Current version string
            vulnerability_versions: List of known vulnerable versions
            
        Returns:
            Matching results dictionary
        """
        try:
            matches = []
            
            for vuln_version in vulnerability_versions:
                if self._version_matches(current_version, vuln_version):
                    matches.append({
                        'vulnerable_version': vuln_version,
                        'match_type': 'exact' if current_version == vuln_version else 'range',
                        'confidence': 0.9 if current_version == vuln_version else 0.7
                    })
            
            return {
                'package_name': package_name,
                'current_version': current_version,
                'matches': matches,
                'is_vulnerable': len(matches) > 0,
                'match_count': len(matches)
            }
            
        except Exception as e:
            self.logger.error(f"Version matching failed for {package_name}: {e}")
            return {
                'package_name': package_name,
                'current_version': current_version,
                'matches': [],
                'is_vulnerable': False,
                'match_count': 0,
                'error': str(e)
            }
    
    def _version_matches(self, current: str, vulnerable: str) -> bool:
        """
        Check if current version matches vulnerable version pattern.
        
        Args:
            current: Current version string
            vulnerable: Vulnerable version pattern
            
        Returns:
            True if versions match, False otherwise
        """
        try:
            # Simple exact match for now
            if current == vulnerable:
                return True
            
            # Check for range patterns like "< 2.0.0"
            if vulnerable.startswith('<'):
                from packaging import version
                vuln_ver = vulnerable.strip('< =')
                return version.parse(current) < version.parse(vuln_ver)
            
            if vulnerable.startswith('<='):
                from packaging import version
                vuln_ver = vulnerable.strip('<= ')
                return version.parse(current) <= version.parse(vuln_ver)
            
            # Check for range patterns like "> 1.0.0"
            if vulnerable.startswith('>'):
                from packaging import version
                vuln_ver = vulnerable.strip('> =')
                return version.parse(current) > version.parse(vuln_ver)
            
            if vulnerable.startswith('>='):
                from packaging import version
                vuln_ver = vulnerable.strip('>= ')
                return version.parse(current) >= version.parse(vuln_ver)
            
            return False
            
        except Exception:
            # Fallback to string comparison
            return current == vulnerable
    
    def analyze_version_impact(self, package_name: str, current_version: str,
                             vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the impact of vulnerabilities on the current version.
        
        Args:
            package_name: Name of the package
            current_version: Current version string
            vulnerability_data: Vulnerability information
            
        Returns:
            Impact analysis results
        """
        try:
            impact_level = 'low'
            
            # Determine impact based on vulnerability data
            severity = vulnerability_data.get('severity', '').upper()
            if severity in ['CRITICAL', 'HIGH']:
                impact_level = 'high'
            elif severity in ['MEDIUM']:
                impact_level = 'medium'
            
            affected_versions = vulnerability_data.get('affected_versions', [])
            is_affected = any(self._version_matches(current_version, v) for v in affected_versions)
            
            return {
                'package_name': package_name,
                'current_version': current_version,
                'impact_level': impact_level,
                'is_affected': is_affected,
                'severity': severity,
                'recommendation': self._generate_recommendation(impact_level, is_affected)
            }
            
        except Exception as e:
            self.logger.error(f"Version impact analysis failed for {package_name}: {e}")
            return {
                'package_name': package_name,
                'current_version': current_version,
                'impact_level': 'unknown',
                'is_affected': False,
                'error': str(e)
            }
    
    def _generate_recommendation(self, impact_level: str, is_affected: bool) -> str:
        """Generate recommendation based on impact analysis"""
        if not is_affected:
            return "SAFE - Current version not affected"
        
        if impact_level == 'high':
            return "CRITICAL - Immediate update required"
        elif impact_level == 'medium':
            return "HIGH - Update recommended"
        else:
            return "MODERATE - Review and consider update"


# For backward compatibility
def match_versions(package_name: str, current_version: str, 
                  vulnerability_versions: List[str]) -> Dict[str, Any]:
    """Standalone version matching function"""
    matcher = VersionMatcher()
    return matcher.match_versions(package_name, current_version, vulnerability_versions)