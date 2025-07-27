"""
Enhanced Column Processors for IHACPA v2.0

Implements specialized functions for columns E, F, K, L, W, and M
as requested to enhance the Excel processing capabilities.
"""

import asyncio
import aiohttp
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urljoin, quote

from .pypi_client import PyPIClient, PyPIPackageInfo
from ..core.ai_analyzer import AIAnalyzer
from ..core.browser_automation import BrowserAutomation
from ..core.sandbox_manager import SandboxManager
from ..utils.enhanced_version_utils import EnhancedVersionChecker
from ..utils.vulnerability_filter import VulnerabilityFilter
from ..config.color_config import ExcelColors, ColorCodingRules


class ColumnProcessors:
    """Enhanced column processing functions for IHACPA Excel integration"""
    
    def __init__(self, config: Union[Dict[str, Any], Any], ai_analyzer: Optional[AIAnalyzer] = None, sandbox_manager=None):
        """
        Initialize column processors.
        
        Args:
            config: Application configuration (dict or config object)
            ai_analyzer: Optional AI analyzer for enhanced processing
            sandbox_manager: Optional sandbox manager for vulnerability scanning
        """
        self.config = config
        self.ai_analyzer = ai_analyzer
        self.sandbox_manager = sandbox_manager
        
        # Handle both dict and config object
        if hasattr(config, 'processing'):
            timeout = getattr(config.processing, 'request_timeout', 30)
            max_retries = getattr(config.processing, 'retry_attempts', 3)
        else:
            timeout = config.get('processing', {}).get('request_timeout', 30)
            max_retries = config.get('processing', {}).get('retry_attempts', 3)
        
        self.pypi_client = PyPIClient(
            timeout=timeout,
            max_retries=max_retries
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize enhanced utilities
        self.version_checker = EnhancedVersionChecker()
        self.vulnerability_filter = VulnerabilityFilter()
        
        # Browser automation for GitHub security scanning
        self.browser = None
        browser_enabled = False
        browser_config = {}
        
        if hasattr(config, 'browser'):
            browser_enabled = getattr(config.browser, 'enabled', False)
            browser_config = config.browser.__dict__ if hasattr(config.browser, '__dict__') else {}
        else:
            browser_enabled = config.get('browser', {}).get('enabled', False)
            browser_config = config.get('browser', {})
        
        if browser_enabled:
            try:
                self.browser = BrowserAutomation(browser_config)
            except Exception as e:
                self.logger.warning(f"Browser automation not available: {e}")
    
    async def process_column_E_date_published(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Column E: Extract publication date from PyPI for the current version
        
        Args:
            package_name: Name of the Python package
            current_version: Current version being analyzed
            
        Returns:
            Dictionary with publication date information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column E (date_published) for {package_name} v{current_version}")
            
            package_info = await self.pypi_client.get_package_info(package_name)
            if not package_info:
                return {
                    'value': 'Package not found',
                    'color': 'critical',
                    'font': 'critical',
                    'note': f'Package {package_name} not found on PyPI'
                }
            
            # Get version-specific information
            version_info = package_info.get_version_info(current_version)
            if not version_info or not version_info.get('release_date'):
                return {
                    'value': 'Date not available',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': f'Release date not available for {package_name} v{current_version}'
                }
            
            release_date = version_info['release_date']
            formatted_date = release_date.strftime('%Y-%m-%d')
            
            # Determine color based on age
            days_old = (datetime.now() - release_date.replace(tzinfo=None)).days
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
                'raw_date': release_date,
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
    
    async def process_column_F_latest_version(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Column F: Get latest version from PyPI and compare with current
        
        Args:
            package_name: Name of the Python package
            current_version: Current version being analyzed
            
        Returns:
            Dictionary with latest version information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column F (latest_version) for {package_name} v{current_version}")
            
            comparison_result = await self.pypi_client.compare_versions(package_name, current_version)
            if not comparison_result:
                return {
                    'value': 'Not available',
                    'color': 'critical',
                    'font': 'critical',
                    'note': f'Unable to retrieve version information for {package_name}'
                }
            
            latest_version = comparison_result['latest_version']
            is_outdated = comparison_result['is_outdated']
            is_same = comparison_result['is_same']
            
            # Determine formatting based on version comparison
            if is_same:
                color = 'new_data'
                font = 'new_data'
                note = 'Using latest version'
            elif is_outdated:
                color = 'version_update'
                font = 'version_update'
                note = f'Update available: {current_version} → {latest_version}'
            else:
                color = 'ai_enhanced'
                font = 'ai_enhanced'
                note = f'Using newer version than latest: {current_version} > {latest_version}'
            
            return {
                'value': latest_version,
                'color': color,
                'font': font,
                'note': note,
                'is_outdated': is_outdated,
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
    
    async def process_column_H_latest_release_date(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Column H: Get latest version release date from PyPI
        
        Args:
            package_name: Name of the Python package
            current_version: Current version string
            
        Returns:
            Dictionary with latest release date information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column H (latest_release_date) for {package_name}")
            
            # Get package info from PyPI - compare_versions already has the release date
            comparison_result = await self.pypi_client.compare_versions(package_name, current_version)
            if not comparison_result:
                return {
                    'value': 'Not available',
                    'color': 'critical',
                    'font': 'critical',
                    'note': f'Unable to retrieve version information for {package_name}'
                }
            
            # Get the latest release date directly from comparison result
            latest_release_date = comparison_result.get('latest_release_date')
            if not latest_release_date:
                return {
                    'value': 'Not available',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': f'Release date not available for {package_name}'
                }
            
            # Format the date to match Excel format (YYYY-MM-DD HH:MM:SS)
            formatted_date = latest_release_date.strftime('%Y-%m-%d %H:%M:%S')
            
            # Determine color based on how recent the release is
            days_old = (datetime.now() - latest_release_date.replace(tzinfo=None)).days
            
            if days_old <= 30:
                color = 'new_data'  # Very recent
                font = 'new_data'
            elif days_old <= 365:
                color = 'updated'  # Recent
                font = 'updated'
            else:
                color = 'version_update'  # Older
                font = 'version_update'
            
            return {
                'value': formatted_date,
                'color': color,
                'font': font,
                'raw_date': latest_release_date,
                'days_old': days_old,
                'latest_version': comparison_result['latest_version'],
                'note': f'Latest version {comparison_result["latest_version"]} released {days_old} days ago'
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column H for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error retrieving latest release date: {str(e)}'
            }
    
    async def process_column_K_github_url(self, package_name: str) -> Dict[str, Any]:
        """
        Column K: Extract GitHub repository URL from PyPI metadata
        
        Args:
            package_name: Name of the Python package
            
        Returns:
            Dictionary with GitHub URL information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column K (github_url) for {package_name}")
            
            package_info = await self.pypi_client.get_package_info(package_name)
            if not package_info:
                return {
                    'value': 'Package not found',
                    'color': 'critical',
                    'font': 'critical',
                    'note': f'Package {package_name} not found on PyPI'
                }
            
            github_url = package_info.github_url
            if not github_url:
                # Try to find GitHub URL in other fields
                github_url = self._extract_github_from_metadata(package_info)
            
            if github_url:
                # Clean and validate GitHub URL
                clean_url = self._clean_github_url(github_url)
                return {
                    'value': clean_url,
                    'color': 'new_data',
                    'font': 'new_data',
                    'note': 'GitHub repository found',
                    'hyperlink': clean_url
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
    
    async def process_column_L_github_security_url(self, package_name: str, github_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Column L: Generate GitHub Security Advisories URL
        
        Args:
            package_name: Name of the Python package
            github_url: Optional GitHub URL (if not provided, will be extracted)
            
        Returns:
            Dictionary with GitHub security URL information and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column L (github_security_url) for {package_name}")
            
            if not github_url:
                # Get GitHub URL from Column K processing
                github_result = await self.process_column_K_github_url(package_name)
                github_url = github_result.get('hyperlink') or github_result.get('value')
            
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
                'color': 'ai_enhanced',
                'font': 'ai_enhanced',
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
    
    async def process_column_W_recommendation(self, package_name: str, vulnerability_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Column W: Generate IHACPA recommendations based on scan results
        
        Args:
            package_name: Name of the Python package
            vulnerability_results: Results from vulnerability scans (columns P, R, T, etc.)
            
        Returns:
            Dictionary with recommendation and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column W (recommendation) for {package_name}")
            
            # Analyze vulnerability results
            risk_score = self._calculate_risk_score(vulnerability_results)
            critical_vulns = vulnerability_results.get('critical_vulnerabilities', 0)
            high_vulns = vulnerability_results.get('high_risk_vulnerabilities', 0)
            total_vulns = vulnerability_results.get('total_vulnerabilities', 0)
            
            # Generate recommendation based on risk assessment
            if critical_vulns > 0:
                recommendation = "CRITICAL - IMMEDIATE ACTION REQUIRED"
                color = 'critical'
                font = 'critical'
                note = f"Found {critical_vulns} critical vulnerabilities"
            elif high_vulns > 2:
                recommendation = "HIGH RISK - UPDATE REQUIRED"
                color = 'high_risk'
                font = 'high_risk'
                note = f"Found {high_vulns} high-risk vulnerabilities"
            elif total_vulns > 5:
                recommendation = "MODERATE RISK - REVIEW AND UPDATE"
                color = 'security_risk'
                font = 'security_risk'
                note = f"Found {total_vulns} vulnerabilities"
            elif total_vulns > 0:
                recommendation = "LOW RISK - MONITOR"
                color = 'version_update'
                font = 'version_update'
                note = f"Found {total_vulns} low-risk vulnerabilities"
            else:
                recommendation = "PROCEED"
                color = 'new_data'
                font = 'new_data'
                note = "No vulnerabilities found"
            
            # Add AI enhancement if available
            if self.ai_analyzer:
                try:
                    ai_recommendation = await self.ai_analyzer.generate_recommendation(
                        package_name, vulnerability_results
                    )
                    if ai_recommendation:
                        recommendation = f"AI: {ai_recommendation}"
                        color = 'ai_enhanced'
                        font = 'ai_enhanced'
                        note += " (AI Enhanced)"
                except Exception as e:
                    self.logger.warning(f"AI recommendation failed for {package_name}: {e}")
            
            return {
                'value': recommendation,
                'color': color,
                'font': font,
                'note': note,
                'risk_score': risk_score,
                'critical_count': critical_vulns,
                'high_risk_count': high_vulns,
                'total_vulnerabilities': total_vulns
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column W for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error generating recommendation: {str(e)}'
            }
    
    async def process_column_M_github_security_result(self, package_name: str, current_version: str, 
                                                     github_security_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Column M: Analyze GitHub Security Advisories with sandbox/browser/AI integration
        Similar to columns P, R, T but for GitHub Security
        
        Args:
            package_name: Name of the Python package
            current_version: Current version being analyzed
            github_security_url: Optional security URL (if not provided, will be generated)
            
        Returns:
            Dictionary with GitHub security analysis results and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column M (github_security_result) for {package_name} v{current_version}")
            
            if not github_security_url:
                # Get GitHub security URL from Column L processing
                url_result = await self.process_column_L_github_security_url(package_name)
                github_security_url = url_result.get('hyperlink') or url_result.get('value')
            
            if not github_security_url or github_security_url in ['No GitHub repo', 'Invalid GitHub URL', 'Error']:
                return {
                    'value': 'No GitHub security data',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': 'Cannot analyze GitHub security without repository URL'
                }
            
            # Multi-strategy approach: Browser + AI + Sandbox
            security_results = await self._analyze_github_security_multi_strategy(
                package_name, current_version, github_security_url
            )
            
            if not security_results:
                return {
                    'value': 'Analysis failed',
                    'color': 'critical',
                    'font': 'critical',
                    'note': 'GitHub security analysis could not be completed'
                }
            
            vulnerabilities_found = security_results.get('vulnerabilities_found', False)
            vulnerability_count = security_results.get('vulnerability_count', 0)
            
            if vulnerabilities_found:
                severity = security_results.get('max_severity', 'UNKNOWN').upper()
                if severity in ['CRITICAL', 'HIGH']:
                    color = 'critical'
                    font = 'critical'
                    value = f"GITHUB: {vulnerability_count} {severity.lower()} vulnerabilities found"
                else:
                    color = 'security_risk'
                    font = 'security_risk'
                    value = f"GITHUB: {vulnerability_count} vulnerabilities found"
            else:
                color = 'new_data'
                font = 'new_data'
                value = "GITHUB: No vulnerabilities found"
            
            # Add AI enhancement marker if used
            if security_results.get('ai_enhanced'):
                value += " (AI Enhanced)"
                color = 'ai_enhanced'
                font = 'ai_enhanced'
            
            return {
                'value': value,
                'color': color,
                'font': font,
                'note': security_results.get('summary', 'GitHub security analysis completed'),
                'vulnerabilities_found': vulnerabilities_found,
                'vulnerability_count': vulnerability_count,
                'max_severity': security_results.get('max_severity'),
                'analysis_method': security_results.get('analysis_method'),
                'github_url': github_security_url
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column M for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error analyzing GitHub security: {str(e)}'
            }
    
    def _extract_github_from_metadata(self, package_info: PyPIPackageInfo) -> Optional[str]:
        """Extract GitHub URL from various package metadata fields"""
        # Check project URLs
        for key, url in package_info.project_urls.items():
            if url and 'github.com' in str(url).lower():
                return str(url)
        
        # Check description for GitHub links
        description = package_info.description or ''
        github_match = re.search(r'https?://github\.com/[^\s\)]+', description)
        if github_match:
            return github_match.group()
        
        # Check homepage
        if package_info.home_page and 'github.com' in package_info.home_page.lower():
            return package_info.home_page
        
        return None
    
    def _clean_github_url(self, url: str) -> str:
        """Clean and standardize GitHub URL"""
        # Remove trailing slashes and .git
        url = url.rstrip('/').rstrip('.git')
        
        # Ensure https
        if url.startswith('http://'):
            url = url.replace('http://', 'https://')
        elif not url.startswith('https://'):
            url = f"https://{url}"
        
        return url
    
    def _calculate_risk_score(self, vulnerability_results: Dict[str, Any]) -> float:
        """Calculate risk score from vulnerability results"""
        critical = vulnerability_results.get('critical_vulnerabilities', 0)
        high = vulnerability_results.get('high_risk_vulnerabilities', 0)
        medium = vulnerability_results.get('medium_risk_vulnerabilities', 0)
        low = vulnerability_results.get('low_risk_vulnerabilities', 0)
        
        # Weighted scoring
        score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
        return min(score / 100.0, 1.0)  # Normalize to 0-1
    
    async def _analyze_github_security_multi_strategy(self, package_name: str, current_version: str, 
                                                     security_url: str) -> Optional[Dict[str, Any]]:
        """
        Multi-strategy GitHub security analysis using browser automation, AI, and sandbox
        Similar to vulnerability scanning approach in columns P, R, T
        """
        analysis_results = []
        
        # Strategy 1: AI Analysis (if available)
        if self.ai_analyzer:
            try:
                ai_result = await self.ai_analyzer.analyze_github_security(
                    package_name, current_version, security_url
                )
                if ai_result:
                    analysis_results.append({
                        'method': 'ai',
                        'result': ai_result,
                        'confidence': 0.8
                    })
            except Exception as e:
                self.logger.warning(f"AI GitHub security analysis failed: {e}")
        
        # Strategy 2: Browser Automation (if available)
        if self.browser:
            try:
                browser_result = await self.browser.analyze_github_security(
                    security_url, package_name, current_version
                )
                if browser_result:
                    analysis_results.append({
                        'method': 'browser',
                        'result': browser_result,
                        'confidence': 0.9
                    })
            except Exception as e:
                self.logger.warning(f"Browser GitHub security analysis failed: {e}")
        
        # Strategy 3: API-based analysis (fallback)
        try:
            api_result = await self._github_api_security_check(package_name, current_version, security_url)
            if api_result:
                analysis_results.append({
                    'method': 'api',
                    'result': api_result,
                    'confidence': 0.6
                })
        except Exception as e:
            self.logger.warning(f"GitHub API security analysis failed: {e}")
        
        # Combine and return best result
        if analysis_results:
            # Sort by confidence and take the best result
            best_result = max(analysis_results, key=lambda x: x['confidence'])
            result = best_result['result']
            result['analysis_method'] = best_result['method']
            result['ai_enhanced'] = best_result['method'] in ['ai', 'browser']
            return result
        
        return None
    
    async def _github_api_security_check(self, package_name: str, current_version: str, 
                                       security_url: str) -> Optional[Dict[str, Any]]:
        """Fallback GitHub API-based security check"""
        try:
            # Extract owner/repo from URL
            repo_match = re.search(r'github\.com/([^/]+)/([^/]+)', security_url)
            if not repo_match:
                return None
            
            owner, repo = repo_match.groups()
            repo = repo.rstrip('.git')
            
            # Use GitHub API to check for security advisories
            api_url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url) as response:
                    if response.status == 200:
                        advisories = await response.json()
                        
                        return {
                            'vulnerabilities_found': len(advisories) > 0,
                            'vulnerability_count': len(advisories),
                            'max_severity': 'HIGH' if advisories else 'NONE',
                            'summary': f"Found {len(advisories)} GitHub security advisories" if advisories else "No GitHub security advisories found"
                        }
                    else:
                        return {
                            'vulnerabilities_found': False,
                            'vulnerability_count': 0,
                            'max_severity': 'UNKNOWN',
                            'summary': 'GitHub security check completed (manual review recommended)'
                        }
        
        except Exception as e:
            self.logger.error(f"GitHub API security check failed: {e}")
            return None
    
    async def process_column_P_nvd_result(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Column P: NIST NVD Lookup Result
        
        Args:
            package_name: Name of the Python package
            current_version: Current version string
            
        Returns:
            Dictionary with NVD scan results and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column P (nvd_result) for {package_name}")
            
            if not self.sandbox_manager:
                return {
                    'value': 'Sandbox unavailable',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': 'Sandbox manager not available for NVD scanning'
                }
            
            # Get NVD sandbox and perform scan
            nvd_sandbox = await self.sandbox_manager.get_sandbox('nvd')
            if not nvd_sandbox:
                return {
                    'value': 'NVD unavailable',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': 'NVD sandbox not available'
                }
            
            # Perform NVD scan with error handling
            try:
                scan_result = await nvd_sandbox.scan_package(package_name, current_version)
            except Exception as scan_error:
                # Handle API errors gracefully
                error_msg = str(scan_error).lower()
                if 'status 404' in error_msg or 'not found' in error_msg:
                    return {
                        'value': 'Package not in NVD',
                        'color': 'new_data',
                        'font': 'new_data',
                        'vulnerability_count': 0,
                        'note': f'Package {package_name} not found in NVD database'
                    }
                elif 'status 400' in error_msg or 'api' in error_msg:
                    return {
                        'value': 'NVD API error',
                        'color': 'version_update',
                        'font': 'version_update',
                        'vulnerability_count': 0,
                        'note': f'NVD API temporarily unavailable'
                    }
                else:
                    raise scan_error
            
            if not scan_result or not scan_result.vulnerabilities:
                return {
                    'value': 'No vulnerabilities',
                    'color': 'new_data',
                    'font': 'new_data',
                    'vulnerability_count': 0,
                    'note': f'No NVD vulnerabilities found for {package_name} v{current_version}'
                }
            
            # Check if current version is affected
            vuln_count = len(scan_result.vulnerabilities)
            affected_count = 0
            manual_review_count = 0
            false_positive_count = 0
            
            for vuln in scan_result.vulnerabilities:
                # Check if vulnerability has filter metadata
                if hasattr(vuln, 'filter_metadata'):
                    if not vuln.filter_metadata.get('is_python_related'):
                        false_positive_count += 1
                        continue
                    if vuln.filter_metadata.get('requires_manual_review'):
                        manual_review_count += 1
                
                # Check if current version is affected
                if vuln.affected_versions:
                    for ver_range in vuln.affected_versions:
                        is_affected, _ = self.version_checker.is_version_affected(current_version, ver_range)
                        if is_affected:
                            affected_count += 1
                            break
                else:
                    # No version info - needs manual review
                    manual_review_count += 1
            
            # Determine status and color
            if false_positive_count == vuln_count:
                return {
                    'value': 'None found',
                    'color': ExcelColors.COLORS['safe_alt'],
                    'font': 'safe',
                    'vulnerability_count': 0,
                    'note': f'All {vuln_count} CVEs filtered as non-Python'
                }
            
            actual_vulns = vuln_count - false_positive_count
            
            if manual_review_count > 0:
                return {
                    'value': f'Manual review required - {actual_vulns} CVEs found, {manual_review_count} require manual version checking for v{current_version}',
                    'color': ExcelColors.COLORS['manual_review'],
                    'font': 'manual_review',
                    'vulnerability_count': actual_vulns,
                    'manual_review_count': manual_review_count,
                    'note': 'Manual review needed to determine version impact'
                }
            
            if affected_count > 0:
                high_severity = sum(1 for v in scan_result.vulnerabilities 
                                  if v.severity in ['CRITICAL', 'HIGH'] and 
                                  not (hasattr(v, 'filter_metadata') and not v.filter_metadata.get('is_python_related')))
                
                return {
                    'value': f'VULNERABLE - {affected_count} CVEs affect v{current_version}' + 
                             (f' (Highest: {high_severity} HIGH/CRITICAL)' if high_severity > 0 else ''),
                    'color': ExcelColors.COLORS['vulnerable'],
                    'font': 'vulnerable',
                    'vulnerability_count': affected_count,
                    'high_severity_count': high_severity,
                    'note': f'Current version {current_version} is affected by {affected_count} vulnerabilities'
                }
            else:
                return {
                    'value': f'SAFE - {actual_vulns} CVEs found but v{current_version} not affected',
                    'color': ExcelColors.COLORS['safe'],
                    'font': 'safe',
                    'vulnerability_count': 0,
                    'total_cves': actual_vulns,
                    'note': f'Vulnerabilities exist but do not affect version {current_version}'
                }
            
        except Exception as e:
            self.logger.error(f"Error processing Column P for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error during NVD scan: {str(e)}'
            }
    
    async def process_column_R_mitre_result(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Column R: MITRE CVE Lookup Result
        
        Args:
            package_name: Name of the Python package
            current_version: Current version string
            
        Returns:
            Dictionary with MITRE scan results and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column R (mitre_result) for {package_name}")
            
            if not self.sandbox_manager:
                return {
                    'value': 'Sandbox unavailable',
                    'color': 'version_update',
                    'font': 'version_update'
                }
            
            mitre_sandbox = await self.sandbox_manager.get_sandbox('mitre')
            if not mitre_sandbox:
                return {
                    'value': 'MITRE unavailable',
                    'color': 'version_update',
                    'font': 'version_update'
                }
            
            # Perform MITRE scan with error handling
            try:
                scan_result = await mitre_sandbox.scan_package(package_name, current_version)
            except Exception as scan_error:
                # Handle API errors gracefully
                error_msg = str(scan_error).lower()
                if 'status 400' in error_msg or 'status 404' in error_msg:
                    return {
                        'value': 'MITRE API error',
                        'color': 'version_update',
                        'font': 'version_update',
                        'vulnerability_count': 0,
                        'note': f'MITRE API temporarily unavailable'
                    }
                else:
                    raise scan_error
            
            if not scan_result or not scan_result.vulnerabilities:
                return {
                    'value': 'No CVEs',
                    'color': 'new_data',
                    'font': 'new_data',
                    'vulnerability_count': 0
                }
            
            vuln_count = len(scan_result.vulnerabilities)
            high_severity = sum(1 for v in scan_result.vulnerabilities if v.severity in ['CRITICAL', 'HIGH'])
            
            if high_severity > 0:
                return {
                    'value': f'MITRE: {vuln_count} CVEs ({high_severity} high/critical)',
                    'color': 'security_risk',
                    'font': 'security_risk',
                    'vulnerability_count': vuln_count
                }
            else:
                return {
                    'value': f'MITRE: {vuln_count} CVEs (low/medium)',
                    'color': 'version_update',
                    'font': 'version_update',
                    'vulnerability_count': vuln_count
                }
            
        except Exception as e:
            self.logger.error(f"Error processing Column R for {package_name}: {e}")
            return {'value': 'Error', 'color': 'critical', 'font': 'critical'}
    
    async def process_column_T_snyk_result(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Column T: SNYK Vulnerability Lookup Result
        
        Args:
            package_name: Name of the Python package
            current_version: Current version string
            
        Returns:
            Dictionary with SNYK scan results and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column T (snyk_result) for {package_name}")
            
            if not self.sandbox_manager:
                return {
                    'value': 'Sandbox unavailable',
                    'color': 'version_update',
                    'font': 'version_update'
                }
            
            snyk_sandbox = await self.sandbox_manager.get_sandbox('snyk')
            if not snyk_sandbox:
                return {
                    'value': 'SNYK unavailable',
                    'color': 'version_update',
                    'font': 'version_update'
                }
            
            # Perform SNYK scan with error handling
            try:
                scan_result = await snyk_sandbox.scan_package(package_name, current_version)
            except Exception as scan_error:
                # Handle API and browser errors gracefully
                error_msg = str(scan_error).lower()
                if 'playwright' in error_msg or 'browser' in error_msg:
                    return {
                        'value': 'Browser unavailable',
                        'color': 'version_update',
                        'font': 'version_update',
                        'vulnerability_count': 0,
                        'note': f'Browser dependencies missing for SNYK scan'
                    }
                elif 'api' in error_msg or 'status' in error_msg:
                    return {
                        'value': 'SNYK API error',
                        'color': 'version_update',
                        'font': 'version_update',
                        'vulnerability_count': 0,
                        'note': f'SNYK API temporarily unavailable'
                    }
                else:
                    raise scan_error
            
            if not scan_result or not scan_result.vulnerabilities:
                return {
                    'value': 'No vulnerabilities',
                    'color': 'new_data',
                    'font': 'new_data',
                    'vulnerability_count': 0
                }
            
            vuln_count = len(scan_result.vulnerabilities)
            high_severity = sum(1 for v in scan_result.vulnerabilities if v.severity in ['CRITICAL', 'HIGH'])
            
            if high_severity > 0:
                return {
                    'value': f'SNYK: {vuln_count} vulnerabilities ({high_severity} high/critical)',
                    'color': 'security_risk',
                    'font': 'security_risk',
                    'vulnerability_count': vuln_count
                }
            else:
                return {
                    'value': f'SNYK: {vuln_count} vulnerabilities (low/medium)',
                    'color': 'version_update',
                    'font': 'version_update',
                    'vulnerability_count': vuln_count
                }
            
        except Exception as e:
            self.logger.error(f"Error processing Column T for {package_name}: {e}")
            return {'value': 'Error', 'color': 'critical', 'font': 'critical'}
    
    async def process_column_V_exploit_result(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Column V: Exploit Database Lookup Result
        
        Args:
            package_name: Name of the Python package
            current_version: Current version string
            
        Returns:
            Dictionary with ExploitDB scan results and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column V (exploit_result) for {package_name}")
            
            if not self.sandbox_manager:
                return {
                    'value': 'Sandbox unavailable',
                    'color': 'version_update',
                    'font': 'version_update'
                }
            
            exploit_sandbox = await self.sandbox_manager.get_sandbox('exploitdb')
            if not exploit_sandbox:
                return {
                    'value': 'ExploitDB unavailable',
                    'color': 'version_update',
                    'font': 'version_update'
                }
            
            # Perform ExploitDB scan with error handling
            try:
                scan_result = await exploit_sandbox.scan_package(package_name, current_version)
            except Exception as scan_error:
                # Handle API and browser errors gracefully
                error_msg = str(scan_error).lower()
                if 'playwright' in error_msg or 'browser' in error_msg:
                    return {
                        'value': 'Browser unavailable',
                        'color': 'version_update',
                        'font': 'version_update',
                        'vulnerability_count': 0,
                        'note': f'Browser dependencies missing for ExploitDB scan'
                    }
                elif 'api' in error_msg or 'status' in error_msg:
                    return {
                        'value': 'ExploitDB API error',
                        'color': 'version_update',
                        'font': 'version_update',
                        'vulnerability_count': 0,
                        'note': f'ExploitDB API temporarily unavailable'
                    }
                else:
                    raise scan_error
            
            if not scan_result or not scan_result.vulnerabilities:
                return {
                    'value': 'No exploits',
                    'color': 'new_data',
                    'font': 'new_data',
                    'vulnerability_count': 0
                }
            
            vuln_count = len(scan_result.vulnerabilities)
            
            # ExploitDB findings are typically high severity
            return {
                'value': f'ExploitDB: {vuln_count} exploits found',
                'color': 'security_risk',
                'font': 'security_risk',
                'vulnerability_count': vuln_count
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column V for {package_name}: {e}")
            return {'value': 'Error', 'color': 'critical', 'font': 'critical'}
    
    async def close(self):
        """Clean up resources"""
        if self.pypi_client and hasattr(self.pypi_client, 'close'):
            await self.pypi_client.close()
        
        if self.browser:
            await self.browser.close()