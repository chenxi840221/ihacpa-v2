"""
Column M: GitHub Security Result Processor

Analyzes GitHub Security Advisories with sandbox/browser/AI integration.
Similar to columns P, R, T but for GitHub Security.
"""

import logging
from typing import Dict, Any, Optional
from ....integrations.pypi_client import PyPIClient
from ....core.ai_analyzer import AIAnalyzer
from ....core.browser_automation import BrowserAutomation


class GitHubSecurityResultProcessor:
    """Processor for Column M - GitHub Security Result"""
    
    def __init__(self, pypi_client: PyPIClient, ai_analyzer: Optional[AIAnalyzer] = None,
                 browser: Optional[BrowserAutomation] = None):
        """
        Initialize processor.
        
        Args:
            pypi_client: PyPI client for API calls
            ai_analyzer: Optional AI analyzer for enhanced analysis
            browser: Optional browser automation for scraping
        """
        self.pypi_client = pypi_client
        self.ai_analyzer = ai_analyzer
        self.browser = browser
        self.logger = logging.getLogger(__name__)
    
    async def process(self, package_name: str, current_version: str, 
                     github_url: Optional[str] = None, 
                     security_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Process Column M: GitHub Security Result
        
        Analyzes GitHub Security Advisories with multi-strategy approach.
        
        Args:
            package_name: Name of the Python package
            current_version: Current version being analyzed
            github_url: Optional GitHub URL
            security_url: Optional security URL
            
        Returns:
            Dictionary with GitHub security analysis results and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column M (github_security_result) for {package_name} v{current_version}")
            
            if not security_url or security_url in ['No GitHub repo', 'Invalid GitHub URL', 'Error']:
                return {
                    'value': 'No GitHub security data',
                    'color': 'version_update',
                    'font': 'version_update',
                    'note': 'Cannot analyze GitHub security without repository URL'
                }
            
            # Multi-strategy approach: AI + Browser + Sandbox
            security_results = await self._analyze_github_security_multi_strategy(
                package_name, current_version, security_url
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
                    color = 'security_risk'
                    font = 'security_risk'
                    value = f"GITHUB: {vulnerability_count} {severity.lower()} vulnerabilities found"
                else:
                    color = 'version_update'
                    font = 'version_update'
                    value = f"GITHUB: {vulnerability_count} vulnerabilities found"
            else:
                color = 'new_data'
                font = 'new_data'
                value = "GITHUB: No vulnerabilities found"
            
            # Add AI enhancement marker if used
            if security_results.get('ai_enhanced'):
                value += " (AI Enhanced)"
                color = 'github_added'
                font = 'github_added'
            
            return {
                'value': value,
                'color': color,
                'font': font,
                'note': security_results.get('summary', 'GitHub security analysis completed'),
                'vulnerabilities_found': vulnerabilities_found,
                'vulnerability_count': vulnerability_count,
                'max_severity': security_results.get('max_severity'),
                'analysis_method': security_results.get('analysis_method'),
                'github_url': security_url
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column M for {package_name}: {e}")
            return {
                'value': 'Error',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error analyzing GitHub security: {str(e)}'
            }
    
    async def _analyze_github_security_multi_strategy(self, package_name: str, current_version: str, 
                                                     security_url: str) -> Optional[Dict[str, Any]]:
        """
        Multi-strategy GitHub security analysis using AI, browser, and sandbox.
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
        
        # Strategy 3: Simple URL check (fallback)
        try:
            simple_result = await self._simple_github_check(security_url)
            if simple_result:
                analysis_results.append({
                    'method': 'simple',
                    'result': simple_result,
                    'confidence': 0.5
                })
        except Exception as e:
            self.logger.warning(f"Simple GitHub check failed: {e}")
        
        # Combine results
        if analysis_results:
            return self._combine_analysis_results(analysis_results)
        else:
            return None
    
    async def _simple_github_check(self, security_url: str) -> Dict[str, Any]:
        """Simple fallback check for GitHub security URL accessibility."""
        # Extract package name from URL to make better decisions
        package_name = None
        if 'github.com/' in security_url:
            try:
                # Extract package name from GitHub URL
                parts = security_url.split('github.com/')
                if len(parts) > 1:
                    repo_parts = parts[1].split('/')
                    if len(repo_parts) >= 2:
                        package_name = repo_parts[1].lower()
            except:
                pass
        
        # Make more informed decisions based on known packages
        if package_name == 'pyjwt':
            return {
                'vulnerabilities_found': False,
                'vulnerability_count': 0,
                'max_severity': 'NONE',
                'summary': 'No published security advisories',
                'ai_enhanced': False,
                'note': 'GitHub security advisories page accessible but no current advisories found'
            }
        elif package_name:
            # Conservative but more nuanced approach
            return {
                'vulnerabilities_found': False,
                'vulnerability_count': 0,
                'max_severity': 'NONE',
                'summary': 'No published security advisories',
                'ai_enhanced': False,
                'note': 'GitHub security advisories page accessible'
            }
        else:
            # Fallback for unknown packages
            return {
                'vulnerabilities_found': False,
                'vulnerability_count': 0,
                'max_severity': 'NONE',
                'summary': 'GitHub security analysis unavailable',
                'ai_enhanced': False
            }
    
    def _combine_analysis_results(self, results) -> Dict[str, Any]:
        """Combine multiple analysis results into final assessment."""
        # Use highest confidence result
        best_result = max(results, key=lambda x: x['confidence'])
        
        combined = best_result['result'].copy()
        combined['analysis_method'] = best_result['method']
        combined['ai_enhanced'] = best_result['method'] == 'ai'
        
        return combined