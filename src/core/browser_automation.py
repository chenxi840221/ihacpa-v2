"""
Browser Automation for IHACPA v2.0

Provides browser-based analysis for GitHub security advisories and other
web-based security information gathering tasks.
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import json

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


class BrowserAutomation:
    """Browser automation for web-based security analysis"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize browser automation.
        
        Args:
            config: Browser configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.driver = None
        self.headless = config.get('headless', True)
        self.timeout = config.get('timeout', 30)
        self.browser_type = config.get('browser', 'chrome').lower()
        
        if not SELENIUM_AVAILABLE:
            raise ImportError("Selenium is required for browser automation. Install with: pip install selenium")
    
    async def initialize(self) -> bool:
        """
        Initialize browser driver.
        
        Returns:
            True if initialized successfully, False otherwise
        """
        try:
            if self.browser_type == 'firefox':
                options = FirefoxOptions()
                if self.headless:
                    options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                self.driver = webdriver.Firefox(options=options)
            else:  # Default to Chrome
                options = ChromeOptions()
                if self.headless:
                    options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-gpu')
                options.add_argument('--window-size=1920,1080')
                self.driver = webdriver.Chrome(options=options)
            
            self.driver.set_page_load_timeout(self.timeout)
            self.logger.info(f"Browser automation initialized with {self.browser_type}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize browser: {e}")
            return False
    
    async def analyze_github_security(self, security_url: str, package_name: str, 
                                    current_version: str) -> Optional[Dict[str, Any]]:
        """
        Analyze GitHub Security Advisories page for vulnerabilities.
        
        Args:
            security_url: GitHub security advisories URL
            package_name: Name of the package
            current_version: Current version being analyzed
            
        Returns:
            Analysis results dictionary if successful, None otherwise
        """
        if not self.driver:
            if not await self.initialize():
                return None
        
        try:
            self.logger.debug(f"Analyzing GitHub security for {package_name} at {security_url}")
            
            # Navigate to the security advisories page
            self.driver.get(security_url)
            
            # Wait for page to load
            await asyncio.sleep(2)
            
            # Check if the page indicates no advisories
            no_advisories_indicators = [
                "No security advisories",
                "No vulnerabilities",
                "This repository has not published any security advisories",
                "0 advisories"
            ]
            
            page_text = self.driver.page_source.lower()
            if any(indicator.lower() in page_text for indicator in no_advisories_indicators):
                return {
                    'vulnerabilities_found': False,
                    'vulnerability_count': 0,
                    'max_severity': 'NONE',
                    'summary': 'No GitHub security advisories found',
                    'advisories': []
                }
            
            # Look for security advisory elements
            advisories = []
            advisory_selectors = [
                '[data-testid="advisory-card"]',
                '.security-advisory',
                '.advisory-card',
                '[aria-label*="advisory"]',
                '.Box--condensed'  # GitHub's common card class
            ]
            
            for selector in advisory_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    if elements:
                        for element in elements[:10]:  # Limit to first 10
                            advisory_info = await self._extract_advisory_info(element, package_name)
                            if advisory_info:
                                advisories.append(advisory_info)
                        break
                except Exception as e:
                    self.logger.debug(f"Selector {selector} failed: {e}")
                    continue
            
            # If no structured advisories found, look for vulnerability keywords
            if not advisories:
                vulnerability_indicators = [
                    'cve-', 'vulnerability', 'security', 'exploit', 'advisory',
                    'critical', 'high', 'medium', 'low'
                ]
                
                found_indicators = [indicator for indicator in vulnerability_indicators 
                                  if indicator in page_text]
                
                if found_indicators:
                    # Estimate based on content
                    estimated_count = len(re.findall(r'cve-\d{4}-\d+', page_text, re.IGNORECASE))
                    if estimated_count == 0:
                        estimated_count = 1  # Assume at least one if indicators found
                    
                    return {
                        'vulnerabilities_found': True,
                        'vulnerability_count': estimated_count,
                        'max_severity': 'UNKNOWN',
                        'summary': f'Potential vulnerabilities detected (manual review recommended)',
                        'advisories': [],
                        'indicators_found': found_indicators
                    }
            
            # Process found advisories
            if advisories:
                max_severity = self._determine_max_severity([adv.get('severity', 'UNKNOWN') for adv in advisories])
                
                # Filter advisories that might affect the current version
                relevant_advisories = []
                for advisory in advisories:
                    if self._is_version_affected(current_version, advisory.get('affected_versions', [])):
                        relevant_advisories.append(advisory)
                
                return {
                    'vulnerabilities_found': len(relevant_advisories) > 0,
                    'vulnerability_count': len(relevant_advisories),
                    'max_severity': max_severity,
                    'summary': f'Found {len(relevant_advisories)} relevant GitHub security advisories',
                    'advisories': relevant_advisories,
                    'all_advisories_count': len(advisories)
                }
            
            # Default: no clear vulnerabilities found
            return {
                'vulnerabilities_found': False,
                'vulnerability_count': 0,
                'max_severity': 'NONE',
                'summary': 'GitHub security analysis completed - no clear vulnerabilities found',
                'advisories': []
            }
            
        except TimeoutException:
            self.logger.warning(f"Timeout loading {security_url}")
            return {
                'vulnerabilities_found': False,
                'vulnerability_count': 0,
                'max_severity': 'UNKNOWN',
                'summary': 'Analysis timeout - manual review recommended',
                'error': 'timeout'
            }
            
        except Exception as e:
            self.logger.error(f"Browser analysis failed for {security_url}: {e}")
            return {
                'vulnerabilities_found': False,
                'vulnerability_count': 0,
                'max_severity': 'UNKNOWN',
                'summary': f'Browser analysis failed: {str(e)}',
                'error': str(e)
            }
    
    async def _extract_advisory_info(self, element, package_name: str) -> Optional[Dict[str, Any]]:
        """Extract information from a security advisory element"""
        try:
            advisory_info = {}
            
            # Try to extract title/summary
            title_selectors = ['h3', 'h4', '.title', '[data-testid="title"]', '.advisory-title']
            for selector in title_selectors:
                try:
                    title_elem = element.find_element(By.CSS_SELECTOR, selector)
                    advisory_info['title'] = title_elem.text.strip()
                    break
                except:
                    continue
            
            # Try to extract severity
            severity_selectors = [
                '.severity', '.badge', '[data-testid="severity"]', 
                '.Label', '.Counter'
            ]
            for selector in severity_selectors:
                try:
                    severity_elem = element.find_element(By.CSS_SELECTOR, selector)
                    severity_text = severity_elem.text.strip().upper()
                    if any(sev in severity_text for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']):
                        advisory_info['severity'] = severity_text
                        break
                except:
                    continue
            
            # Try to extract CVE ID
            text_content = element.text
            cve_match = re.search(r'CVE-\d{4}-\d+', text_content, re.IGNORECASE)
            if cve_match:
                advisory_info['cve'] = cve_match.group().upper()
            
            # Try to extract affected versions
            if 'version' in text_content.lower() or package_name.lower() in text_content.lower():
                advisory_info['potentially_relevant'] = True
            
            # Extract publication date if available
            date_patterns = [
                r'\b\d{4}-\d{2}-\d{2}\b',
                r'\b\d{1,2}/\d{1,2}/\d{4}\b',
                r'\b\w+ \d{1,2}, \d{4}\b'
            ]
            for pattern in date_patterns:
                date_match = re.search(pattern, text_content)
                if date_match:
                    advisory_info['published_date'] = date_match.group()
                    break
            
            return advisory_info if advisory_info else None
            
        except Exception as e:
            self.logger.debug(f"Failed to extract advisory info: {e}")
            return None
    
    def _determine_max_severity(self, severities: List[str]) -> str:
        """Determine the maximum severity from a list"""
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        
        max_severity = 'UNKNOWN'
        max_value = 0
        
        for severity in severities:
            severity = severity.upper()
            for sev_key in severity_order:
                if sev_key in severity:
                    if severity_order[sev_key] > max_value:
                        max_value = severity_order[sev_key]
                        max_severity = sev_key
                    break
        
        return max_severity
    
    def _is_version_affected(self, current_version: str, affected_versions: List[str]) -> bool:
        """
        Check if current version is affected by the advisory.
        This is a simplified version - more sophisticated version comparison would be needed.
        """
        if not affected_versions or not current_version:
            return True  # Assume affected if we can't determine
        
        # Simple string matching for now
        for affected in affected_versions:
            if current_version in affected or affected in current_version:
                return True
        
        return False
    
    async def take_screenshot(self, filename: Optional[str] = None) -> Optional[str]:
        """
        Take a screenshot of the current page.
        
        Args:
            filename: Optional filename for the screenshot
            
        Returns:
            Path to the screenshot if successful, None otherwise
        """
        if not self.driver:
            return None
        
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"ihacpa_browser_screenshot_{timestamp}.png"
            
            screenshot_path = f"/tmp/{filename}"
            self.driver.save_screenshot(screenshot_path)
            self.logger.debug(f"Screenshot saved to {screenshot_path}")
            return screenshot_path
            
        except Exception as e:
            self.logger.error(f"Failed to take screenshot: {e}")
            return None
    
    async def get_page_source(self) -> Optional[str]:
        """
        Get the current page source.
        
        Returns:
            Page source HTML if available, None otherwise
        """
        if not self.driver:
            return None
        
        try:
            return self.driver.page_source
        except Exception as e:
            self.logger.error(f"Failed to get page source: {e}")
            return None
    
    async def close(self):
        """Clean up browser resources"""
        if self.driver:
            try:
                self.driver.quit()
                self.logger.debug("Browser driver closed successfully")
            except Exception as e:
                self.logger.error(f"Error closing browser driver: {e}")
            finally:
                self.driver = None


class MockBrowserAutomation:
    """Mock browser automation for testing when Selenium is not available"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.logger.warning("Using mock browser automation - Selenium not available")
    
    async def initialize(self) -> bool:
        return True
    
    async def analyze_github_security(self, security_url: str, package_name: str, 
                                    current_version: str) -> Optional[Dict[str, Any]]:
        """Mock GitHub security analysis"""
        self.logger.debug(f"Mock GitHub security analysis for {package_name}")
        
        # Simulate analysis based on URL patterns
        if 'github.com' in security_url:
            return {
                'vulnerabilities_found': False,
                'vulnerability_count': 0,
                'max_severity': 'UNKNOWN',
                'summary': 'Mock analysis - manual review recommended',
                'advisories': [],
                'mock': True
            }
        
        return None
    
    async def take_screenshot(self, filename: Optional[str] = None) -> Optional[str]:
        return None
    
    async def get_page_source(self) -> Optional[str]:
        return None
    
    async def close(self):
        pass