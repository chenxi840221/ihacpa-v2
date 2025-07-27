"""
SNYK Vulnerability Scanner

AI-enhanced scanner for SNYK's commercial vulnerability database.
Provides comprehensive vulnerability analysis with intelligent threat assessment.
"""

import aiohttp
import asyncio
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from urllib.parse import quote
import logging

from ...core.base_scanner import BaseSandbox, ScanResult, VulnerabilityInfo
from ...automation.playwright_manager import PlaywrightManager
from .models import (
    SNYKVulnerability, SNYKPackageInfo, SNYKScanResult, 
    SNYKAnalysisContext, SNYKSeverity, SNYKLicense
)


class SNYKSandbox(BaseSandbox):
    """
    SNYK vulnerability scanner with AI-enhanced analysis.
    
    Features:
    - Web scraping of SNYK security database
    - AI-powered vulnerability analysis and risk assessment
    - Commercial-grade vulnerability intelligence
    - License and dependency analysis
    - Exploit maturity assessment
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("snyk", config)
        self.base_url = config.get("base_url", "https://security.snyk.io")
        self.timeout = config.get("timeout", 30)
        self.max_retries = config.get("max_retries", 3)
        self.user_agent = config.get("user_agent", 
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        
        self.logger = logging.getLogger(__name__)
        self._session: Optional[aiohttp.ClientSession] = None
        self._playwright_manager: Optional[PlaywrightManager] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(limit=10)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {"User-Agent": self.user_agent}
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=headers
            )
        return self._session
    
    async def _get_playwright_manager(self) -> PlaywrightManager:
        """Get or create Playwright manager for complex scraping"""
        if self._playwright_manager is None:
            self._playwright_manager = PlaywrightManager({
                "headless": True,
                "timeout": self.timeout * 1000,
                "user_agent": self.user_agent
            })
            await self._playwright_manager.initialize()
        return self._playwright_manager
    
    async def scan_package(
        self, 
        package_name: str, 
        current_version: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Scan package for vulnerabilities using SNYK database.
        
        Args:
            package_name: Name of the package to scan
            current_version: Current version of the package
            **kwargs: Additional parameters
            
        Returns:
            ScanResult with SNYK findings and AI analysis
        """
        scan_start = datetime.utcnow()
        
        # Check cache first
        cache_key = f"snyk:{package_name}:{current_version or 'latest'}"
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            self.logger.info(f"Cache hit for SNYK scan: {package_name}")
            cached_result.cache_hit = True
            return cached_result
        
        # Apply rate limiting
        await self._apply_rate_limit()
        
        try:
            # Get package vulnerabilities
            vulnerabilities = await self._get_package_vulnerabilities(package_name)
            
            # Get package information
            package_info = await self._get_package_info(package_name)
            
            # Apply AI enhancement if available
            if self.ai_layer and vulnerabilities:
                vulnerabilities = await self._enhance_with_ai(
                    package_name, current_version, vulnerabilities, package_info
                )
            
            # Convert to base format
            base_vulnerabilities = []
            for vuln in vulnerabilities:
                # Filter by version if specified
                if current_version and vuln.affected_versions:
                    if not self._is_version_affected(current_version, vuln.affected_versions):
                        continue
                
                base_vuln = vuln.to_base_vulnerability()
                base_vulnerabilities.append(base_vuln)
            
            # Create result
            scan_duration = (datetime.utcnow() - scan_start).total_seconds()
            
            result = ScanResult(
                package_name=package_name,
                source=self.name,
                scan_time=datetime.utcnow(),
                success=True,
                vulnerabilities=base_vulnerabilities,
                ai_enhanced=bool(self.ai_layer),
                metadata={
                    "snyk_vulnerabilities_count": len(vulnerabilities),
                    "scan_duration": scan_duration,
                    "package_info": package_info.__dict__ if package_info else None,
                    "ai_enhanced_count": sum(1 for v in vulnerabilities if v.ai_confidence),
                    "high_confidence_count": sum(1 for v in vulnerabilities if v.ai_confidence and v.ai_confidence >= 0.8)
                }
            )
            
            # Cache the result
            await self._cache_result(cache_key, result)
            
            self.logger.info(
                f"SNYK scan completed for {package_name}: "
                f"{len(base_vulnerabilities)} vulnerabilities found"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"SNYK scan failed for {package_name}: {e}")
            return self._create_error_result(package_name, f"SNYK scan error: {str(e)}")
    
    async def _get_package_vulnerabilities(self, package_name: str) -> List[SNYKVulnerability]:
        """Get vulnerabilities for a package from SNYK"""
        vulnerabilities = []
        
        try:
            # Try API endpoint first
            api_vulns = await self._get_vulnerabilities_via_api(package_name)
            if api_vulns:
                vulnerabilities.extend(api_vulns)
            else:
                # Fallback to web scraping
                web_vulns = await self._get_vulnerabilities_via_web(package_name)
                vulnerabilities.extend(web_vulns)
            
        except Exception as e:
            self.logger.warning(f"Failed to get SNYK vulnerabilities for {package_name}: {e}")
        
        return vulnerabilities
    
    async def _get_vulnerabilities_via_api(self, package_name: str) -> List[SNYKVulnerability]:
        """Try to get vulnerabilities via SNYK API (if available)"""
        # Note: SNYK API requires authentication for most endpoints
        # This is a placeholder for potential API integration
        return []
    
    async def _get_vulnerabilities_via_web(self, package_name: str) -> List[SNYKVulnerability]:
        """Get vulnerabilities by scraping SNYK web interface"""
        vulnerabilities = []
        
        try:
            playwright_manager = await self._get_playwright_manager()
            
            # Navigate to package security page
            package_url = f"{self.base_url}/package/pip/{quote(package_name)}"
            
            page = await playwright_manager.get_page()
            try:
                await page.goto(package_url)
                
                # Wait for content to load
                await page.wait_for_timeout(2000)
                
                # Check if package exists
                if await page.query_selector('.package-not-found'):
                    self.logger.info(f"Package {package_name} not found in SNYK")
                    return []
                
                # Extract vulnerability cards
                vuln_cards = await page.query_selector_all('.vulnerability-card, .vuln-card, [data-testid="vulnerability"]')
                
                for card in vuln_cards:
                    try:
                        vuln = await self._extract_vulnerability_from_card(card, package_name)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self.logger.warning(f"Failed to extract vulnerability from card: {e}")
                        continue
                
                # Try to get more details if available
                if vulnerabilities:
                    await self._enrich_vulnerability_details(page, vulnerabilities)
        
            except Exception as e:
                self.logger.error(f"Web scraping failed for {package_name}: {e}")
            finally:
                if 'page' in locals():
                    await playwright_manager.close_page(page)
        
        return vulnerabilities
    
    async def _extract_vulnerability_from_card(self, card, package_name: str) -> Optional[SNYKVulnerability]:
        """Extract vulnerability information from a card element"""
        try:
            # Extract basic information
            title_elem = await card.query_selector('.vuln-title, .vulnerability-title, h3, h4')
            title = await title_elem.inner_text() if title_elem else "Unknown Vulnerability"
            
            # Extract SNYK ID
            snyk_id_elem = await card.query_selector('.snyk-id, [data-testid="snyk-id"]')
            snyk_id = await snyk_id_elem.inner_text() if snyk_id_elem else f"SNYK-{package_name}-{hash(title) % 10000}"
            
            # Extract severity
            severity_elem = await card.query_selector('.severity, .vuln-severity, [data-testid="severity"]')
            severity_text = await severity_elem.inner_text() if severity_elem else "medium"
            severity = self._parse_severity(severity_text.lower())
            
            # Extract description
            desc_elem = await card.query_selector('.vuln-description, .description, p')
            description = await desc_elem.inner_text() if desc_elem else ""
            
            # Extract CVSS score
            cvss_elem = await card.query_selector('.cvss-score, [data-testid="cvss"]')
            cvss_text = await cvss_elem.inner_text() if cvss_elem else None
            cvss_score = self._parse_cvss_score(cvss_text) if cvss_text else None
            
            # Extract CVE IDs
            cve_elems = await card.query_selector_all('.cve-id, [data-testid="cve"]')
            cve_ids = []
            for cve_elem in cve_elems:
                cve_text = await cve_elem.inner_text()
                if cve_text.startswith('CVE-'):
                    cve_ids.append(cve_text.strip())
            
            # Extract affected versions
            versions_elem = await card.query_selector('.affected-versions, .versions')
            versions_text = await versions_elem.inner_text() if versions_elem else ""
            affected_versions = self._parse_version_ranges(versions_text)
            
            return SNYKVulnerability(
                snyk_id=snyk_id,
                title=title.strip(),
                description=description.strip(),
                severity=severity,
                cvss_score=cvss_score,
                cve_ids=cve_ids,
                affected_versions=affected_versions,
                package_name=package_name,
                published_date=datetime.utcnow()  # Placeholder
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to extract vulnerability: {e}")
            return None
    
    async def _enrich_vulnerability_details(self, page, vulnerabilities: List[SNYKVulnerability]):
        """Enrich vulnerabilities with additional details"""
        for vuln in vulnerabilities:
            try:
                # Try to click on vulnerability for more details
                vuln_link = await page.query_selector(f'[href*="{vuln.snyk_id}"]')
                if vuln_link:
                    await vuln_link.click()
                    await page.wait_for_timeout(1000)
                    
                    # Extract additional details
                    await self._extract_detailed_info(page, vuln)
                    
                    # Go back
                    await page.go_back()
                    await page.wait_for_timeout(1000)
                    
            except Exception as e:
                self.logger.debug(f"Could not enrich details for {vuln.snyk_id}: {e}")
                continue
    
    async def _extract_detailed_info(self, page, vuln: SNYKVulnerability):
        """Extract detailed information from vulnerability page"""
        try:
            # Extract exploit maturity
            maturity_elem = await page.query_selector('.exploit-maturity, [data-testid="exploit-maturity"]')
            if maturity_elem:
                vuln.exploit_maturity = await maturity_elem.inner_text()
            
            # Extract references
            ref_elems = await page.query_selector_all('.reference-link, .external-link')
            references = []
            for ref_elem in ref_elems:
                href = await ref_elem.get_attribute('href')
                if href:
                    references.append(href)
            vuln.references = references
            
            # Extract functions if mentioned
            func_elems = await page.query_selector_all('.vulnerable-function, .function-name')
            functions = []
            for func_elem in func_elems:
                func_text = await func_elem.inner_text()
                if func_text:
                    functions.append(func_text.strip())
            vuln.functions = functions
            
        except Exception as e:
            self.logger.debug(f"Failed to extract detailed info: {e}")
    
    async def _get_package_info(self, package_name: str) -> Optional[SNYKPackageInfo]:
        """Get general package information from SNYK"""
        try:
            playwright_manager = await self._get_playwright_manager()
            
            package_url = f"{self.base_url}/package/pip/{quote(package_name)}"
            
            page = await playwright_manager.get_page()
            try:
                await page.goto(package_url)
                await page.wait_for_timeout(2000)
                
                # Extract package information
                info = SNYKPackageInfo(package_name=package_name)
                
                # Extract license
                license_elem = await page.query_selector('.license, [data-testid="license"]')
                if license_elem:
                    license_text = await license_elem.inner_text()
                    info.license_type = self._parse_license(license_text)
                
                # Check for deprecation/malicious flags
                warning_elems = await page.query_selector_all('.warning, .alert, .deprecated')
                for warning_elem in warning_elems:
                    warning_text = await warning_elem.inner_text()
                    if 'deprecated' in warning_text.lower():
                        info.deprecated = True
                    if 'malicious' in warning_text.lower():
                        info.malicious = True
                
                # Count vulnerabilities
                vuln_count_elem = await page.query_selector('.vulnerability-count, [data-testid="vuln-count"]')
                if vuln_count_elem:
                    count_text = await vuln_count_elem.inner_text()
                    info.vulnerabilities_count = self._parse_count(count_text)
                
                return info
                
            except Exception as e:
                self.logger.warning(f"Failed to get package info for {package_name}: {e}")
                return None
            finally:
                if 'page' in locals():
                    await playwright_manager.close_page(page)
        
        except Exception as e:
            self.logger.warning(f"Failed to get package info for {package_name}: {e}")
            return None
    
    async def _enhance_with_ai(
        self, 
        package_name: str, 
        current_version: Optional[str],
        vulnerabilities: List[SNYKVulnerability],
        package_info: Optional[SNYKPackageInfo]
    ) -> List[SNYKVulnerability]:
        """Enhance vulnerabilities with AI analysis"""
        if not self.ai_layer:
            return vulnerabilities
        
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            try:
                # Create analysis context
                context = SNYKAnalysisContext(
                    package_name=package_name,
                    current_version=current_version,
                    vulnerability=vuln,
                    package_info=package_info
                )
                
                # Get AI analysis
                analysis = await self._get_ai_vulnerability_analysis(context)
                
                # Apply analysis to vulnerability
                if analysis:
                    vuln.ai_risk_assessment = analysis.get('risk_assessment')
                    vuln.ai_confidence = analysis.get('confidence', 0.5)
                    vuln.ai_recommendation = analysis.get('recommendation')
                    vuln.ai_reasoning = analysis.get('reasoning')
                    vuln.ai_exploitability = analysis.get('exploitability')
                    vuln.ai_business_impact = analysis.get('business_impact')
                
                enhanced_vulns.append(vuln)
                
            except Exception as e:
                self.logger.warning(f"AI enhancement failed for {vuln.snyk_id}: {e}")
                enhanced_vulns.append(vuln)  # Add without enhancement
        
        return enhanced_vulns
    
    async def _get_ai_vulnerability_analysis(self, context: SNYKAnalysisContext) -> Optional[Dict[str, Any]]:
        """Get AI analysis for a vulnerability"""
        try:
            from ...ai_layer.agents.cve_analyzer import CVEAnalyzer
            
            analyzer = CVEAnalyzer(self.ai_layer)
            
            # Create comprehensive prompt context
            prompt_context = context.to_prompt_context()
            
            # Use the CVE analyzer with SNYK-specific context
            analysis_result = await analyzer.analyze_cve(
                cve_id=context.vulnerability.cve_ids[0] if context.vulnerability.cve_ids else context.vulnerability.snyk_id,
                cve_description=f"SNYK Vulnerability: {context.vulnerability.description}",
                package_name=context.package_name,
                current_version=context.current_version,
                cvss_score=context.vulnerability.cvss_score,
                affected_products=f"Python package {context.package_name}"
            )
            
            return {
                'risk_assessment': analysis_result.severity.value,
                'confidence': analysis_result.confidence,
                'recommendation': analysis_result.recommendation,
                'reasoning': analysis_result.reasoning,
                'exploitability': 'High' if context.vulnerability.exploit_maturity == 'Mature' else 'Medium',
                'business_impact': self._assess_business_impact(context.vulnerability)
            }
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return None
    
    def _assess_business_impact(self, vuln: SNYKVulnerability) -> str:
        """Assess business impact based on vulnerability characteristics"""
        if vuln.severity == SNYKSeverity.CRITICAL:
            return "Critical - Immediate action required"
        elif vuln.severity == SNYKSeverity.HIGH:
            if vuln.exploit_maturity == "Mature":
                return "High - Active exploitation possible"
            else:
                return "High - Potential security breach"
        elif vuln.severity == SNYKSeverity.MEDIUM:
            return "Medium - Monitor and plan remediation"
        else:
            return "Low - Address in next maintenance cycle"
    
    def _parse_severity(self, severity_text: str) -> SNYKSeverity:
        """Parse severity from text"""
        severity_text = severity_text.lower().strip()
        
        if 'critical' in severity_text:
            return SNYKSeverity.CRITICAL
        elif 'high' in severity_text:
            return SNYKSeverity.HIGH
        elif 'medium' in severity_text:
            return SNYKSeverity.MEDIUM
        elif 'low' in severity_text:
            return SNYKSeverity.LOW
        else:
            return SNYKSeverity.MEDIUM
    
    def _parse_cvss_score(self, cvss_text: str) -> Optional[float]:
        """Parse CVSS score from text"""
        import re
        
        # Extract numeric score
        match = re.search(r'(\d+\.?\d*)', cvss_text)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
        return None
    
    def _parse_version_ranges(self, versions_text: str) -> List[str]:
        """Parse affected version ranges"""
        if not versions_text:
            return []
        
        # Simple parsing - can be enhanced
        versions = []
        for line in versions_text.split('\n'):
            line = line.strip()
            if line and not line.startswith('Fixed in'):
                versions.append(line)
        
        return versions
    
    def _parse_license(self, license_text: str) -> SNYKLicense:
        """Parse license type"""
        license_text = license_text.lower()
        
        if any(term in license_text for term in ['gpl', 'copyleft', 'agpl']):
            return SNYKLicense.COPYLEFT
        elif any(term in license_text for term in ['mit', 'apache', 'bsd', 'permissive']):
            return SNYKLicense.PERMISSIVE
        elif any(term in license_text for term in ['proprietary', 'commercial']):
            return SNYKLicense.PROPRIETARY
        else:
            return SNYKLicense.UNKNOWN
    
    def _parse_count(self, count_text: str) -> int:
        """Parse count from text"""
        import re
        
        match = re.search(r'(\d+)', count_text)
        if match:
            return int(match.group(1))
        return 0
    
    def _is_version_affected(self, current_version: str, affected_ranges: List[str]) -> bool:
        """Check if current version is affected by vulnerability"""
        # Simple version checking - can be enhanced with proper version parsing
        try:
            from packaging import version
            
            current = version.parse(current_version)
            
            for range_str in affected_ranges:
                # Handle various range formats
                if '<' in range_str:
                    # e.g., "< 1.2.3"
                    max_version = range_str.split('<')[1].strip()
                    if current < version.parse(max_version):
                        return True
                elif range_str == current_version:
                    return True
                # Add more range parsing as needed
            
            return False
            
        except Exception:
            # Fallback to simple string matching
            return current_version in affected_ranges
    
    async def health_check(self) -> bool:
        """Check if SNYK sandbox is healthy"""
        try:
            session = await self._get_session()
            
            # Test basic connectivity
            async with session.get(f"{self.base_url}") as response:
                if response.status == 200:
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"SNYK health check failed: {e}")
            return False
    
    async def close(self):
        """Clean up resources"""
        if self._session and not self._session.closed:
            await self._session.close()
        
        if self._playwright_manager:
            await self._playwright_manager.cleanup()
        
        self.logger.info("SNYK sandbox closed")