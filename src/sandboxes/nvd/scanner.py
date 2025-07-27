"""
NVD (NIST) Sandbox Scanner

NIST National Vulnerability Database integration with AI-enhanced analysis.
"""

import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from urllib.parse import quote

from ...core.base_scanner import BaseSandbox, ScanResult, VulnerabilityInfo, SeverityLevel, ConfidenceLevel
from ...ai_layer.agents.cve_analyzer import CVEAnalyzer
from ...utils.vulnerability_filter import VulnerabilityFilter
from .models import NVDVulnerability


class NVDSandbox(BaseSandbox):
    """
    NIST National Vulnerability Database scanner with AI enhancement.
    
    Features:
    - Official NVD API v2.0 integration
    - Intelligent CVE filtering by package relevance
    - AI-powered impact analysis
    - CVSS score interpretation
    - Version-specific vulnerability assessment
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("nvd", config)
        self.base_url = config.get("base_url", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.api_key = config.get("api_key")  # Optional NVD API key for higher rate limits
        self.timeout = config.get("timeout", 30)
        self.max_results = config.get("max_results", 100)
        self.days_back = config.get("days_back", 365)  # How far back to search
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.cve_analyzer: Optional[CVEAnalyzer] = None
        self.vulnerability_filter = VulnerabilityFilter()
        self.logger = logging.getLogger(__name__)
    
    async def _ensure_session(self):
        """Ensure HTTP session is available"""
        if not self.session:
            headers = {
                "User-Agent": "IHACPA-v2-NVD-Scanner/1.0",
                "Accept": "application/json"
            }
            
            # Add API key if available
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers
            )
    
    async def _ensure_ai_analyzer(self):
        """Ensure AI analyzer is available"""
        if not self.cve_analyzer and self.ai_layer:
            self.cve_analyzer = CVEAnalyzer(self.ai_layer)
    
    async def health_check(self) -> bool:
        """Check if NVD API is accessible"""
        try:
            await self._ensure_session()
            
            # Test with a simple query
            url = f"{self.base_url}?resultsPerPage=1"
            async with self.session.get(url) as response:
                return response.status == 200
                
        except Exception as e:
            print(f"NVD health check failed: {e}")
            return False
    
    async def scan_package(
        self, 
        package_name: str, 
        current_version: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Scan NVD for vulnerabilities related to a package.
        
        Args:
            package_name: Name of the package to scan
            current_version: Current version of the package
            **kwargs: Additional parameters
            
        Returns:
            ScanResult with NVD findings
        """
        scan_start = datetime.utcnow()
        
        # Check cache first
        if self.cache_manager:
            cached_result = await self.cache_manager.get_scan_result(
                "nvd", package_name, current_version=current_version
            )
            if cached_result:
                return cached_result
        
        # Apply rate limiting (NVD has strict limits: 5 requests per 30 seconds)
        await self._apply_rate_limit()
        
        try:
            await self._ensure_session()
            await self._ensure_ai_analyzer()
            
            # Search for CVEs related to the package
            cve_data = await self._search_cves(package_name)
            
            if self.rate_limiter:
                self.rate_limiter.record_success("nvd")
            
            # Process and analyze CVEs
            vulnerabilities = await self._process_cves(cve_data, package_name, current_version)
            
            # Create scan result
            result = ScanResult(
                package_name=package_name,
                source=self.name,
                scan_time=scan_start,
                success=True,
                vulnerabilities=vulnerabilities,
                metadata={
                    "total_cves_found": len(cve_data),
                    "relevant_cves": len(vulnerabilities),
                    "search_timeframe_days": self.days_back,
                    "ai_enhanced": bool(self.cve_analyzer),
                    "api_key_used": bool(self.api_key)
                },
                ai_enhanced=bool(self.cve_analyzer)
            )
            
            # Cache the result
            if self.cache_manager:
                await self.cache_manager.cache_scan_result(
                    "nvd", package_name, result, current_version=current_version
                )
            
            return result
            
        except asyncio.TimeoutError:
            if self.rate_limiter:
                self.rate_limiter.record_failure("nvd", "timeout")
            return self._create_error_result(package_name, "NVD API request timeout")
            
        except Exception as e:
            if self.rate_limiter:
                self.rate_limiter.record_failure("nvd", "generic")
            return self._create_error_result(package_name, f"NVD scan error: {str(e)}")
    
    async def _search_cves(self, package_name: str) -> List[Dict[str, Any]]:
        """
        Search NVD for CVEs related to a package.
        
        Args:
            package_name: Package name to search for
            
        Returns:
            List of CVE data from NVD API
        """
        # Build search parameters
        params = {
            "keywordSearch": package_name,
            "resultsPerPage": min(self.max_results, 2000),  # NVD limit
            "startIndex": 0
        }
        
        # Two-stage search strategy for better accuracy:
        # 1. First try without date filter to get all CVEs
        # 2. Let our vulnerability filter determine relevance
        # This matches the manual review approach and avoids missing legitimate CVEs
        
        # Remove date filtering to match manual review methodology
        # Our smart vulnerability filter will handle relevance assessment
        # This ensures we don't miss legitimate CVEs due to arbitrary date cutoffs
        
        try:
            async with self.session.get(self.base_url, params=params) as response:
                if response.status == 403:
                    # Rate limited
                    if self.rate_limiter:
                        self.rate_limiter.record_failure("nvd", "rate_limit")
                    raise Exception("NVD API rate limit exceeded")
                
                if response.status != 200:
                    raise Exception(f"NVD API returned status {response.status}")
                
                data = await response.json()
                
                # Check for rate limit headers
                if self.rate_limiter and hasattr(response, 'headers'):
                    self.rate_limiter.adjust_rate_limit("nvd", dict(response.headers))
                
                # Extract CVE items
                vulnerabilities = data.get("vulnerabilities", [])
                
                print(f"🔍 NVD search for '{package_name}': found {len(vulnerabilities)} CVEs")
                
                return vulnerabilities
                
        except Exception as e:
            print(f"❌ NVD search failed for '{package_name}': {e}")
            raise
    
    async def _process_cves(
        self, 
        cve_data: List[Dict[str, Any]], 
        package_name: str, 
        current_version: Optional[str]
    ) -> List[VulnerabilityInfo]:
        """
        Process and analyze CVEs for package relevance.
        
        Args:
            cve_data: Raw CVE data from NVD
            package_name: Target package name
            current_version: Current package version
            
        Returns:
            List of relevant vulnerability information
        """
        vulnerabilities = []
        
        for cve_item in cve_data:
            try:
                # Parse NVD vulnerability
                nvd_vuln = NVDVulnerability.from_nvd_response(cve_item)
                
                # Basic relevance check
                if not self._is_cve_relevant(nvd_vuln, package_name):
                    continue
                
                # Create basic vulnerability info
                vuln_info = await self._create_vulnerability_info(nvd_vuln, package_name, current_version)
                
                # Enhance with AI analysis if available
                if self.cve_analyzer:
                    try:
                        ai_result = await self.cve_analyzer.analyze_cve(
                            cve_id=nvd_vuln.cve_id,
                            cve_description=nvd_vuln.get_primary_description(),
                            package_name=package_name,
                            current_version=current_version,
                            cvss_score=nvd_vuln.get_best_cvss_score(),
                            published_date=nvd_vuln.published
                        )
                        
                        # Use AI analysis if it has higher confidence
                        if ai_result.confidence > 0.5:
                            enhanced_vuln = ai_result.to_vulnerability_info()
                            # Merge with basic info
                            enhanced_vuln.published_date = nvd_vuln.published
                            enhanced_vuln.cvss_score = nvd_vuln.get_best_cvss_score()
                            enhanced_vuln.references = [ref.url for ref in nvd_vuln.references]
                            vuln_info = enhanced_vuln
                        
                    except Exception as e:
                        print(f"⚠️  AI analysis failed for {nvd_vuln.cve_id}: {e}")
                
                vulnerabilities.append(vuln_info)
                
            except Exception as e:
                print(f"⚠️  Failed to process CVE: {e}")
                continue
        
        # Sort by severity and CVSS score
        vulnerabilities.sort(key=lambda v: (
            v.severity.value != "critical",
            v.severity.value != "high", 
            v.severity.value != "medium",
            -(v.cvss_score or 0)
        ))
        
        print(f"📊 NVD: {len(vulnerabilities)} relevant vulnerabilities for {package_name}")
        
        return vulnerabilities
    
    def _is_cve_relevant(self, nvd_vuln: NVDVulnerability, package_name: str) -> bool:
        """
        Check if a CVE is relevant to the package using smart filtering.
        
        Args:
            nvd_vuln: NVD vulnerability data
            package_name: Target package name
            
        Returns:
            True if CVE appears relevant
        """
        # Get affected products from CPE configurations
        affected_products = []
        for config in nvd_vuln.configurations:
            for cpe_match in config.cpe_match:
                if cpe_match.vulnerable:
                    affected_products.append(cpe_match.criteria)
        
        affected_products_str = ' '.join(affected_products)
        
        # Use smart filter to check relevance
        is_relevant, confidence, reason = self.vulnerability_filter.is_python_related_cve(
            cve_id=nvd_vuln.cve_id,
            cve_description=nvd_vuln.get_primary_description(),
            package_name=package_name,
            affected_products=affected_products_str
        )
        
        # Log filtering decision for transparency
        if not is_relevant and confidence > 0.7:
            self.logger.debug(f"Filtered out {nvd_vuln.cve_id} for {package_name}: {reason}")
        
        # For low confidence, fall back to basic string matching
        if confidence < 0.5:
            package_lower = package_name.lower()
            description = nvd_vuln.get_primary_description().lower()
            
            # Basic relevance check
            if package_lower in description:
                return True
            
            # Check references
            for ref in nvd_vuln.references:
                if package_lower in str(ref.url).lower():
                    return True
        
        return is_relevant
    
    async def _create_vulnerability_info(
        self, 
        nvd_vuln: NVDVulnerability, 
        package_name: str, 
        current_version: Optional[str]
    ) -> VulnerabilityInfo:
        """
        Create VulnerabilityInfo from NVD data.
        
        Args:
            nvd_vuln: NVD vulnerability
            package_name: Package name
            current_version: Current version
            
        Returns:
            VulnerabilityInfo object
        """
        # Determine affected versions (basic implementation)
        affected_versions = []
        if current_version and nvd_vuln.affects_package(package_name, current_version):
            affected_versions = [current_version]
        
        # Extract fixed versions from CPE data (simplified)
        fixed_versions = []
        for config in nvd_vuln.configurations:
            for cpe_match in config.cpe_match:
                if not cpe_match.vulnerable and cpe_match.version_start_including:
                    fixed_versions.append(cpe_match.version_start_including)
        
        return VulnerabilityInfo(
            cve_id=nvd_vuln.cve_id,
            title=f"NVD: {nvd_vuln.cve_id}",
            description=nvd_vuln.get_primary_description(),
            severity=nvd_vuln.get_severity_level(),
            confidence=ConfidenceLevel.HIGH,  # NVD is authoritative
            cvss_score=nvd_vuln.get_best_cvss_score(),
            affected_versions=affected_versions,
            fixed_versions=list(set(fixed_versions)),  # Remove duplicates
            published_date=nvd_vuln.published,
            references=[str(ref.url) for ref in nvd_vuln.references],
            source_url=f"https://nvd.nist.gov/vuln/detail/{nvd_vuln.cve_id}"
        )
    
    async def get_cve_details(self, cve_id: str) -> Optional[NVDVulnerability]:
        """
        Get detailed information for a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2023-12345")
            
        Returns:
            NVD vulnerability data if found
        """
        try:
            await self._ensure_session()
            
            params = {"cveId": cve_id}
            
            async with self.session.get(self.base_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    
                    if vulnerabilities:
                        return NVDVulnerability.from_nvd_response(vulnerabilities[0])
                        
        except Exception as e:
            print(f"Error fetching CVE {cve_id}: {e}")
        
        return None
    
    async def close(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
            self.session = None
    
    def __del__(self):
        """Ensure session is closed on object destruction"""
        if self.session:
            try:
                asyncio.get_event_loop().create_task(self.close())
            except Exception:
                pass