"""
PyPI Sandbox Scanner

Fetches package information from the Python Package Index API.
"""

import aiohttp
from typing import Optional, Dict, Any
from datetime import datetime
import asyncio

from ...core.base_scanner import BaseSandbox, ScanResult, VulnerabilityInfo, SeverityLevel, ConfidenceLevel
from .models import PyPIPackageInfo


class PyPISandbox(BaseSandbox):
    """
    PyPI package information scanner.
    
    This sandbox fetches package metadata from PyPI including:
    - Latest version information
    - Release history
    - Dependencies
    - Project URLs (including GitHub)
    - Author/maintainer information
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("pypi", config)
        self.base_url = config.get("base_url", "https://pypi.org/pypi")
        self.timeout = config.get("timeout", 30)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def _ensure_session(self):
        """Ensure HTTP session is available"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    "User-Agent": "IHACPA-v2-PyPI-Scanner/1.0",
                    "Accept": "application/json"
                }
            )
    
    async def health_check(self) -> bool:
        """Check if PyPI API is accessible"""
        try:
            await self._ensure_session()
            
            # Test with a known package
            url = f"{self.base_url}/requests/json"
            async with self.session.get(url) as response:
                return response.status == 200
                
        except Exception as e:
            print(f"PyPI health check failed: {e}")
            return False
    
    async def scan_package(
        self, 
        package_name: str, 
        current_version: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Scan a package from PyPI.
        
        Args:
            package_name: Name of the package to scan
            current_version: Current version (for comparison)
            **kwargs: Additional parameters
            
        Returns:
            ScanResult with package information and any issues found
        """
        scan_start = datetime.utcnow()
        
        # Check cache first
        cache_key = f"pypi:{package_name}:{current_version or 'latest'}"
        if self.cache_manager:
            cached_result = await self.cache_manager.get_scan_result(
                "pypi", package_name, current_version=current_version
            )
            if cached_result:
                return cached_result
        
        # Apply rate limiting
        await self._apply_rate_limit()
        
        try:
            await self._ensure_session()
            
            # Fetch package information from PyPI
            url = f"{self.base_url}/{package_name}/json"
            
            async with self.session.get(url) as response:
                if response.status == 404:
                    result = ScanResult(
                        package_name=package_name,
                        source=self.name,
                        scan_time=scan_start,
                        success=False,
                        vulnerabilities=[],
                        error_message=f"Package '{package_name}' not found on PyPI"
                    )
                    
                    # Cache the not-found result briefly
                    if self.cache_manager:
                        await self.cache_manager.cache_scan_result(
                            "pypi", package_name, result, current_version=current_version
                        )
                    
                    return result
                
                if response.status != 200:
                    error_msg = f"PyPI API returned status {response.status}"
                    if self.rate_limiter:
                        self.rate_limiter.record_failure("pypi", "server_error")
                    
                    return self._create_error_result(package_name, error_msg)
                
                data = await response.json()
                
                # Record successful request
                if self.rate_limiter:
                    self.rate_limiter.record_success("pypi")
                    # Check for rate limit headers
                    self.rate_limiter.adjust_rate_limit("pypi", dict(response.headers))
            
            # Parse package information
            package_info = PyPIPackageInfo.from_pypi_response(data)
            
            # Analyze package for potential issues
            vulnerabilities = await self._analyze_package(package_info, current_version)
            
            # Create scan result
            result = ScanResult(
                package_name=package_name,
                source=self.name,
                scan_time=scan_start,
                success=True,
                vulnerabilities=vulnerabilities,
                metadata={
                    "latest_version": package_info.version,
                    "release_date": package_info.latest_release_date.isoformat() if package_info.latest_release_date else None,
                    "github_url": package_info.get_github_url(),
                    "total_releases": len(package_info.releases),
                    "has_dependencies": len(package_info.requires_dist) > 0,
                    "author": package_info.author,
                    "license": package_info.license,
                    "description": package_info.summary
                }
            )
            
            # Cache the successful result
            if self.cache_manager:
                await self.cache_manager.cache_scan_result(
                    "pypi", package_name, result, current_version=current_version
                )
            
            return result
            
        except asyncio.TimeoutError:
            if self.rate_limiter:
                self.rate_limiter.record_failure("pypi", "timeout")
            return self._create_error_result(package_name, "Request timeout")
            
        except Exception as e:
            if self.rate_limiter:
                self.rate_limiter.record_failure("pypi", "generic")
            return self._create_error_result(package_name, f"Unexpected error: {str(e)}")
    
    async def _analyze_package(
        self, 
        package_info: PyPIPackageInfo, 
        current_version: Optional[str]
    ) -> list[VulnerabilityInfo]:
        """
        Analyze package for potential issues.
        
        Args:
            package_info: Parsed package information
            current_version: Current version being used
            
        Returns:
            List of potential issues found
        """
        issues = []
        
        # Check for version updates
        if current_version and current_version != package_info.version:
            try:
                from packaging import version
                
                if version.parse(current_version) < version.parse(package_info.version):
                    issues.append(VulnerabilityInfo(
                        title="Package Update Available",
                        description=f"Newer version {package_info.version} is available (current: {current_version})",
                        severity=SeverityLevel.INFO,
                        confidence=ConfidenceLevel.VERY_HIGH,
                        affected_versions=[current_version],
                        fixed_versions=[package_info.version],
                        source_url=f"https://pypi.org/project/{package_info.name}/",
                        published_date=package_info.latest_release_date
                    ))
            except Exception:
                # If version comparison fails, just note it
                pass
        
        # Check for missing license
        if not package_info.license or package_info.license.strip() == "":
            issues.append(VulnerabilityInfo(
                title="Missing License Information",
                description="Package does not specify a license, which may pose legal risks",
                severity=SeverityLevel.LOW,
                confidence=ConfidenceLevel.HIGH,
                source_url=f"https://pypi.org/project/{package_info.name}/"
            ))
        
        # Check for very old packages (no releases in 2+ years)
        if package_info.latest_release_date:
            days_since_release = (datetime.utcnow() - package_info.latest_release_date.replace(tzinfo=None)).days
            if days_since_release > 730:  # 2 years
                issues.append(VulnerabilityInfo(
                    title="Potentially Unmaintained Package",
                    description=f"No releases in {days_since_release} days. Package may be unmaintained.",
                    severity=SeverityLevel.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    source_url=f"https://pypi.org/project/{package_info.name}/"
                ))
        
        # Check for suspicious patterns in description
        if package_info.description:
            suspicious_keywords = [
                "download", "install", "crack", "keygen", "serial", "license key"
            ]
            description_lower = package_info.description.lower()
            
            found_suspicious = [kw for kw in suspicious_keywords if kw in description_lower]
            if found_suspicious:
                issues.append(VulnerabilityInfo(
                    title="Potentially Suspicious Package",
                    description=f"Package description contains suspicious keywords: {', '.join(found_suspicious)}",
                    severity=SeverityLevel.HIGH,
                    confidence=ConfidenceLevel.MEDIUM,
                    source_url=f"https://pypi.org/project/{package_info.name}/"
                ))
        
        return issues
    
    async def get_package_info(self, package_name: str) -> Optional[PyPIPackageInfo]:
        """
        Get detailed package information (convenience method).
        
        Args:
            package_name: Package name to fetch
            
        Returns:
            PyPIPackageInfo if found, None otherwise
        """
        try:
            await self._ensure_session()
            
            url = f"{self.base_url}/{package_name}/json"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return PyPIPackageInfo.from_pypi_response(data)
                    
        except Exception as e:
            print(f"Error fetching package info for {package_name}: {e}")
        
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
                pass  # Ignore errors during cleanup