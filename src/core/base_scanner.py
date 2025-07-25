"""
Base Scanner Interface

Defines the abstract interface that all vulnerability sandboxes must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(Enum):
    """Standardized severity levels across all scanners"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """Confidence level for vulnerability findings"""
    VERY_HIGH = "very_high"  # 90-100%
    HIGH = "high"            # 75-89%
    MEDIUM = "medium"        # 50-74%
    LOW = "low"              # 25-49%
    VERY_LOW = "very_low"    # 0-24%


@dataclass
class VulnerabilityInfo:
    """Standardized vulnerability information"""
    cve_id: Optional[str] = None
    title: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    cvss_score: Optional[float] = None
    affected_versions: List[str] = None
    fixed_versions: List[str] = None
    published_date: Optional[datetime] = None
    references: List[str] = None
    source_url: str = ""
    
    def __post_init__(self):
        if self.affected_versions is None:
            self.affected_versions = []
        if self.fixed_versions is None:
            self.fixed_versions = []
        if self.references is None:
            self.references = []


@dataclass
class ScanResult:
    """Standardized scan result from any sandbox"""
    package_name: str
    source: str  # Scanner name (pypi, nvd, snyk, etc.)
    scan_time: datetime
    success: bool
    vulnerabilities: List[VulnerabilityInfo]
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None
    ai_enhanced: bool = False
    cache_hit: bool = False
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseSandbox(ABC):
    """
    Abstract base class for all vulnerability scanners.
    
    Each scanner (PyPI, NVD, SNYK, etc.) must inherit from this class
    and implement the required methods.
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.rate_limiter = None  # Will be injected by SandboxManager
        self.cache_manager = None  # Will be injected by SandboxManager
        self.ai_layer = None  # Will be injected by SandboxManager
    
    @abstractmethod
    async def scan_package(
        self, 
        package_name: str, 
        current_version: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Scan a package for vulnerabilities.
        
        Args:
            package_name: Name of the package to scan
            current_version: Current version of the package (optional)
            **kwargs: Additional parameters specific to the scanner
            
        Returns:
            ScanResult with findings
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the scanner is healthy and can perform scans.
        
        Returns:
            True if healthy, False otherwise
        """
        pass
    
    def set_dependencies(self, rate_limiter, cache_manager, ai_layer):
        """Inject dependencies from the sandbox manager"""
        self.rate_limiter = rate_limiter
        self.cache_manager = cache_manager
        self.ai_layer = ai_layer
    
    async def _get_cached_result(self, cache_key: str) -> Optional[ScanResult]:
        """Get cached scan result if available"""
        if self.cache_manager:
            return await self.cache_manager.get(cache_key)
        return None
    
    async def _cache_result(self, cache_key: str, result: ScanResult):
        """Cache scan result for future use"""
        if self.cache_manager:
            await self.cache_manager.set(cache_key, result)
    
    async def _apply_rate_limit(self):
        """Apply rate limiting before making requests"""
        if self.rate_limiter:
            await self.rate_limiter.acquire(self.name)
    
    def _create_error_result(self, package_name: str, error_msg: str) -> ScanResult:
        """Create a standardized error result"""
        return ScanResult(
            package_name=package_name,
            source=self.name,
            scan_time=datetime.utcnow(),
            success=False,
            vulnerabilities=[],
            error_message=error_msg
        )