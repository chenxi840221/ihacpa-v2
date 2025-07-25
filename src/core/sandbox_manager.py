"""
Sandbox Manager

Orchestrates all vulnerability scanners and provides a unified interface
for scanning packages across multiple sources.
"""

import asyncio
from typing import Dict, List, Optional, Any, Type
from datetime import datetime
import logging

from .base_scanner import BaseSandbox, ScanResult, VulnerabilityInfo
from .cache_manager import CacheManager
from .rate_limiter import RateLimiter


class SandboxManager:
    """
    Central orchestrator for all vulnerability scanning sandboxes.
    
    Features:
    - Automatic dependency injection (cache, rate limiter, AI layer)
    - Parallel scanning across multiple sources
    - Unified result aggregation
    - Health monitoring
    - Performance metrics
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.sandboxes: Dict[str, BaseSandbox] = {}
        self.sandbox_classes: Dict[str, Type[BaseSandbox]] = {}
        
        # Core components
        self.cache_manager: Optional[CacheManager] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.ai_layer = None  # Will be set up with AI factory
        
        # Performance tracking
        self.scan_stats = {
            "total_scans": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "cache_hits": 0,
            "total_scan_time": 0.0
        }
        
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize all core components"""
        try:
            # Initialize cache manager
            if self.config.get("redis", {}).get("enabled", True):
                redis_url = self.config.get("redis", {}).get("url", "redis://localhost:6379")
                self.cache_manager = CacheManager(redis_url)
                await self.cache_manager.connect()
                self.logger.info("✅ Cache manager initialized")
            
            # Initialize rate limiter
            self.rate_limiter = RateLimiter()
            self.logger.info("✅ Rate limiter initialized")
            
            # Initialize AI layer
            if self.config.get("ai", {}).get("enabled", True):
                from ..ai_layer.chain_factory import initialize_ai_layer
                self.ai_layer = initialize_ai_layer(self.config.get("ai", {}))
                self.logger.info("✅ AI layer initialized")
            
            # Register default sandboxes
            await self._register_default_sandboxes()
            
            self.logger.info(f"✅ SandboxManager initialized with {len(self.sandboxes)} sandboxes")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize SandboxManager: {e}")
            raise
    
    async def _register_default_sandboxes(self):
        """Register all available sandboxes"""
        try:
            # Import and register PyPI sandbox
            from ..sandboxes.pypi import PyPISandbox
            await self.register_sandbox("pypi", PyPISandbox, {
                "base_url": "https://pypi.org/pypi",
                "timeout": 30
            })
            
            # Import and register NVD sandbox
            from ..sandboxes.nvd import NVDSandbox
            await self.register_sandbox("nvd", NVDSandbox, {
                "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "timeout": 30,
                "max_results": 100,
                "days_back": 365
            })
            
            # TODO: Register other sandboxes as they're implemented
            # await self.register_sandbox("snyk", SNYKSandbox, snyk_config)
            
        except ImportError as e:
            self.logger.warning(f"Could not import sandbox: {e}")
    
    async def register_sandbox(
        self, 
        name: str, 
        sandbox_class: Type[BaseSandbox], 
        config: Dict[str, Any]
    ):
        """
        Register a new sandbox scanner.
        
        Args:
            name: Unique name for the sandbox
            sandbox_class: Class implementing BaseSandbox
            config: Configuration for the sandbox
        """
        try:
            # Create sandbox instance
            sandbox = sandbox_class(config)
            
            # Inject dependencies
            sandbox.set_dependencies(
                rate_limiter=self.rate_limiter,
                cache_manager=self.cache_manager,
                ai_layer=self.ai_layer
            )
            
            # Test health
            is_healthy = await sandbox.health_check()
            if not is_healthy:
                self.logger.warning(f"Sandbox '{name}' failed health check but will be registered")
            
            self.sandboxes[name] = sandbox
            self.sandbox_classes[name] = sandbox_class
            
            self.logger.info(f"✅ Registered sandbox: {name} ({'healthy' if is_healthy else 'unhealthy'})")
            
        except Exception as e:
            self.logger.error(f"Failed to register sandbox '{name}': {e}")
            raise
    
    async def scan_package(
        self, 
        package_name: str, 
        current_version: Optional[str] = None,
        sources: Optional[List[str]] = None,
        parallel: bool = True,
        **kwargs
    ) -> Dict[str, ScanResult]:
        """
        Scan a package across multiple vulnerability sources.
        
        Args:
            package_name: Name of the package to scan
            current_version: Current version of the package
            sources: List of specific sources to scan (None = all sources)
            parallel: Whether to run scans in parallel
            **kwargs: Additional parameters passed to scanners
            
        Returns:
            Dictionary mapping source names to ScanResults
        """
        scan_start = datetime.utcnow()
        self.scan_stats["total_scans"] += 1
        
        # Determine which sources to scan
        if sources is None:
            sources = list(self.sandboxes.keys())
        else:
            # Validate requested sources
            invalid_sources = set(sources) - set(self.sandboxes.keys())
            if invalid_sources:
                raise ValueError(f"Unknown sources: {invalid_sources}")
        
        if not sources:
            self.logger.warning("No sources available for scanning")
            return {}
        
        self.logger.info(f"Scanning {package_name} across {len(sources)} sources: {sources}")
        
        # Execute scans
        if parallel and len(sources) > 1:
            results = await self._scan_parallel(package_name, current_version, sources, **kwargs)
        else:
            results = await self._scan_sequential(package_name, current_version, sources, **kwargs)
        
        # Update statistics
        scan_duration = (datetime.utcnow() - scan_start).total_seconds()
        self.scan_stats["total_scan_time"] += scan_duration
        
        successful = sum(1 for result in results.values() if result.success)
        failed = len(results) - successful
        cache_hits = sum(1 for result in results.values() if result.cache_hit)
        
        self.scan_stats["successful_scans"] += successful
        self.scan_stats["failed_scans"] += failed
        self.scan_stats["cache_hits"] += cache_hits
        
        self.logger.info(
            f"Scan completed in {scan_duration:.2f}s: "
            f"{successful} successful, {failed} failed, {cache_hits} cache hits"
        )
        
        return results
    
    async def _scan_parallel(
        self, 
        package_name: str, 
        current_version: Optional[str], 
        sources: List[str],
        **kwargs
    ) -> Dict[str, ScanResult]:
        """Execute scans in parallel"""
        tasks = []
        
        for source in sources:
            sandbox = self.sandboxes[source]
            task = asyncio.create_task(
                self._scan_with_error_handling(sandbox, package_name, current_version, **kwargs),
                name=f"scan_{source}_{package_name}"
            )
            tasks.append((source, task))
        
        results = {}
        completed_tasks = await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)
        
        for (source, _), result in zip(tasks, completed_tasks):
            if isinstance(result, Exception):
                self.logger.error(f"Scan failed for {source}: {result}")
                results[source] = ScanResult(
                    package_name=package_name,
                    source=source,
                    scan_time=datetime.utcnow(),
                    success=False,
                    vulnerabilities=[],
                    error_message=f"Unexpected error: {str(result)}"
                )
            else:
                results[source] = result
        
        return results
    
    async def _scan_sequential(
        self, 
        package_name: str, 
        current_version: Optional[str], 
        sources: List[str],
        **kwargs
    ) -> Dict[str, ScanResult]:
        """Execute scans sequentially"""
        results = {}
        
        for source in sources:
            sandbox = self.sandboxes[source]
            try:
                result = await self._scan_with_error_handling(
                    sandbox, package_name, current_version, **kwargs
                )
                results[source] = result
                
            except Exception as e:
                self.logger.error(f"Scan failed for {source}: {e}")
                results[source] = ScanResult(
                    package_name=package_name,
                    source=source,
                    scan_time=datetime.utcnow(),
                    success=False,
                    vulnerabilities=[],
                    error_message=f"Unexpected error: {str(e)}"
                )
        
        return results
    
    async def _scan_with_error_handling(
        self, 
        sandbox: BaseSandbox, 
        package_name: str, 
        current_version: Optional[str],
        **kwargs
    ) -> ScanResult:
        """Execute a single scan with comprehensive error handling"""
        try:
            return await sandbox.scan_package(package_name, current_version, **kwargs)
        except asyncio.TimeoutError:
            return ScanResult(
                package_name=package_name,
                source=sandbox.name,
                scan_time=datetime.utcnow(),
                success=False,
                vulnerabilities=[],
                error_message="Scan timeout"
            )
        except Exception as e:
            return ScanResult(
                package_name=package_name,
                source=sandbox.name,
                scan_time=datetime.utcnow(),
                success=False,
                vulnerabilities=[],
                error_message=f"Scan error: {str(e)}"
            )
    
    async def aggregate_results(
        self, 
        scan_results: Dict[str, ScanResult]
    ) -> ScanResult:
        """
        Aggregate results from multiple sources into a unified result.
        
        Args:
            scan_results: Results from individual scanners
            
        Returns:
            Aggregated ScanResult
        """
        all_vulnerabilities = []
        successful_scans = []
        errors = []
        
        # Collect all data
        for source, result in scan_results.items():
            if result.success:
                successful_scans.append(source)
                all_vulnerabilities.extend(result.vulnerabilities)
            else:
                errors.append(f"{source}: {result.error_message}")
        
        # Deduplicate vulnerabilities (basic implementation)
        unique_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)
        
        # Determine overall success
        overall_success = len(successful_scans) > 0
        
        # Create aggregated metadata
        metadata = {
            "successful_sources": successful_scans,
            "failed_sources": [s for s in scan_results.keys() if s not in successful_scans],
            "total_sources": len(scan_results),
            "success_rate": len(successful_scans) / len(scan_results) if scan_results else 0,
            "unique_vulnerabilities": len(unique_vulnerabilities),
            "total_vulnerabilities": len(all_vulnerabilities)
        }
        
        # Get package name from any result
        package_name = next(iter(scan_results.values())).package_name if scan_results else "unknown"
        
        return ScanResult(
            package_name=package_name,
            source="aggregated",
            scan_time=datetime.utcnow(),
            success=overall_success,
            vulnerabilities=unique_vulnerabilities,
            error_message="; ".join(errors) if errors else None,
            metadata=metadata
        )
    
    def _deduplicate_vulnerabilities(
        self, 
        vulnerabilities: List[VulnerabilityInfo]
    ) -> List[VulnerabilityInfo]:
        """
        Simple deduplication of vulnerabilities by CVE ID and title.
        
        Args:
            vulnerabilities: List of vulnerabilities to deduplicate
            
        Returns:
            Deduplicated list
        """
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create a key for deduplication
            key = (vuln.cve_id, vuln.title.strip().lower()) if vuln.cve_id else vuln.title.strip().lower()
            
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
        
        return unique
    
    async def health_check_all(self) -> Dict[str, bool]:
        """Check health of all registered sandboxes"""
        results = {}
        
        for name, sandbox in self.sandboxes.items():
            try:
                is_healthy = await sandbox.health_check()
                results[name] = is_healthy
            except Exception as e:
                self.logger.error(f"Health check failed for {name}: {e}")
                results[name] = False
        
        return results
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        stats = {
            "scan_stats": self.scan_stats.copy(),
            "registered_sandboxes": list(self.sandboxes.keys()),
            "sandbox_health": await self.health_check_all()
        }
        
        # Add cache stats if available
        if self.cache_manager:
            stats["cache_stats"] = await self.cache_manager.get_stats()
        
        # Add rate limiter stats if available
        if self.rate_limiter:
            stats["rate_limiter_stats"] = await self.rate_limiter.get_stats()
        
        return stats
    
    async def cleanup(self):
        """Clean up all resources"""
        # Close all sandboxes
        for sandbox in self.sandboxes.values():
            if hasattr(sandbox, 'close'):
                try:
                    await sandbox.close()
                except Exception as e:
                    self.logger.error(f"Error closing sandbox {sandbox.name}: {e}")
        
        # Close cache manager
        if self.cache_manager:
            await self.cache_manager.disconnect()
        
        self.logger.info("✅ SandboxManager cleanup completed")
    
    def __len__(self):
        """Return number of registered sandboxes"""
        return len(self.sandboxes)
    
    def __contains__(self, sandbox_name: str):
        """Check if sandbox is registered"""
        return sandbox_name in self.sandboxes
    
    def __getitem__(self, sandbox_name: str) -> BaseSandbox:
        """Get sandbox by name"""
        return self.sandboxes[sandbox_name]