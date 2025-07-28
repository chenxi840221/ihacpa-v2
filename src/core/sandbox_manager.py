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
            redis_config = self._get_config_value("redis", {})
            if self._get_nested_config_value(redis_config, "enabled", True):
                redis_url = self._get_nested_config_value(redis_config, "url", "redis://localhost:6379")
                self.cache_manager = CacheManager(redis_url)
                await self.cache_manager.connect()
                self.logger.info("✅ Cache manager initialized")
            
            # Initialize rate limiter
            self.rate_limiter = RateLimiter()
            self.logger.info("✅ Rate limiter initialized")
            
            # Initialize AI layer
            ai_config = self._get_config_value("ai", {})
            if self._get_nested_config_value(ai_config, "enabled", True):
                from ..ai_layer.chain_factory import initialize_ai_layer
                # Convert config object to dict if needed
                ai_config_dict = ai_config.__dict__ if hasattr(ai_config, '__dict__') and not isinstance(ai_config, dict) else ai_config
                self.ai_layer = initialize_ai_layer(ai_config_dict)
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
            try:
                from ..sandboxes.pypi import PyPISandbox
                await self.register_sandbox("pypi", PyPISandbox, {
                    "base_url": "https://pypi.org/pypi",
                    "timeout": 30
                })
                self.logger.info("✅ PyPI sandbox registered")
            except ImportError as e:
                self.logger.warning(f"PyPI sandbox not available: {e}")
            
            # Import and register NVD sandbox
            try:
                from ..sandboxes.nvd import NVDSandbox
                await self.register_sandbox("nvd", NVDSandbox, {
                    "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    "timeout": 30,
                    "max_results": 100,
                    "days_back": 365
                })
                self.logger.info("✅ NVD sandbox registered")
            except ImportError as e:
                self.logger.warning(f"NVD sandbox not available: {e}")
            
            # Import and register SNYK sandbox
            try:
                from ..sandboxes.snyk import SNYKSandbox
                await self.register_sandbox("snyk", SNYKSandbox, {
                    "base_url": "https://security.snyk.io",
                    "timeout": 45,
                    "max_retries": 3
                })
            except ImportError as e:
                self.logger.warning(f"SNYK sandbox not available: {e}")
            
            # Import and register MITRE sandbox
            try:
                from ..sandboxes.mitre import MITRESandbox
                await self.register_sandbox("mitre", MITRESandbox, {
                    "base_url": "https://cveawg.mitre.org/api/cve",
                    "web_base_url": "https://cve.mitre.org",
                    "timeout": 30,
                    "max_results": 100,
                    "days_back": 365
                })
            except ImportError as e:
                self.logger.warning(f"MITRE sandbox not available: {e}")
            
            # Import and register GitHub Advisory sandbox
            try:
                from ..sandboxes.github_advisory import GitHubAdvisorySandbox
                await self.register_sandbox("github_advisory", GitHubAdvisorySandbox, {
                    "api_url": "https://api.github.com/graphql",
                    "rest_api_url": "https://api.github.com",
                    "timeout": 30,
                    "max_results": 100
                })
            except ImportError as e:
                self.logger.warning(f"GitHub Advisory sandbox not available: {e}")
            
            # Import and register Exploit-DB sandbox (if implemented)
            try:
                from ..sandboxes.exploit_db import ExploitDBScanner
                await self.register_sandbox("exploit_db", ExploitDBScanner, {
                    "base_url": "https://www.exploit-db.com",
                    "timeout": 30,
                    "max_results": 50
                })
                self.logger.info("✅ Exploit-DB sandbox registered")
            except ImportError as e:
                self.logger.warning(f"Exploit-DB sandbox not available: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to register sandboxes: {e}")
    
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
    
    async def scan_package_with_ai_analysis(
        self, 
        package_name: str, 
        current_version: Optional[str] = None,
        include_correlation_analysis: bool = True,
        include_risk_assessment: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Enhanced package scanning with AI-powered correlation and risk assessment.
        
        Args:
            package_name: Name of the package to scan
            current_version: Current version of the package
            include_correlation_analysis: Whether to perform cross-database correlation
            include_risk_assessment: Whether to perform AI risk assessment
            **kwargs: Additional parameters
            
        Returns:
            Enhanced scan results with AI analysis
        """
        # Perform standard scanning
        scan_results = await self.scan_package(
            package_name, current_version, **kwargs
        )
        
        enhanced_results = {
            "package_name": package_name,
            "current_version": current_version,
            "scan_results": scan_results,
            "scan_timestamp": datetime.utcnow()
        }
        
        # Add cross-database correlation analysis if requested
        if include_correlation_analysis and self.ai_layer:
            try:
                from ..ai_layer.agents.correlation_analyzer import CrossDatabaseCorrelationAnalyzer
                
                correlation_analyzer = CrossDatabaseCorrelationAnalyzer(self.ai_layer)
                correlation_analysis = await correlation_analyzer.analyze_cross_database_results(
                    package_name, scan_results
                )
                enhanced_results["correlation_analysis"] = correlation_analysis
                
            except Exception as e:
                self.logger.warning(f"Correlation analysis failed: {e}")
                enhanced_results["correlation_analysis"] = None
        
        # Add AI risk assessment if requested
        if include_risk_assessment and self.ai_layer:
            try:
                from ..ai_layer.agents.risk_assessor import AIRiskAssessor, ThreatContext
                
                risk_assessor = AIRiskAssessor(self.ai_layer)
                
                # Collect all unique vulnerabilities
                all_vulnerabilities = []
                for result in scan_results.values():
                    if result.success:
                        all_vulnerabilities.extend(result.vulnerabilities)
                
                # Deduplicate vulnerabilities
                unique_vulnerabilities = self._deduplicate_vulnerabilities_simple(all_vulnerabilities)
                
                # Perform risk assessment
                if unique_vulnerabilities:
                    risk_profile = await risk_assessor.assess_package_risk_profile(
                        unique_vulnerabilities, package_name, ThreatContext.PRODUCTION
                    )
                    enhanced_results["risk_assessment"] = risk_profile
                else:
                    enhanced_results["risk_assessment"] = None
                
            except Exception as e:
                self.logger.warning(f"Risk assessment failed: {e}")
                enhanced_results["risk_assessment"] = None
        
        return enhanced_results
    
    def _deduplicate_vulnerabilities_simple(
        self, 
        vulnerabilities: List[VulnerabilityInfo]
    ) -> List[VulnerabilityInfo]:
        """Simple vulnerability deduplication"""
        seen_cves = set()
        seen_titles = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Deduplicate by CVE ID first
            if vuln.cve_id and vuln.cve_id not in seen_cves:
                seen_cves.add(vuln.cve_id)
                unique_vulns.append(vuln)
            # Then by normalized title for non-CVE vulnerabilities
            elif not vuln.cve_id:
                normalized_title = vuln.title.lower().strip()
                if normalized_title not in seen_titles:
                    seen_titles.add(normalized_title)
                    unique_vulns.append(vuln)
        
        return unique_vulns
    
    async def get_enhanced_scan_summary(
        self, 
        scan_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get enhanced summary of scan results with AI insights.
        
        Args:
            scan_results: Results from scan_package_with_ai_analysis
            
        Returns:
            Enhanced summary with key insights
        """
        summary = {
            "package_name": scan_results.get("package_name"),
            "scan_timestamp": scan_results.get("scan_timestamp"),
            "total_sources_scanned": len(scan_results.get("scan_results", {})),
            "successful_scans": 0,
            "total_vulnerabilities_found": 0,
            "unique_vulnerabilities": 0,
            "ai_enhanced_sources": 0
        }
        
        # Analyze basic scan results
        for source, result in scan_results.get("scan_results", {}).items():
            if result.success:
                summary["successful_scans"] += 1
                summary["total_vulnerabilities_found"] += len(result.vulnerabilities)
                if result.ai_enhanced:
                    summary["ai_enhanced_sources"] += 1
        
        # Add correlation analysis insights
        correlation_analysis = scan_results.get("correlation_analysis")
        if correlation_analysis:
            summary["correlation_insights"] = correlation_analysis.get_correlation_summary()
            summary["unique_vulnerabilities"] = len(correlation_analysis.unique_vulnerabilities)
            summary["ai_overall_risk"] = correlation_analysis.ai_overall_risk_assessment
            summary["ai_priority_vulnerabilities"] = correlation_analysis.ai_priority_vulnerabilities
        
        # Add risk assessment insights
        risk_assessment = scan_results.get("risk_assessment")
        if risk_assessment:
            summary["risk_insights"] = {
                "overall_package_risk": risk_assessment.overall_package_risk,
                "critical_vulnerabilities": risk_assessment.critical_vulnerabilities,
                "high_risk_vulnerabilities": risk_assessment.high_risk_vulnerabilities,
                "immediate_actions_needed": len(risk_assessment.immediate_actions),
                "top_priority_vulnerabilities": [
                    {
                        "cve_id": vuln.vulnerability.cve_id,
                        "title": vuln.vulnerability.title,
                        "risk_score": vuln.overall_risk_score,
                        "urgency": vuln.urgency_level
                    }
                    for vuln in risk_assessment.get_top_priority_vulnerabilities(3)
                ]
            }
        
        return summary
    
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
    
    async def get_sandbox(self, sandbox_name: str) -> Optional[BaseSandbox]:
        """
        Get a specific sandbox by name.
        
        Args:
            sandbox_name: Name of the sandbox to retrieve
            
        Returns:
            BaseSandbox instance if found, None otherwise
        """
        return self.sandboxes.get(sandbox_name)
    
    def _get_config_value(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with robust handling of both dict and object configs.
        
        Args:
            key: Configuration key to retrieve
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            if isinstance(self.config, dict):
                return self.config.get(key, default)
            elif hasattr(self.config, key):
                return getattr(self.config, key, default)
            elif hasattr(self.config, '__dict__') and key in self.config.__dict__:
                return self.config.__dict__[key]
            else:
                return default
        except Exception:
            return default
    
    def _get_nested_config_value(self, config_obj: Any, key: str, default: Any = None) -> Any:
        """
        Get nested configuration value with robust handling.
        
        Args:
            config_obj: Configuration object or dict
            key: Configuration key to retrieve
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            if isinstance(config_obj, dict):
                return config_obj.get(key, default)
            elif hasattr(config_obj, key):
                return getattr(config_obj, key, default)
            elif hasattr(config_obj, '__dict__') and key in config_obj.__dict__:
                return config_obj.__dict__[key]
            else:
                return default
        except Exception:
            return default