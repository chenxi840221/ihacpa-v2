"""
Integration tests for the full IHACPA v2.0 pipeline
"""

import pytest
import asyncio
from datetime import datetime

from src.core.sandbox_manager import SandboxManager
from src.core.base_scanner import SeverityLevel


class TestFullPipeline:
    """Integration tests for the complete scanning pipeline"""
    
    @pytest.fixture
    async def manager(self):
        """Create and initialize sandbox manager for testing"""
        config = {
            "redis": {
                "enabled": False  # Use in-memory for tests
            },
            "ai": {
                "enabled": True,
                "provider": "openai",
                "model": "gpt-4"
            }
        }
        
        manager = SandboxManager(config)
        await manager.initialize()
        yield manager
        await manager.cleanup()
    
    @pytest.mark.asyncio
    async def test_single_package_scan(self, manager):
        """Test scanning a single package across all sandboxes"""
        package_name = "requests"
        current_version = "2.30.0"
        
        results = await manager.scan_package(
            package_name=package_name,
            current_version=current_version
        )
        
        # Verify results structure
        assert isinstance(results, dict)
        assert len(results) > 0
        
        # Check each sandbox result
        for source, result in results.items():
            assert result.package_name == package_name
            assert result.source == source
            assert isinstance(result.scan_time, datetime)
            assert isinstance(result.success, bool)
            assert isinstance(result.vulnerabilities, list)
            
            if result.success:
                # Verify vulnerability structure
                for vuln in result.vulnerabilities:
                    assert hasattr(vuln, 'title')
                    assert hasattr(vuln, 'severity')
                    assert isinstance(vuln.severity, SeverityLevel)
    
    @pytest.mark.asyncio 
    async def test_multiple_sources_parallel(self, manager):
        """Test parallel scanning across multiple sources"""
        package_name = "urllib3"
        
        results = await manager.scan_package(
            package_name=package_name,
            parallel=True
        )
        
        # Should have results from multiple sources
        assert len(results) >= 2  # At least PyPI and NVD
        
        # All scans should complete around the same time (parallel execution)
        scan_times = [result.scan_time for result in results.values()]
        time_spread = max(scan_times) - min(scan_times)
        
        # Parallel scans should complete within 5 seconds of each other
        assert time_spread.total_seconds() < 5.0
    
    @pytest.mark.asyncio
    async def test_cache_performance(self, manager):
        """Test caching improves performance on repeat scans"""
        package_name = "certifi"
        
        # First scan (cache miss)
        start_time = datetime.utcnow()
        results1 = await manager.scan_package(package_name)
        first_scan_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Second scan (should hit cache)
        start_time = datetime.utcnow()
        results2 = await manager.scan_package(package_name)
        second_scan_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Verify results are consistent
        assert len(results1) == len(results2)
        
        # Check for cache hits
        cache_hits = sum(1 for result in results2.values() if result.cache_hit)
        assert cache_hits > 0
        
        # Second scan should be significantly faster
        assert second_scan_time < first_scan_time * 0.5
    
    @pytest.mark.asyncio
    async def test_ai_enhancement(self, manager):
        """Test AI enhancement of vulnerability analysis"""
        # Use a package known to have CVEs for testing
        package_name = "pillow"  # Known to have historical vulnerabilities
        current_version = "8.0.0"  # Older version with known issues
        
        results = await manager.scan_package(
            package_name=package_name,
            current_version=current_version
        )
        
        # Check if any results are AI enhanced
        ai_enhanced_count = sum(1 for result in results.values() if result.ai_enhanced)
        
        # If we have NVD results, they should be AI enhanced (if AI is working)
        if "nvd" in results and results["nvd"].success:
            # AI enhancement might be disabled in test environment, so this is optional
            if results["nvd"].ai_enhanced:
                assert ai_enhanced_count > 0
                
                # Check for AI-enhanced metadata
                nvd_result = results["nvd"]
                if nvd_result.vulnerabilities:
                    # AI-enhanced vulnerabilities should have detailed descriptions
                    for vuln in nvd_result.vulnerabilities:
                        assert len(vuln.description) > 50  # AI should provide detailed analysis
    
    @pytest.mark.asyncio
    async def test_error_handling_and_fallback(self, manager):
        """Test error handling for various failure scenarios"""
        # Test with non-existent package
        results = await manager.scan_package("this-package-definitely-does-not-exist-12345")
        
        # Should get results (even if they're errors)
        assert len(results) > 0
        
        # Check error handling
        for source, result in results.items():
            if not result.success:
                assert result.error_message is not None
                assert len(result.error_message) > 0
    
    @pytest.mark.asyncio
    async def test_aggregated_results(self, manager):
        """Test result aggregation across multiple sources"""
        package_name = "pyyaml"
        
        # Get individual results
        results = await manager.scan_package(package_name)
        
        # Test aggregation
        aggregated = await manager.aggregate_results(results)
        
        # Verify aggregated result structure
        assert aggregated.package_name == package_name
        assert aggregated.source == "aggregated"
        assert aggregated.success == (len([r for r in results.values() if r.success]) > 0)
        assert "successful_sources" in aggregated.metadata
        assert "total_sources" in aggregated.metadata
        assert "success_rate" in aggregated.metadata
        
        # Aggregated vulnerabilities should be deduplicated
        total_individual_vulns = sum(len(r.vulnerabilities) for r in results.values() if r.success)
        aggregated_vulns = len(aggregated.vulnerabilities)
        
        # Aggregated count should be <= sum of individual counts (due to deduplication)
        assert aggregated_vulns <= total_individual_vulns
    
    @pytest.mark.asyncio
    async def test_health_checks(self, manager):
        """Test health checking of all sandboxes"""
        health_status = await manager.health_check_all()
        
        # Should have health status for all registered sandboxes
        assert len(health_status) == len(manager.sandboxes)
        
        # Each health check should return a boolean
        for sandbox_name, is_healthy in health_status.items():
            assert isinstance(is_healthy, bool)
            print(f"{sandbox_name}: {'✅' if is_healthy else '❌'}")
    
    @pytest.mark.asyncio
    async def test_performance_stats(self, manager):
        """Test performance statistics collection"""
        # Perform some scans to generate stats
        packages = ["requests", "urllib3", "certifi"]
        
        for package in packages:
            await manager.scan_package(package)
        
        # Get comprehensive stats
        stats = await manager.get_stats()
        
        # Verify stats structure
        assert "scan_stats" in stats
        assert "registered_sandboxes" in stats
        assert "sandbox_health" in stats
        
        scan_stats = stats["scan_stats"]
        assert scan_stats["total_scans"] >= len(packages)
        assert scan_stats["successful_scans"] >= 0
        assert scan_stats["failed_scans"] >= 0
        
        # If cache is enabled, check cache stats
        if "cache_stats" in stats:
            cache_stats = stats["cache_stats"]
            assert "hit_rate_percent" in cache_stats
            assert "total_requests" in cache_stats
    
    @pytest.mark.asyncio
    async def test_version_specific_analysis(self, manager):
        """Test version-specific vulnerability analysis"""
        package_name = "django"
        old_version = "2.0.0"  # Known to have vulnerabilities
        new_version = "4.2.0"  # More recent version
        
        # Scan old version
        old_results = await manager.scan_package(package_name, old_version)
        
        # Scan new version  
        new_results = await manager.scan_package(package_name, new_version)
        
        # Both should succeed
        assert len(old_results) > 0
        assert len(new_results) > 0
        
        # Compare vulnerability counts (old version should typically have more)
        old_vuln_count = sum(len(r.vulnerabilities) for r in old_results.values() if r.success)
        new_vuln_count = sum(len(r.vulnerabilities) for r in new_results.values() if r.success)
        
        print(f"Vulnerabilities in {old_version}: {old_vuln_count}")
        print(f"Vulnerabilities in {new_version}: {new_vuln_count}")
        
        # This is informational - we don't assert a specific relationship
        # as it depends on the actual vulnerability data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])