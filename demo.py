#!/usr/bin/env python3
"""
IHACPA v2.0 Demo Script

Demonstrates the new modular vulnerability scanning system.
"""

import asyncio
import json
from datetime import datetime
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.core.sandbox_manager import SandboxManager
from src.core.base_scanner import SeverityLevel


async def demo_single_package():
    """Demo scanning a single package"""
    print("🔍 IHACPA v2.0 Demo - Single Package Scan")
    print("=" * 50)
    
    # Initialize the sandbox manager with Azure OpenAI
    manager = SandboxManager({
        "redis": {
            "enabled": True,
            "url": "redis://localhost:6379"
        },
        "ai": {
            "enabled": True,
            "provider": "azure",    # Use Azure OpenAI
            "model": "gpt-4.1",     # Azure deployment name
            "temperature": 0.1,
            "timeout": 45
        },
        "performance": {
            "max_concurrent_scans": 2  # Optimized for Azure rate limits
        }
    })
    
    try:
        # Initialize all components
        print("🚀 Initializing sandbox manager...")
        await manager.initialize()
        print(f"✅ Initialized with {len(manager)} sandboxes")
        
        # Demo package to scan (known to have some historical vulnerabilities)
        package_name = "requests"
        current_version = "2.30.0"
        
        print(f"\n📦 Scanning package: {package_name} (current version: {current_version})")
        print("-" * 30)
        
        # Perform the scan
        scan_start = datetime.now()
        results = await manager.scan_package(
            package_name=package_name,
            current_version=current_version,
            parallel=True
        )
        scan_duration = (datetime.now() - scan_start).total_seconds()
        
        # Display results
        print(f"⏱️  Scan completed in {scan_duration:.2f} seconds\n")
        
        for source, result in results.items():
            print(f"📊 {source.upper()} Results:")
            print(f"   Success: {'✅' if result.success else '❌'}")
            print(f"   Cache Hit: {'🎯' if result.cache_hit else '🔄'}")
            
            if result.success:
                print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
                
                # Show vulnerabilities by severity
                severity_counts = {}
                for vuln in result.vulnerabilities:
                    severity = vuln.severity
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                for severity, count in severity_counts.items():
                    emoji = {
                        SeverityLevel.CRITICAL: "🚨",
                        SeverityLevel.HIGH: "🔴", 
                        SeverityLevel.MEDIUM: "🟡",
                        SeverityLevel.LOW: "🟢",
                        SeverityLevel.INFO: "ℹ️"
                    }.get(severity, "❓")
                    print(f"   {emoji} {severity.value}: {count}")
                
                # Show sample vulnerabilities
                if result.vulnerabilities:
                    print(f"   \n   📋 Sample findings:")
                    for vuln in result.vulnerabilities[:3]:  # Show first 3
                        print(f"      • {vuln.title}")
                        if vuln.cve_id:
                            print(f"        CVE: {vuln.cve_id}")
                        print(f"        Severity: {vuln.severity.value}")
                        if hasattr(vuln, 'confidence'):
                            print(f"        Confidence: {vuln.confidence.value}")
                        
                        # Show AI enhancement indicator
                        if result.ai_enhanced:
                            print(f"        🤖 AI Enhanced")
                
                # Show metadata
                if result.metadata:
                    print(f"   \n   📈 Metadata:")
                    for key, value in result.metadata.items():
                        if value is not None:
                            print(f"      {key}: {value}")
            else:
                print(f"   Error: {result.error_message}")
            
            print()
        
        # Aggregate results
        print("🔗 Aggregated Results:")
        print("-" * 20)
        aggregated = await manager.aggregate_results(results)
        
        print(f"Overall Success: {'✅' if aggregated.success else '❌'}")
        print(f"Total Unique Vulnerabilities: {len(aggregated.vulnerabilities)}")
        print(f"Sources: {aggregated.metadata['successful_sources']}")
        print(f"Success Rate: {aggregated.metadata['success_rate']:.1%}")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        print("\n🧹 Cleaning up...")
        await manager.cleanup()


async def demo_multiple_packages():
    """Demo scanning multiple packages"""
    print("\n" + "=" * 60)
    print("🔍 IHACPA v2.0 Demo - Multiple Package Scan")
    print("=" * 60)
    
    packages = [
        ("requests", "2.30.0"),
        ("urllib3", "1.26.0"),
        ("certifi", "2022.12.7")
    ]
    
    manager = SandboxManager({
        "redis": {
            "enabled": True,
            "url": "redis://localhost:6379"
        }
    })
    
    try:
        await manager.initialize()
        
        print(f"📦 Scanning {len(packages)} packages...")
        
        all_results = {}
        total_vulnerabilities = 0
        
        for package_name, version in packages:
            print(f"\n🔍 Scanning {package_name} v{version}...")
            
            results = await manager.scan_package(
                package_name=package_name,
                current_version=version,
                parallel=True
            )
            
            all_results[package_name] = results
            
            # Count vulnerabilities across all sources
            package_vulns = sum(len(r.vulnerabilities) for r in results.values() if r.success)
            total_vulnerabilities += package_vulns
            
            print(f"   Found {package_vulns} potential issues")
        
        # Summary
        print(f"\n📊 Scan Summary:")
        print(f"   Packages scanned: {len(packages)}")
        print(f"   Total findings: {total_vulnerabilities}")
        print(f"   Sources used: {list(next(iter(all_results.values())).keys())}")
        
    except Exception as e:
        print(f"❌ Multi-package demo failed: {e}")
    
    finally:
        await manager.cleanup()


async def demo_system_stats():
    """Demo system statistics and monitoring"""
    print("\n" + "=" * 60)
    print("📊 IHACPA v2.0 Demo - System Statistics")
    print("=" * 60)
    
    manager = SandboxManager({
        "redis": {
            "enabled": True,
            "url": "redis://localhost:6379"
        }
    })
    
    try:
        await manager.initialize()
        
        # Get comprehensive stats
        stats = await manager.get_stats()
        
        print("🏥 System Health:")
        for sandbox, healthy in stats["sandbox_health"].items():
            status = "✅ Healthy" if healthy else "❌ Unhealthy"
            print(f"   {sandbox}: {status}")
        
        print("\n📈 Performance Stats:")
        scan_stats = stats["scan_stats"]
        print(f"   Total scans: {scan_stats['total_scans']}")
        print(f"   Successful: {scan_stats['successful_scans']}")
        print(f"   Failed: {scan_stats['failed_scans']}")
        print(f"   Cache hits: {scan_stats['cache_hits']}")
        
        if scan_stats['total_scans'] > 0:
            success_rate = scan_stats['successful_scans'] / scan_stats['total_scans'] * 100
            print(f"   Success rate: {success_rate:.1f}%")
            
            if scan_stats['cache_hits'] > 0:
                cache_rate = scan_stats['cache_hits'] / scan_stats['total_scans'] * 100
                print(f"   Cache hit rate: {cache_rate:.1f}%")
        
        # Cache stats
        if "cache_stats" in stats:
            print("\n🎯 Cache Performance:")
            cache_info = stats["cache_stats"]
            print(f"   Hit rate: {cache_info['hit_rate_percent']:.1f}%")
            print(f"   Total requests: {cache_info['total_requests']}")
            
            if "redis_info" in cache_info:
                redis_info = cache_info["redis_info"]
                print(f"   Redis memory: {redis_info.get('used_memory_human', 'N/A')}")
                print(f"   Connected clients: {redis_info.get('connected_clients', 0)}")
        
        # Rate limiter stats
        if "rate_limiter_stats" in stats:
            print("\n⏱️  Rate Limiter Status:")
            for service, info in stats["rate_limiter_stats"].items():
                state = info["circuit_breaker"]["state"]
                failures = info["circuit_breaker"]["failures"]
                
                state_emoji = {
                    "closed": "✅",
                    "open": "🚨", 
                    "half-open": "⚠️"
                }.get(state, "❓")
                
                print(f"   {service}: {state_emoji} {state} (failures: {failures})")
        
    except Exception as e:
        print(f"❌ Stats demo failed: {e}")
    
    finally:
        await manager.cleanup()


async def main():
    """Run all demos"""
    print("🚀 Welcome to IHACPA v2.0 Demo!")
    print("This demo showcases the new modular vulnerability scanning system.")
    print()
    
    # Check if Redis is available
    try:
        import aioredis
        redis = aioredis.from_url("redis://localhost:6379")
        await redis.ping()
        await redis.close()
        print("✅ Redis connection successful")
    except Exception as e:
        print(f"⚠️  Redis not available: {e}")
        print("   Some features may not work. To start Redis:")
        print("   docker-compose up -d redis")
        print()
    
    # Run demos
    await demo_single_package()
    await demo_multiple_packages() 
    await demo_system_stats()
    
    print("\n🎉 Demo completed!")
    print("\nNext steps:")
    print("1. Start Redis: docker-compose up -d redis")
    print("2. Run tests: pytest tests/")
    print("3. Add more sandboxes (NVD, SNYK, etc.)")
    print("4. Integrate with AI layer (LangChain)")


if __name__ == "__main__":
    asyncio.run(main())