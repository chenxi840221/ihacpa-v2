#!/usr/bin/env python3
"""
Test MITRE scanner without cache to verify the fix works
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

async def test_mitre_without_cache():
    """Test MITRE scanner without cache"""
    print("🔍 Testing MITRE Scanner (Cache Cleared)")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    await manager.initialize()
    
    # Get MITRE scanner
    mitre = await manager.get_sandbox('mitre')
    if not mitre:
        print("❌ MITRE scanner not available")
        return
    
    # Clear cache to ensure we get fresh results
    print("🗑️  Clearing MITRE cache...")
    try:
        # Clear the cache by accessing the scanner's cache manager
        if hasattr(mitre, '_cache') and mitre._cache:
            cache_keys = await mitre._cache.keys("mitre:*")
            if cache_keys:
                await mitre._cache.delete(*cache_keys)
                print(f"✅ Cleared {len(cache_keys)} cached entries")
            else:
                print("✅ No cached entries to clear")
        else:
            print("ℹ️  No cache available")
    except Exception as e:
        print(f"⚠️  Could not clear cache: {e}")
    
    # Test packages with known vulnerabilities
    test_packages = [
        ("django", "2.2.0", "Should find Django web framework CVEs"),
        ("requests", "2.25.1", "Should find HTTP library CVEs"),
        ("pillow", "8.0.0", "Should find image processing CVEs")
    ]
    
    print("\n📊 Testing various packages (fresh scan):")
    print("-" * 60)
    
    for package_name, version, expected in test_packages:
        print(f"\n📦 Testing {package_name} v{version}")
        print(f"   Expected: {expected}")
        
        try:
            result = await mitre.scan_package(package_name, version)
            
            if result.success:
                total_found = result.metadata.get('total_cves_found', 0)
                relevant_found = len(result.vulnerabilities)
                
                print(f"   ✅ Total CVEs found: {total_found}")
                print(f"   ✅ Relevant CVEs: {relevant_found}")
                
                if relevant_found > 0:
                    print(f"   📋 Sample CVEs:")
                    for i, vuln in enumerate(result.vulnerabilities[:3]):
                        print(f"      {i+1}. {vuln.cve_id}: {vuln.title}")
                        
                        # Show why it's relevant
                        desc = vuln.description[:100] if vuln.description else ""
                        if package_name.lower() in desc.lower():
                            print(f"         ✓ Direct package mention in description")
                        elif "python" in desc.lower():
                            print(f"         ✓ Python context")
                        elif any(tech in desc.lower() for tech in ["web", "http", "framework", "library"]):
                            print(f"         ✓ Technology match")
                        
                    if relevant_found > 3:
                        print(f"      ... and {relevant_found - 3} more")
                else:
                    print(f"   ⚠️  No relevant CVEs found (filtered from {total_found})")
                    
                    # If we expected results but got none, this might indicate an issue
                    if total_found > 0:
                        print(f"   🔍 This might indicate an issue with relevance filtering")
                        
            else:
                print(f"   ❌ Scan failed: {result.error_message}")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Clean up
    await manager.cleanup()
    print("\n✅ Test completed")

if __name__ == "__main__":
    asyncio.run(test_mitre_without_cache())