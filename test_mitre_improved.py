#!/usr/bin/env python3
"""
Test improved MITRE scanner with known vulnerable packages
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

async def test_mitre_improved():
    """Test MITRE scanner with various packages"""
    print("🔍 Testing Improved MITRE Scanner")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    await manager.initialize()
    
    # Test packages with known vulnerabilities
    test_packages = [
        ("django", "2.2.0", "Should find Django web framework CVEs"),
        ("requests", "2.25.1", "Should find HTTP library CVEs"),
        ("pillow", "8.0.0", "Should find image processing CVEs"),
        ("pyyaml", "5.3", "Should find YAML parsing CVEs"),
        ("jinja2", "2.10", "Should find template injection CVEs")
    ]
    
    # Get MITRE scanner
    mitre = await manager.get_sandbox('mitre')
    if not mitre:
        print("❌ MITRE scanner not available")
        return
    
    print("\n📊 Testing various packages:")
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
                        print(f"      {i+1}. {vuln.cve_id}: {vuln.title[:60]}...")
                        # Check if description contains package or technology keywords
                        desc_lower = vuln.description.lower() if vuln.description else ""
                        if package_name.lower() in desc_lower:
                            print(f"         ✓ Direct package mention")
                        elif any(tech in desc_lower for tech in ["python", "web", "http", "framework"]):
                            print(f"         ✓ Technology match")
                else:
                    print(f"   ⚠️  No relevant CVEs found (filtered from {total_found})")
            else:
                print(f"   ❌ Scan failed: {result.error_message}")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Clean up
    await manager.cleanup()
    print("\n✅ Test completed")

if __name__ == "__main__":
    asyncio.run(test_mitre_improved())