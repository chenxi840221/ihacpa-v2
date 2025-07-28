#!/usr/bin/env python3
"""
Debug the conversion issue to see where CVEs are being lost
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager

# Enable debug logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

async def debug_conversion_issue():
    """Debug the conversion issue"""
    print("🔍 Debugging CVE Conversion Issue")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    await manager.initialize()
    
    # Get MITRE scanner
    mitre = await manager.get_sandbox('mitre')
    if not mitre:
        print("❌ MITRE scanner not available")
        return
    
    print("\n📦 Testing Django conversion process:")
    
    # Manually call internal methods to trace the exact issue
    from src.sandboxes.mitre.models import MITRESearchContext
    
    context = MITRESearchContext(
        package_name="django",
        search_terms=["django", "Django"],
        max_results=5  # Limit for debugging
    )
    
    try:
        # Call internal search method
        print("🔍 Step 1: Searching for CVEs...")
        cve_info = await mitre._search_cves(context)
        print(f"✅ Found {cve_info.total_results} CVEs")
        
        if cve_info.vulnerabilities:
            print(f"\n🔍 Step 2: Processing each CVE...")
            
            base_vulnerabilities = []
            for i, vuln in enumerate(cve_info.vulnerabilities[:3]):
                print(f"\n📋 Processing CVE {i+1}: {vuln.cve_id}")
                
                # Test relevance filtering
                is_relevant = mitre._is_relevant_to_package(vuln, "django", "2.2.0")
                print(f"   🎯 Relevance: {is_relevant}")
                
                if is_relevant:
                    print("   🔄 Converting to base vulnerability...")
                    try:
                        base_vuln = vuln.to_base_vulnerability()
                        print(f"   ✅ Conversion successful:")
                        print(f"      - CVE ID: {base_vuln.cve_id}")
                        print(f"      - Title: {base_vuln.title}")
                        print(f"      - Severity: {base_vuln.severity}")
                        print(f"      - Description length: {len(base_vuln.description) if base_vuln.description else 0}")
                        
                        base_vulnerabilities.append(base_vuln)
                        
                    except Exception as e:
                        print(f"   ❌ Conversion failed: {e}")
                        import traceback
                        traceback.print_exc()
                else:
                    print("   ❌ Filtered out (not relevant)")
            
            print(f"\n📊 Final results:")
            print(f"   - Total CVEs found: {cve_info.total_results}")
            print(f"   - CVEs processed: 3")
            print(f"   - Base vulnerabilities created: {len(base_vulnerabilities)}")
            
            # Now let's test the actual scan method to see if we get the same results
            print(f"\n🔍 Step 3: Testing full scan method...")
            result = await mitre.scan_package("django", "2.2.0")
            
            print(f"📊 Full scan results:")
            print(f"   - Success: {result.success}")
            print(f"   - Vulnerabilities found: {len(result.vulnerabilities)}")
            print(f"   - Metadata: {result.metadata}")
            
            if len(base_vulnerabilities) != len(result.vulnerabilities):
                print(f"⚠️  DISCREPANCY DETECTED!")
                print(f"   Manual process: {len(base_vulnerabilities)} vulnerabilities")
                print(f"   Full scan: {len(result.vulnerabilities)} vulnerabilities")
                
        else:
            print("No vulnerabilities returned from search")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    # Clean up
    await manager.cleanup()
    print("\n✅ Debug completed")

if __name__ == "__main__":
    asyncio.run(debug_conversion_issue())