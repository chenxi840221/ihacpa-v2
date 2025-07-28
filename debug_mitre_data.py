#!/usr/bin/env python3
"""
Debug MITRE data to see what we're actually getting
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')

async def debug_mitre():
    """Debug MITRE data"""
    print("🔍 Debugging MITRE Data")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    await manager.initialize()
    
    # Get MITRE scanner
    mitre = await manager.get_sandbox('mitre')
    if not mitre:
        print("❌ MITRE scanner not available")
        return
    
    # Skip cache clearing for now
    
    # Test with Django
    print("\n📦 Testing Django to see CVE data structure:")
    
    # Manually call search to see what we get
    from src.sandboxes.mitre.models import MITRESearchContext
    
    context = MITRESearchContext(
        package_name="django",
        search_terms=["django", "Django", "python django"],
        max_results=5
    )
    
    try:
        # Call internal search method
        cve_info = await mitre._search_cves(context)
        
        print(f"\n✅ Found {cve_info.total_results} CVEs")
        
        if cve_info.vulnerabilities:
            for i, vuln in enumerate(cve_info.vulnerabilities[:3]):
                print(f"\n📋 CVE {i+1}: {vuln.cve_id}")
                print(f"   Description: {vuln.description[:200]}...")
                print(f"   Affected Products: {vuln.affected_products}")
                print(f"   Affected Vendors: {vuln.affected_vendors}")
                print(f"   Published: {vuln.published_date}")
                
                # Test relevance check
                is_relevant = mitre._is_relevant_to_package(vuln, "django", "2.2.0")
                print(f"   Relevant to Django: {is_relevant}")
                
                # Check why it might not be relevant
                desc_lower = vuln.description.lower() if vuln.description else ""
                print(f"   - Contains 'django': {'django' in desc_lower}")
                print(f"   - Contains 'python': {'python' in desc_lower}")
                print(f"   - Contains 'web': {'web' in desc_lower}")
        else:
            print("No vulnerabilities returned")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    # Clean up
    await manager.cleanup()
    print("\n✅ Debug completed")

if __name__ == "__main__":
    asyncio.run(debug_mitre())