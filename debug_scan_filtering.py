#!/usr/bin/env python3
"""
Debug the scan filtering process to see why CVEs are being filtered out
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager

# Enable debug logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(name)s - %(message)s')

async def debug_scan_filtering():
    """Debug the scan filtering process"""
    print("🔍 Debugging Scan Filtering Process")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    await manager.initialize()
    
    # Get MITRE scanner
    mitre = await manager.get_sandbox('mitre')
    if not mitre:
        print("❌ MITRE scanner not available")
        return
    
    print("\n📦 Testing Django with detailed filtering debug:")
    
    # Manually call internal methods to trace the issue
    from src.sandboxes.mitre.models import MITRESearchContext
    
    context = MITRESearchContext(
        package_name="django",
        search_terms=["django", "Django", "python django"],
        max_results=10  # Limit for debugging
    )
    
    try:
        # Call internal search method
        cve_info = await mitre._search_cves(context)
        
        print(f"✅ Found {cve_info.total_results} CVEs")
        
        if cve_info.vulnerabilities:
            print(f"\n🔍 Analyzing each CVE for relevance:")
            
            for i, vuln in enumerate(cve_info.vulnerabilities[:5]):
                print(f"\n📋 CVE {i+1}: {vuln.cve_id}")
                print(f"   Description: {vuln.description[:100] if vuln.description else 'NO DESCRIPTION'}...")
                print(f"   Affected Products: {vuln.affected_products}")
                print(f"   Affected Vendors: {vuln.affected_vendors}")
                
                # Test relevance filtering step by step
                is_relevant = mitre._is_relevant_to_package(vuln, "django", "2.2.0")
                print(f"   🎯 Relevance Result: {is_relevant}")
                
                # Debug the filtering logic
                if not is_relevant:
                    print("   🔍 Why not relevant:")
                    
                    # Check AI relevance score first
                    if vuln.ai_relevance_score is not None:
                        print(f"      - AI relevance score: {vuln.ai_relevance_score} (threshold: 0.3)")
                        if vuln.ai_relevance_score < 0.3:
                            print("      ❌ Failed AI relevance threshold")
                    else:
                        print("      - No AI relevance score, using fallback logic")
                        
                        # Check direct mention
                        package_lower = "django"
                        description_lower = vuln.description.lower() if vuln.description else ""
                        
                        print(f"      - Package in description: {'django' in description_lower}")
                        
                        # Check package variations
                        package_variations = [
                            "django",
                            "django".replace('-', '_'),
                            "django".replace('_', '-'),
                            "django".replace('-', ''),
                            "django".replace('_', '')
                        ]
                        
                        print(f"      - Package variations: {package_variations}")
                        
                        variation_found = False
                        for variation in package_variations:
                            if variation in description_lower:
                                variation_found = True
                                print(f"      ✅ Found variation '{variation}' in description")
                                break
                        
                        if not variation_found:
                            print("      ❌ No package variations found in description")
                        
                        # Check affected products
                        if vuln.affected_products:
                            product_match = False
                            for prod in vuln.affected_products:
                                prod_lower = prod.lower()
                                for variation in package_variations:
                                    if variation in prod_lower or prod_lower in variation:
                                        product_match = True
                                        print(f"      ✅ Found product match: '{prod}' matches '{variation}'")
                                        break
                                if product_match:
                                    break
                            
                            if not product_match:
                                print(f"      ❌ No product matches found in: {vuln.affected_products}")
                        else:
                            print("      ❌ No affected products available")
                
                if is_relevant:
                    print("   ✅ CVE should be included in results")
                else:
                    print("   ❌ CVE will be filtered out")
                    
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
    asyncio.run(debug_scan_filtering())