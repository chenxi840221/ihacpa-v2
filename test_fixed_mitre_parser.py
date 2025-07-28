#!/usr/bin/env python3
"""
Test the fixed MITRE web parser
"""

import asyncio
import aiohttp
import re
from src.sandboxes.mitre.scanner import MITRESandbox
from src.sandboxes.mitre.models import MITREReference, MITREVulnerability
from datetime import datetime

async def test_fixed_parser():
    """Test the updated MITRE parser"""
    print("🔍 Testing Fixed MITRE Parser")
    print("=" * 60)
    
    # Create a MITRE scanner instance
    config = {
        "base_url": "https://cveawg.mitre.org/api/cve",
        "web_base_url": "https://cve.mitre.org",
        "timeout": 30
    }
    
    scanner = MITRESandbox(config)
    
    # Test with a known CVE
    test_cve = "CVE-2023-40217"  # Known Python CVE
    
    print(f"📦 Testing with {test_cve}")
    
    # Fetch the HTML
    async with aiohttp.ClientSession() as session:
        try:
            headers = {
                "User-Agent": "IHACPA-v2.0-Security-Scanner",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
            
            url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={test_cve}"
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    print(f"✅ Successfully fetched HTML ({len(html)} chars)")
                    
                    # Test the new parser
                    result = scanner._parse_web_cve(test_cve, html)
                    
                    if result:
                        print(f"✅ Successfully parsed CVE!")
                        print(f"🆔 CVE ID: {result.cve_id}")
                        print(f"📝 Description: {result.description[:200]}...")
                        print(f"🔗 References: {len(result.references)} found")
                        
                        if result.references:
                            print(f"📋 First few references:")
                            for i, ref in enumerate(result.references[:3]):
                                print(f"   {i+1}. {ref.name}: {ref.url}")
                        
                        print(f"📦 Affected Products: {result.affected_products}")
                        print(f"🏢 Affected Vendors: {result.affected_vendors}")
                        
                        # Test relevance filtering with different packages
                        test_packages = ["python", "requests", "django", "flask", "numpy"]
                        
                        print(f"\n🔍 Testing relevance filtering:")
                        for package in test_packages:
                            is_relevant = scanner._is_relevant_to_package(result, package, "1.0.0")
                            print(f"   {package}: {'✅ Relevant' if is_relevant else '❌ Not relevant'}")
                            
                            # Show why it's relevant/not relevant
                            desc_lower = result.description.lower() if result.description else ""
                            package_in_desc = package.lower() in desc_lower
                            python_in_desc = "python" in desc_lower
                            print(f"      - Package in description: {package_in_desc}")
                            print(f"      - Python context: {python_in_desc}")
                        
                    else:
                        print("❌ Failed to parse CVE")
                        
                else:
                    print(f"❌ Failed to fetch HTML: Status {response.status}")
                    
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_fixed_parser())