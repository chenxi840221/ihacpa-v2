#!/usr/bin/env python3
"""
Detailed MITRE HTML analysis to create proper parsing
"""

import asyncio
import aiohttp
import re

async def debug_mitre_html():
    """Debug MITRE HTML in detail"""
    print("🔍 Detailed MITRE HTML Analysis")
    print("=" * 60)
    
    # Test with a known CVE
    test_cve = "CVE-2023-40217"  # Known Python requests CVE
    
    url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={test_cve}"
    
    async with aiohttp.ClientSession() as session:
        try:
            headers = {
                "User-Agent": "IHACPA-v2.0-Security-Scanner",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    html = await response.text()
                    
                    print(f"✅ Successfully fetched {test_cve}")
                    
                    # Find description section more precisely
                    print("\n" + "=" * 60)
                    print("LOOKING FOR DESCRIPTION SECTION")
                    print("=" * 60)
                    
                    # Search for description header and the content that follows
                    desc_header_match = re.search(r'<th[^>]*>Description</th>', html, re.IGNORECASE)
                    if desc_header_match:
                        print("✅ Found Description header")
                        
                        # Get the position and look for content after it
                        start_pos = desc_header_match.end()
                        
                        # Look for the next table row or table data
                        next_section = html[start_pos:start_pos+2000]
                        print(f"\n📋 Next 500 chars after Description header:")
                        print(next_section[:500])
                        
                        # Try to find the actual description content
                        # Pattern: Look for <tr> followed by <td> containing the description
                        desc_content_match = re.search(
                            r'<th[^>]*>Description</th>\s*</tr>\s*<tr[^>]*>\s*<td[^>]*>(.*?)</td>',
                            html, 
                            re.DOTALL | re.IGNORECASE
                        )
                        
                        if desc_content_match:
                            raw_desc = desc_content_match.group(1)
                            clean_desc = re.sub(r'<[^>]+>', '', raw_desc).strip()
                            print(f"\n✅ DESCRIPTION FOUND:")
                            print(f"Raw: {raw_desc[:300]}...")
                            print(f"Clean: {clean_desc[:300]}...")
                        else:
                            # Try alternative pattern
                            alt_pattern = r'<th[^>]*>Description</th>.*?<td[^>]*>(.*?)</td>'
                            alt_match = re.search(alt_pattern, html, re.DOTALL | re.IGNORECASE)
                            if alt_match:
                                raw_desc = alt_match.group(1)
                                clean_desc = re.sub(r'<[^>]+>', '', raw_desc).strip()
                                print(f"\n✅ DESCRIPTION FOUND (alternative):")
                                print(f"Clean: {clean_desc[:300]}...")
                            else:
                                print("❌ Could not find description content")
                    else:
                        print("❌ Could not find Description header")
                    
                    # Look for References section
                    print("\n" + "=" * 60)
                    print("LOOKING FOR REFERENCES SECTION")
                    print("=" * 60)
                    
                    ref_header_match = re.search(r'<th[^>]*>References?</th>', html, re.IGNORECASE)
                    if ref_header_match:
                        print("✅ Found References header")
                        
                        start_pos = ref_header_match.end()
                        ref_section = html[start_pos:start_pos+2000]
                        print(f"\n📋 Next 500 chars after References header:")
                        print(ref_section[:500])
                        
                        # Extract reference links
                        ref_links = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', ref_section)
                        print(f"\n✅ Found {len(ref_links)} reference links:")
                        for i, (url, text) in enumerate(ref_links[:5]):
                            if url.startswith('http'):
                                print(f"  {i+1}. {text}: {url}")
                    else:
                        print("❌ Could not find References header")
                    
                    # Look for other useful information
                    print("\n" + "=" * 60)
                    print("LOOKING FOR OTHER INFORMATION")
                    print("=" * 60)
                    
                    # Check if there are affected products/vendors mentioned
                    if 'product' in html.lower() or 'vendor' in html.lower():
                        print("✅ Found product/vendor mentions in HTML")
                        
                        # Look for common patterns
                        product_matches = re.findall(r'product[^:]*:?\s*([^<\n,]+)', html, re.IGNORECASE)
                        if product_matches:
                            print(f"📦 Potential products: {product_matches[:5]}")
                        
                        vendor_matches = re.findall(r'vendor[^:]*:?\s*([^<\n,]+)', html, re.IGNORECASE)
                        if vendor_matches:
                            print(f"🏢 Potential vendors: {vendor_matches[:5]}")
                    else:
                        print("❌ No product/vendor information found")
                        
                else:
                    print(f"❌ Failed to fetch {test_cve}: Status {response.status}")
                    
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(debug_mitre_html())