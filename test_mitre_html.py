#!/usr/bin/env python3
"""
Test what actual MITRE HTML looks like to fix the web scraper
"""

import asyncio
import aiohttp
import re

async def test_mitre_html():
    """Test MITRE HTML structure"""
    print("🔍 Testing MITRE HTML Structure")
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
                    print(f"📄 HTML length: {len(html)} characters")
                    print("\n" + "=" * 60)
                    print("HTML STRUCTURE ANALYSIS")
                    print("=" * 60)
                    
                    # Show relevant sections
                    lines = html.split('\n')
                    for i, line in enumerate(lines):
                        line_lower = line.lower()
                        
                        # Look for description patterns
                        if 'description' in line_lower and ('td' in line_lower or 'div' in line_lower):
                            print(f"\n📋 DESCRIPTION SECTION (line {i}):")
                            # Show context around this line
                            start = max(0, i-2)
                            end = min(len(lines), i+3)
                            for j in range(start, end):
                                prefix = ">>> " if j == i else "    "
                                print(f"{prefix}{lines[j]}")
                        
                        # Look for reference patterns
                        if 'reference' in line_lower and ('td' in line_lower or 'div' in line_lower):
                            print(f"\n📋 REFERENCE SECTION (line {i}):")
                            start = max(0, i-2)
                            end = min(len(lines), i+3)
                            for j in range(start, end):
                                prefix = ">>> " if j == i else "    "
                                print(f"{prefix}{lines[j]}")
                    
                    # Test current regex patterns
                    print("\n" + "=" * 60)
                    print("CURRENT REGEX TESTING")
                    print("=" * 60)
                    
                    # Test description pattern
                    desc_pattern = r'<td[^>]*>\s*Description\s*</td>\s*<td[^>]*>(.*?)</td>'
                    desc_match = re.search(desc_pattern, html, re.DOTALL | re.IGNORECASE)
                    
                    if desc_match:
                        desc = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip()
                        print(f"✅ Description found: {desc[:200]}...")
                    else:
                        print("❌ Description pattern not found")
                        
                        # Try alternative patterns
                        alt_patterns = [
                            r'Description.*?<td[^>]*>(.*?)</td>',
                            r'<th[^>]*>Description</th>\s*<td[^>]*>(.*?)</td>',
                            r'Description:</th>\s*<td[^>]*>(.*?)</td>',
                            r'<div[^>]*description[^>]*>(.*?)</div>',
                            r'description[^>]*>(.*?)<'
                        ]
                        
                        for i, pattern in enumerate(alt_patterns):
                            alt_match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
                            if alt_match:
                                alt_desc = re.sub(r'<[^>]+>', '', alt_match.group(1)).strip()
                                print(f"✅ Alternative pattern {i+1} worked: {alt_desc[:200]}...")
                                break
                        else:
                            print("❌ No alternative patterns worked")
                    
                    # Check for table structure
                    print("\n" + "=" * 60)
                    print("TABLE STRUCTURE ANALYSIS")
                    print("=" * 60)
                    
                    # Look for table rows with Description
                    table_rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL | re.IGNORECASE)
                    for i, row in enumerate(table_rows):
                        if 'description' in row.lower():
                            print(f"\n📋 Table row {i} with description:")
                            print(f"    {row[:300]}...")
                    
                else:
                    print(f"❌ Failed to fetch {test_cve}: Status {response.status}")
                    
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_mitre_html())