#!/usr/bin/env python3
"""
Test individual scanners to verify they're working correctly
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager

# Configure logging to see what's happening
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(name)s - %(message)s')

async def test_scanners():
    """Test each scanner individually"""
    print("🔍 Testing Individual Scanners")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    await manager.initialize()
    
    # Test package
    test_package = "requests"
    test_version = "2.25.1"
    
    print(f"\n📦 Testing with package: {test_package} v{test_version}")
    print("-" * 60)
    
    # Test each scanner individually
    scanners = ['nvd', 'mitre', 'snyk', 'exploit_db']
    
    for scanner_name in scanners:
        print(f"\n🔍 Testing {scanner_name.upper()} scanner:")
        
        try:
            # Get the scanner
            scanner = await manager.get_sandbox(scanner_name)
            if not scanner:
                print(f"  ❌ {scanner_name} scanner not available")
                continue
            
            # Perform scan
            result = await scanner.scan_package(test_package, test_version)
            
            if result.success:
                vuln_count = len(result.vulnerabilities)
                print(f"  ✅ Success: Found {vuln_count} vulnerabilities")
                
                # Show first few vulnerabilities
                if vuln_count > 0:
                    print(f"  📊 Sample vulnerabilities:")
                    for i, vuln in enumerate(result.vulnerabilities[:3]):
                        cve_id = vuln.cve_id or "No CVE ID"
                        title = vuln.title[:50] + "..." if len(vuln.title) > 50 else vuln.title
                        print(f"     {i+1}. {cve_id}: {title}")
                    if vuln_count > 3:
                        print(f"     ... and {vuln_count - 3} more")
                        
                # Check metadata
                if result.metadata:
                    print(f"  📋 Metadata:")
                    for key, value in result.metadata.items():
                        if key in ['search_query', 'total_cves_found', 'scan_duration', 'exploits_found']:
                            print(f"     - {key}: {value}")
            else:
                print(f"  ❌ Failed: {result.error_message}")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    # Clean up
    await manager.cleanup()
    print("\n✅ Test completed")

if __name__ == "__main__":
    asyncio.run(test_scanners())