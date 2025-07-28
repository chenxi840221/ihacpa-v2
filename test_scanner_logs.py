#!/usr/bin/env python3
"""
Test the updated scanner logs to verify progress visibility
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager

# Configure logging to be less verbose so we can see our progress logs clearly
logging.basicConfig(level=logging.WARNING, format='%(levelname)s - %(message)s')

async def test_scanner_logs():
    """Test scanner logs for progress visibility"""
    print("🔍 Testing Scanner Progress Logs")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    await manager.initialize()
    
    # Test package
    test_package = "django"
    test_version = "2.2.0"
    
    print(f"\n📦 Testing progress logs with package: {test_package} v{test_version}")
    print("=" * 60)
    
    # Test each scanner individually to see the progress logs
    scanners_to_test = [
        ('nvd', 'NVD (Column K)'),
        ('mitre', 'MITRE (Column T)'), 
        ('snyk', 'SNYK (Column V)'),
        ('exploit_db', 'ExploitDB (Column R)')
    ]
    
    for scanner_name, description in scanners_to_test:
        print(f"\n🔍 Testing {description}:")
        print("-" * 40)
        
        try:
            # Get the scanner
            scanner = await manager.get_sandbox(scanner_name)
            if not scanner:
                print(f"  ❌ {scanner_name} scanner not available")
                continue
            
            # Perform scan and watch for progress logs
            result = await scanner.scan_package(test_package, test_version)
            
            if result.success:
                vuln_count = len(result.vulnerabilities)
                print(f"  ✅ Scan completed: {vuln_count} vulnerabilities found")
                
                # Show scan metadata if available
                if result.metadata:
                    duration = result.metadata.get('scan_duration', 'N/A')
                    total_found = result.metadata.get('total_cves_found') or result.metadata.get('exploits_found', 'N/A')
                    print(f"  📊 Total found: {total_found}, Duration: {duration}s")
            else:
                print(f"  ❌ Scan failed: {result.error_message}")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    print(f"\n" + "=" * 60)
    print("📋 Log Format Summary:")
    print("🔍 [Scanner] search for 'package': found X CVEs/vulnerabilities/exploits")
    print("📊 [Scanner]: X relevant vulnerabilities/exploits for package")
    print("=" * 60)
    
    # Clean up
    await manager.cleanup()
    print("\n✅ Test completed")

if __name__ == "__main__":
    asyncio.run(test_scanner_logs())