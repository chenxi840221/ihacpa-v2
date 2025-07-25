#!/usr/bin/env python3
"""
Test IHACPA v2.0 with packages from Excel file
"""

import asyncio
import pandas as pd
import time
import json
from datetime import datetime
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.core.sandbox_manager import SandboxManager


async def test_packages_from_excel(excel_file, limit=5):
    """Test vulnerability scanning with packages from Excel file"""
    
    print(f"📊 Reading packages from: {excel_file}")
    print("=" * 80)
    
    try:
        # Read Excel file
        df = pd.read_excel(excel_file)
        print(f"✅ Loaded {len(df)} packages from Excel")
        
        # Display columns
        print(f"📋 Available columns: {list(df.columns)}")
        
        # Find package name column (common names)
        package_col = None
        for col in ['Package', 'package', 'Name', 'name', 'Package Name', 'package_name']:
            if col in df.columns:
                package_col = col
                break
        
        if not package_col:
            # Use first column if no standard name found
            package_col = df.columns[0]
            
        print(f"📦 Using column '{package_col}' for package names")
        
        # Get unique packages
        packages = df[package_col].dropna().unique()
        print(f"🎯 Found {len(packages)} unique packages")
        
        # Limit for testing
        test_packages = packages[:limit]
        print(f"\n🧪 Testing with first {len(test_packages)} packages:")
        for i, pkg in enumerate(test_packages, 1):
            print(f"   {i}. {pkg}")
        
    except Exception as e:
        print(f"❌ Error reading Excel file: {e}")
        return
    
    # Initialize IHACPA with AI enhancements
    print(f"\n🚀 Initializing IHACPA v2.0 with AI enhancements...")
    
    config = {
        "ai": {
            "enabled": True,
            "provider": "azure",
            "model": "gpt-4.1"
        },
        "performance": {
            "max_concurrent_scans": 3,  # Moderate concurrency
            "request_timeout": 45
        },
        "redis": {
            "enabled": False  # Disable for testing
        }
    }
    
    try:
        manager = SandboxManager(config)
        await manager.initialize()
        print("✅ IHACPA initialized successfully")
        
        # Get sandbox status
        health = await manager.health_check_all()
        healthy_sandboxes = [name for name, status in health.items() if status]
        print(f"✅ {len(healthy_sandboxes)} sandboxes available: {', '.join(healthy_sandboxes)}")
        
    except Exception as e:
        print(f"❌ Failed to initialize IHACPA: {e}")
        return
    
    # Test scanning
    print(f"\n🔍 Starting vulnerability scans...")
    print("=" * 80)
    
    results_summary = []
    start_time = time.time()
    
    for i, package_name in enumerate(test_packages, 1):
        print(f"\n📦 [{i}/{len(test_packages)}] Scanning: {package_name}")
        print("-" * 60)
        
        scan_start = time.time()
        
        try:
            # Perform AI-enhanced comprehensive scan
            results = await manager.scan_package_with_ai_analysis(
                package_name=str(package_name),
                include_correlation_analysis=True,
                include_risk_assessment=True
            )
            
            scan_time = time.time() - scan_start
            
            # Extract key metrics
            scan_results = results.get("scan_results", {})
            correlation = results.get("correlation_analysis")
            risk_assessment = results.get("risk_assessment")
            
            # Count vulnerabilities
            total_vulns = sum(len(r.vulnerabilities) for r in scan_results.values() if r.success)
            successful_sources = sum(1 for r in scan_results.values() if r.success)
            ai_enhanced = sum(1 for r in scan_results.values() if r.ai_enhanced)
            
            # Get unique vulnerabilities from correlation
            unique_vulns = len(correlation.unique_vulnerabilities) if correlation else total_vulns
            
            # Get risk score
            overall_risk = risk_assessment.overall_package_risk if risk_assessment else 0.0
            critical_vulns = risk_assessment.critical_vulnerabilities if risk_assessment else 0
            
            # Create summary
            package_summary = {
                "package": package_name,
                "scan_time": round(scan_time, 2),
                "sources_scanned": len(scan_results),
                "successful_sources": successful_sources,
                "ai_enhanced_sources": ai_enhanced,
                "total_vulnerabilities": total_vulns,
                "unique_vulnerabilities": unique_vulns,
                "critical_vulnerabilities": critical_vulns,
                "overall_risk_score": round(overall_risk, 2),
                "status": "completed"
            }
            
            # Display results
            print(f"✅ Scan completed in {scan_time:.2f}s")
            print(f"   Sources: {successful_sources}/{len(scan_results)} successful")
            print(f"   AI Enhanced: {ai_enhanced} sources")
            print(f"   Vulnerabilities: {total_vulns} total, {unique_vulns} unique")
            print(f"   Risk Score: {overall_risk:.2f}")
            print(f"   Critical Issues: {critical_vulns}")
            
            # Show top vulnerabilities if any
            if risk_assessment and hasattr(risk_assessment, 'get_top_priority_vulnerabilities'):
                top_vulns = risk_assessment.get_top_priority_vulnerabilities(3)
                if top_vulns:
                    print(f"   🎯 Top Priority Issues:")
                    for vuln_assessment in top_vulns:
                        vuln = vuln_assessment.vulnerability
                        print(f"      • {vuln.cve_id or vuln.title[:50]}...")
                        print(f"        Risk: {vuln_assessment.overall_risk_score:.2f}, Urgency: {vuln_assessment.urgency_level}")
            
            results_summary.append(package_summary)
            
        except Exception as e:
            scan_time = time.time() - scan_start
            print(f"❌ Scan failed: {str(e)[:100]}...")
            
            results_summary.append({
                "package": package_name,
                "scan_time": round(scan_time, 2),
                "status": "failed",
                "error": str(e)[:200]
            })
    
    # Clean up
    await manager.cleanup()
    
    # Summary report
    total_time = time.time() - start_time
    print(f"\n📊 Test Summary")
    print("=" * 80)
    print(f"Total packages tested: {len(test_packages)}")
    print(f"Total time: {total_time:.2f}s")
    print(f"Average time per package: {total_time/len(test_packages):.2f}s")
    
    successful_scans = [r for r in results_summary if r.get("status") == "completed"]
    failed_scans = [r for r in results_summary if r.get("status") == "failed"]
    
    print(f"\nSuccess rate: {len(successful_scans)}/{len(results_summary)} ({len(successful_scans)/len(results_summary)*100:.1f}%)")
    
    if successful_scans:
        total_vulns = sum(r["total_vulnerabilities"] for r in successful_scans)
        unique_vulns = sum(r["unique_vulnerabilities"] for r in successful_scans)
        critical_vulns = sum(r["critical_vulnerabilities"] for r in successful_scans)
        
        print(f"\nVulnerability Statistics:")
        print(f"  Total vulnerabilities found: {total_vulns}")
        print(f"  Unique vulnerabilities: {unique_vulns}")
        print(f"  Critical vulnerabilities: {critical_vulns}")
        
        # High risk packages
        high_risk = [r for r in successful_scans if r["overall_risk_score"] >= 0.7]
        if high_risk:
            print(f"\n🚨 High Risk Packages ({len(high_risk)}):")
            for pkg in sorted(high_risk, key=lambda x: x["overall_risk_score"], reverse=True):
                print(f"  • {pkg['package']}: Risk {pkg['overall_risk_score']}, {pkg['critical_vulnerabilities']} critical")
    
    # Save detailed results
    output_file = f"test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump({
            "test_date": datetime.now().isoformat(),
            "excel_file": excel_file,
            "packages_tested": len(test_packages),
            "total_time": round(total_time, 2),
            "results": results_summary
        }, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    print("\n✅ Test completed!")


async def main():
    """Main test function"""
    excel_file = "data/2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    
    # Check if file exists
    if not Path(excel_file).exists():
        print(f"❌ Excel file not found: {excel_file}")
        return
    
    # Run test with first 5 packages
    await test_packages_from_excel(excel_file, limit=5)


if __name__ == "__main__":
    print("🤖 IHACPA v2.0 - Excel Package Testing")
    print("=" * 80)
    asyncio.run(main())