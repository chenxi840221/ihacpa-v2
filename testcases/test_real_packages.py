#!/usr/bin/env python3
"""
Test IHACPA v2.0 with real Python packages from Excel file
"""

import asyncio
import pandas as pd
import time
import json
import os
from datetime import datetime
from pathlib import Path
import sys

# Add src to path - use absolute import
sys.path.insert(0, str(Path(__file__).parent))

from src.core.sandbox_manager import SandboxManager


async def test_real_packages(excel_file, limit=10):
    """Test vulnerability scanning with real Python packages from Excel file"""
    
    print(f"🤖 IHACPA v2.0 - Real Package Testing")
    print("=" * 80)
    print(f"📊 Reading packages from: {excel_file}")
    
    try:
        # Read Excel file with proper structure
        df = pd.read_excel(excel_file, skiprows=1)  # Skip first row
        df.columns = [
            'index', 'package_name', 'version', 'pypi_link', 'date_published',
            'latest_version', 'latest_pypi_link', 'latest_date', 'requires',
            'dev_status', 'github_url', 'github_security_url', 'github_security_result',
            'notes', 'nvd_url', 'nvd_result', 'mitre_url', 'mitre_result',
            'snyk_url', 'snyk_result', 'exploit_db_url', 'exploit_db_result', 'recommendation'
        ]
        
        print(f"✅ Loaded {len(df)} packages from Excel")
        
        # Get package names and versions
        packages_data = []
        for _, row in df.iterrows():
            if pd.notna(row['package_name']) and row['package_name'] not in ['Package Name', '#']:
                packages_data.append({
                    'name': str(row['package_name']).strip(),
                    'current_version': str(row['version']).strip() if pd.notna(row['version']) else None,
                    'latest_version': str(row['latest_version']).strip() if pd.notna(row['latest_version']) else None,
                    'recommendation': str(row['recommendation']).strip() if pd.notna(row['recommendation']) else None
                })
        
        print(f"🎯 Found {len(packages_data)} valid packages")
        
        # Select packages for testing
        test_packages = packages_data[:limit]
        
        print(f"\n🧪 Testing with {len(test_packages)} packages:")
        for i, pkg in enumerate(test_packages, 1):
            rec = pkg['recommendation'] or 'N/A'
            print(f"   {i:2d}. {pkg['name']:<20} v{pkg['current_version']:<10} → {rec}")
        
    except Exception as e:
        print(f"❌ Error reading Excel file: {e}")
        return
    
    # Check Azure OpenAI environment
    print(f"\n🔧 Checking environment...")
    required_vars = ['AZURE_OPENAI_ENDPOINT', 'AZURE_OPENAI_KEY', 'AZURE_OPENAI_MODEL']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"❌ Missing environment variables: {missing_vars}")
        print("💡 Please set Azure OpenAI credentials to enable AI features")
        ai_enabled = False
    else:
        print("✅ Azure OpenAI environment configured")
        ai_enabled = True
    
    # Initialize IHACPA
    print(f"\n🚀 Initializing IHACPA v2.0...")
    
    config = {
        "ai": {
            "enabled": ai_enabled,
            "provider": "azure",
            "model": "gpt-4.1" if ai_enabled else None
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
        
        if ai_enabled:
            print("🤖 AI enhancements: ENABLED")
        else:
            print("📊 AI enhancements: DISABLED (basic scanning only)")
        
    except Exception as e:
        print(f"❌ Failed to initialize IHACPA: {e}")
        return
    
    # Test scanning
    print(f"\n🔍 Starting vulnerability scans...")
    print("=" * 80)
    
    results_summary = []
    start_time = time.time()
    
    for i, pkg_data in enumerate(test_packages, 1):
        package_name = pkg_data['name']
        current_version = pkg_data['current_version']
        recommendation = pkg_data['recommendation']
        
        print(f"\n📦 [{i:2d}/{len(test_packages)}] Scanning: {package_name}")
        if current_version and current_version != 'nan':
            print(f"    Current version: {current_version}")
        if recommendation:
            print(f"    Excel recommendation: {recommendation}")
        print("-" * 60)
        
        scan_start = time.time()
        
        try:
            if ai_enabled:
                # Use AI-enhanced scanning
                results = await manager.scan_package_with_ai_analysis(
                    package_name=package_name,
                    current_version=current_version if current_version != 'nan' else None,
                    include_correlation_analysis=True,
                    include_risk_assessment=True
                )
                
                # Extract enhanced results
                scan_results = results.get("scan_results", {})
                correlation = results.get("correlation_analysis")
                risk_assessment = results.get("risk_assessment")
            else:
                # Use basic scanning
                scan_results = await manager.scan_package(
                    package_name=package_name,
                    current_version=current_version if current_version != 'nan' else None
                )
                correlation = None
                risk_assessment = None
            
            scan_time = time.time() - scan_start
            
            # Count vulnerabilities
            total_vulns = sum(len(r.vulnerabilities) for r in scan_results.values() if r.success)
            successful_sources = sum(1 for r in scan_results.values() if r.success)
            ai_enhanced_sources = sum(1 for r in scan_results.values() if r.ai_enhanced) if ai_enabled else 0
            
            # Get unique vulnerabilities and risk score
            if correlation:
                unique_vulns = len(correlation.unique_vulnerabilities)
                ai_confidence = correlation.consensus_confidence
            else:
                unique_vulns = total_vulns
                ai_confidence = 0.0
            
            if risk_assessment:
                overall_risk = risk_assessment.overall_package_risk
                critical_vulns = risk_assessment.critical_vulnerabilities
                high_risk_vulns = risk_assessment.high_risk_vulnerabilities
            else:
                overall_risk = 0.0
                critical_vulns = 0
                high_risk_vulns = 0
            
            # Determine IHACPA recommendation
            if critical_vulns > 0:
                ihacpa_recommendation = "CRITICAL - IMMEDIATE ACTION"
            elif high_risk_vulns > 0:
                ihacpa_recommendation = "HIGH RISK - URGENT UPDATE"
            elif overall_risk > 0.7:
                ihacpa_recommendation = "MODERATE RISK - PLAN UPDATE"
            elif total_vulns > 0:
                ihacpa_recommendation = "LOW RISK - MONITOR"
            else:
                ihacpa_recommendation = "PROCEED"
            
            # Create summary
            package_summary = {
                "package": package_name,
                "current_version": current_version,
                "scan_time": round(scan_time, 2),
                "sources_scanned": len(scan_results),
                "successful_sources": successful_sources,
                "ai_enhanced_sources": ai_enhanced_sources,
                "total_vulnerabilities": total_vulns,
                "unique_vulnerabilities": unique_vulns,
                "critical_vulnerabilities": critical_vulns,
                "high_risk_vulnerabilities": high_risk_vulns,
                "overall_risk_score": round(overall_risk, 2),
                "ai_confidence": round(ai_confidence, 2),
                "excel_recommendation": recommendation,
                "ihacpa_recommendation": ihacpa_recommendation,
                "status": "completed"
            }
            
            # Display results
            print(f"✅ Scan completed in {scan_time:.2f}s")
            print(f"   Sources: {successful_sources}/{len(scan_results)} successful")
            if ai_enabled:
                print(f"   AI Enhanced: {ai_enhanced_sources} sources")
                print(f"   AI Confidence: {ai_confidence:.1%}")
            print(f"   Vulnerabilities: {total_vulns} total, {unique_vulns} unique")
            if critical_vulns > 0 or high_risk_vulns > 0:
                print(f"   🚨 Risk: {critical_vulns} critical, {high_risk_vulns} high")
            print(f"   Overall Risk: {overall_risk:.2f}")
            
            # Compare recommendations
            print(f"   📋 Excel: {recommendation}")
            print(f"   🤖 IHACPA: {ihacpa_recommendation}")
            
            if recommendation and ihacpa_recommendation:
                if ("PROCEED" in recommendation.upper() and "PROCEED" in ihacpa_recommendation) or \
                   ("CRITICAL" in recommendation.upper() and "CRITICAL" in ihacpa_recommendation) or \
                   ("REMOVE" in recommendation.upper() and "CRITICAL" in ihacpa_recommendation):
                    print(f"   ✅ Recommendations ALIGN")
                else:
                    print(f"   ⚠️  Recommendations DIFFER")
            
            # Show top vulnerabilities for high-risk packages
            if risk_assessment and (critical_vulns > 0 or high_risk_vulns > 0):
                top_vulns = risk_assessment.get_top_priority_vulnerabilities(3)
                if top_vulns:
                    print(f"   🎯 Top Issues:")
                    for vuln_assessment in top_vulns:
                        vuln = vuln_assessment.vulnerability
                        cve_id = vuln.cve_id or "No CVE"
                        title = vuln.title[:40] + "..." if len(vuln.title) > 40 else vuln.title
                        print(f"      • {cve_id}: {title}")
                        print(f"        Risk: {vuln_assessment.overall_risk_score:.2f}, Urgency: {vuln_assessment.urgency_level}")
            
            results_summary.append(package_summary)
            
        except Exception as e:
            scan_time = time.time() - scan_start
            print(f"❌ Scan failed: {str(e)[:100]}...")
            
            results_summary.append({
                "package": package_name,
                "current_version": current_version,
                "scan_time": round(scan_time, 2),
                "status": "failed",
                "error": str(e)[:200],
                "excel_recommendation": recommendation
            })
    
    # Clean up
    await manager.cleanup()
    
    # Generate comprehensive summary
    total_time = time.time() - start_time
    print(f"\n📊 IHACPA v2.0 Test Results")
    print("=" * 80)
    print(f"Total packages tested: {len(test_packages)}")
    print(f"Total scanning time: {total_time:.2f}s")
    print(f"Average time per package: {total_time/len(test_packages):.2f}s")
    
    successful_scans = [r for r in results_summary if r.get("status") == "completed"]
    failed_scans = [r for r in results_summary if r.get("status") == "failed"]
    
    print(f"\n📈 Performance Metrics:")
    print(f"   Success rate: {len(successful_scans)}/{len(results_summary)} ({len(successful_scans)/len(results_summary)*100:.1f}%)")
    
    if successful_scans:
        avg_scan_time = sum(r["scan_time"] for r in successful_scans) / len(successful_scans)
        print(f"   Average scan time: {avg_scan_time:.2f}s")
        
        if ai_enabled:
            avg_ai_sources = sum(r["ai_enhanced_sources"] for r in successful_scans) / len(successful_scans)
            avg_confidence = sum(r["ai_confidence"] for r in successful_scans) / len(successful_scans)
            print(f"   Average AI sources: {avg_ai_sources:.1f}")
            print(f"   Average AI confidence: {avg_confidence:.1%}")
    
    if successful_scans:
        total_vulns = sum(r["total_vulnerabilities"] for r in successful_scans)
        unique_vulns = sum(r["unique_vulnerabilities"] for r in successful_scans)
        critical_vulns = sum(r["critical_vulnerabilities"] for r in successful_scans)
        high_risk_vulns = sum(r["high_risk_vulnerabilities"] for r in successful_scans)
        
        print(f"\n🔍 Vulnerability Statistics:")
        print(f"   Total vulnerabilities found: {total_vulns}")
        print(f"   Unique vulnerabilities: {unique_vulns}")
        print(f"   Critical vulnerabilities: {critical_vulns}")
        print(f"   High risk vulnerabilities: {high_risk_vulns}")
        
        if total_vulns > 0:
            deduplication_rate = (total_vulns - unique_vulns) / total_vulns * 100
            print(f"   Deduplication rate: {deduplication_rate:.1f}%")
    
    # Risk distribution
    if successful_scans and ai_enabled:
        risk_categories = {
            "Critical (>0.9)": len([r for r in successful_scans if r["overall_risk_score"] > 0.9]),
            "High (0.7-0.9)": len([r for r in successful_scans if 0.7 <= r["overall_risk_score"] <= 0.9]),
            "Medium (0.4-0.7)": len([r for r in successful_scans if 0.4 <= r["overall_risk_score"] < 0.7]),
            "Low (<0.4)": len([r for r in successful_scans if r["overall_risk_score"] < 0.4])
        }
        
        print(f"\n⚠️ Risk Distribution:")
        for category, count in risk_categories.items():
            if count > 0:
                print(f"   {category}: {count} packages")
    
    # High priority packages
    high_priority = [r for r in successful_scans if r["critical_vulnerabilities"] > 0 or r["overall_risk_score"] >= 0.8]
    if high_priority:
        print(f"\n🚨 High Priority Packages ({len(high_priority)}):")
        for pkg in sorted(high_priority, key=lambda x: x["overall_risk_score"], reverse=True)[:10]:
            risk_score = pkg["overall_risk_score"]
            critical = pkg["critical_vulnerabilities"]
            excel_rec = pkg["excel_recommendation"]
            ihacpa_rec = pkg["ihacpa_recommendation"]
            
            print(f"   • {pkg['package']:<20} Risk: {risk_score:.2f}, Critical: {critical}")
            print(f"     Excel: {excel_rec:<25} IHACPA: {ihacpa_rec}")
    
    # Recommendation comparison
    comparable_results = [r for r in successful_scans if r.get("excel_recommendation") and r.get("ihacpa_recommendation")]
    if comparable_results:
        agreements = 0
        for r in comparable_results:
            excel_rec = r["excel_recommendation"].upper()
            ihacpa_rec = r["ihacpa_recommendation"].upper()
            
            # Simple agreement logic
            if ("PROCEED" in excel_rec and "PROCEED" in ihacpa_rec) or \
               ("CRITICAL" in excel_rec and "CRITICAL" in ihacpa_rec) or \
               ("REMOVE" in excel_rec and "CRITICAL" in ihacpa_rec) or \
               ("REVIEW" in excel_rec and any(term in ihacpa_rec for term in ["RISK", "UPDATE"])):
                agreements += 1
        
        agreement_rate = agreements / len(comparable_results) * 100
        print(f"\n📋 Recommendation Comparison:")
        print(f"   Comparable packages: {len(comparable_results)}")
        print(f"   Agreement rate: {agreements}/{len(comparable_results)} ({agreement_rate:.1f}%)")
    
    # Save detailed results
    output_file = f"ihacpa_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump({
            "test_metadata": {
                "test_date": datetime.now().isoformat(),
                "excel_file": excel_file,
                "packages_tested": len(test_packages),
                "total_time": round(total_time, 2),
                "ai_enabled": ai_enabled,
                "ihacpa_version": "2.0"
            },
            "summary": {
                "success_rate": len(successful_scans) / len(results_summary) * 100,
                "total_vulnerabilities": sum(r.get("total_vulnerabilities", 0) for r in successful_scans),
                "unique_vulnerabilities": sum(r.get("unique_vulnerabilities", 0) for r in successful_scans),
                "critical_vulnerabilities": sum(r.get("critical_vulnerabilities", 0) for r in successful_scans),
                "agreement_rate": agreement_rate if comparable_results else None
            },
            "detailed_results": results_summary
        }, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    print("\n✅ IHACPA v2.0 testing completed!")
    
    # Final validation message
    if ai_enabled:
        print(f"\n🎯 IHACPA v2.0 AI-Enhanced Testing Summary:")
        print(f"   • Scanned {len(successful_scans)} packages successfully")
        print(f"   • Found {sum(r.get('total_vulnerabilities', 0) for r in successful_scans)} vulnerabilities")
        print(f"   • AI analysis provided {sum(r.get('ai_enhanced_sources', 0) for r in successful_scans)} enhanced assessments")
        if comparable_results:
            print(f"   • {agreement_rate:.1f}% agreement with existing assessments")
    else:
        print(f"\n📊 IHACPA v2.0 Basic Testing Summary:")
        print(f"   • Scanned {len(successful_scans)} packages successfully")
        print(f"   • Found {sum(r.get('total_vulnerabilities', 0) for r in successful_scans)} vulnerabilities")
        print(f"   • Enable Azure OpenAI for AI-enhanced analysis")


async def main():
    """Main test function"""
    excel_file = "data/2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    
    # Check if file exists
    if not Path(excel_file).exists():
        print(f"❌ Excel file not found: {excel_file}")
        return
    
    # Run test with first 10 packages
    await test_real_packages(excel_file, limit=10)


if __name__ == "__main__":
    asyncio.run(main())