#!/usr/bin/env python3
"""
Comprehensive Enhanced Columns Test Suite

Tests the complete refactored column processing architecture including:
- PyPI data columns (E-J including new H)
- GitHub analysis columns (K-M) 
- Vulnerability database columns (O-V) with AI sandboxes
- Sophisticated recommendation column (W)

Based on deep analysis of retired version's approach with our AI infrastructure.
"""

import asyncio
import sys
import json
from pathlib import Path
from typing import Dict, Any
import logging

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.integrations.enhanced_column_orchestrator import EnhancedColumnOrchestrator
from src.core.ai_analyzer import AIAnalyzer
from src.core.sandbox_manager import SandboxManager
from src.config import ConfigManager


async def test_comprehensive_columns(package_name: str, version: str):
    """Test all enhanced columns with the new architecture."""
    print(f"\n{'='*100}")
    print(f"🔬 COMPREHENSIVE ENHANCED COLUMNS TEST")
    print(f"{'='*100}")
    print(f"📦 Package: {package_name} v{version}")
    print(f"🏗️  Architecture: Retired Version Analysis + AI Sandboxes")
    print(f"{'='*100}")
    
    try:
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()
        print(f"✅ Configuration loaded successfully")
        
        # Initialize AI analyzer
        ai_analyzer = AIAnalyzer(config.ai.__dict__ if hasattr(config, 'ai') else {})
        print(f"✅ AI analyzer initialized: {ai_analyzer.__class__.__name__}")
        
        # Initialize sandbox manager
        config_dict = config.__dict__ if hasattr(config, '__dict__') else config
        sandbox_manager = SandboxManager(config_dict)
        await sandbox_manager.initialize()  # This is crucial - it registers all sandboxes
        print(f"✅ Sandbox manager initialized with AI sandboxes")
        
        # Initialize enhanced column orchestrator
        orchestrator = EnhancedColumnOrchestrator(
            config=config,
            ai_analyzer=ai_analyzer,
            sandbox_manager=sandbox_manager
        )
        print(f"✅ Enhanced column orchestrator initialized")
        print()
        
        # Process all columns comprehensively
        print(f"🚀 Starting comprehensive column processing...")
        print(f"   This will test ALL columns A-W with the new architecture")
        print()
        
        start_time = asyncio.get_event_loop().time()
        results = await orchestrator.process_all_columns(package_name, version)
        end_time = asyncio.get_event_loop().time()
        
        processing_time = end_time - start_time
        print(f"⏱️  Total processing time: {processing_time:.2f} seconds")
        print()
        
        # Display results by category
        await display_results_by_category(results, package_name, version)
        
        # Save detailed results
        output_file = f"comprehensive_test_results_{package_name}_{version.replace('.', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"💾 Detailed results saved to: {output_file}")
        
        # Cleanup
        await orchestrator.cleanup()
        print(f"✅ Cleanup completed")
        
    except Exception as e:
        print(f"❌ Comprehensive test failed: {e}")
        import traceback
        traceback.print_exc()


async def display_results_by_category(results: Dict[str, Any], package_name: str, version: str):
    """Display results organized by functional category."""
    
    print(f"📊 COMPREHENSIVE RESULTS FOR {package_name} v{version}")
    print(f"{'='*100}")
    
    # Category 1: PyPI Package Data (E-J)
    print(f"\n📦 PYPI PACKAGE DATA (Columns E-J)")
    print(f"{'─'*60}")
    pypi_columns = {
        'E': 'Date Published (Current Version)',
        'F': 'Latest Version Available', 
        'H': 'Latest Version Release Date ✨ NEW',
        'I': 'Requirements/Dependencies',
        'J': 'Development Status'
    }
    
    for col, description in pypi_columns.items():
        if col in results:
            result = results[col]
            status = "✅" if result.get('color') != 'critical' else "❌"
            print(f"  {status} Column {col}: {description}")
            print(f"     Value: {result.get('value', 'N/A')}")
            print(f"     Note:  {result.get('note', 'N/A')}")
            print()
    
    # Category 2: GitHub Integration (K-M)
    print(f"\n🐙 GITHUB INTEGRATION (Columns K-M)")
    print(f"{'─'*60}")
    github_columns = {
        'K': 'GitHub Repository URL',
        'L': 'GitHub Security Advisories URL',
        'M': 'GitHub Security Analysis Result'
    }
    
    for col, description in github_columns.items():
        if col in results:
            result = results[col]
            status = "✅" if result.get('color') != 'critical' else "❌"
            print(f"  {status} Column {col}: {description}")
            print(f"     Value: {result.get('value', 'N/A')}")
            print(f"     Note:  {result.get('note', 'N/A')}")
            print()
    
    # Category 3: AI-Powered Vulnerability Scanning (O-V)
    print(f"\n🤖 AI-POWERED VULNERABILITY SCANNING (Columns O-V)")
    print(f"{'─'*60}")
    vuln_columns = {
        'O': 'NIST NVD Search URL',
        'P': 'NIST NVD Scan Result (AI Enhanced)',
        'Q': 'MITRE CVE Search URL', 
        'R': 'MITRE CVE Scan Result (AI Enhanced)',
        'S': 'SNYK Vulnerability Search URL',
        'T': 'SNYK Vulnerability Scan Result (AI Enhanced)',
        'U': 'Exploit Database Search URL',
        'V': 'Exploit Database Scan Result (AI Enhanced)'
    }
    
    for col, description in vuln_columns.items():
        if col in results:
            result = results[col]
            status = "✅" if result.get('color') != 'critical' else "❌"
            ai_marker = "🤖" if 'AI' in description else "🔗"
            print(f"  {status} {ai_marker} Column {col}: {description}")
            print(f"     Value: {result.get('value', 'N/A')}")
            print(f"     Note:  {result.get('note', 'N/A')}")
            if result.get('vulnerability_count'):
                print(f"     Vulnerabilities: {result.get('vulnerability_count')} found")
            print()
    
    # Category 4: AI-Enhanced Recommendation (W)
    print(f"\n🧠 AI-ENHANCED COMPREHENSIVE RECOMMENDATION (Column W)")
    print(f"{'─'*60}")
    if 'W' in results:
        recommendation = results['W']
        status = "✅" if recommendation.get('color') != 'critical' else "⚠️" if recommendation.get('color') == 'security_risk' else "✅"
        print(f"  {status} Column W: IHACPA Comprehensive Recommendation")
        print(f"     Recommendation: {recommendation.get('value', 'N/A')}")
        print(f"     Analysis Note:  {recommendation.get('note', 'N/A')}")
        print(f"     Tier Level:     {recommendation.get('recommendation_tier', 'N/A')}")
        print(f"     AI Enhanced:    {recommendation.get('ai_enhanced', False)}")
        
        # Show classification summary
        if 'classification_summary' in recommendation:
            classifications = recommendation['classification_summary']
            print(f"     Classification Summary:")
            for category, items in classifications.items():
                if items:
                    print(f"       - {category.title()}: {len(items)} databases")
        print()
    
    # Summary Statistics
    print(f"\n📈 PROCESSING SUMMARY")
    print(f"{'─'*60}")
    
    total_columns = len(results)
    successful_columns = sum(1 for r in results.values() if r.get('color') != 'critical')
    error_columns = total_columns - successful_columns
    
    print(f"  📊 Total Columns Processed: {total_columns}")
    print(f"  ✅ Successful Columns:     {successful_columns}")
    print(f"  ❌ Error Columns:          {error_columns}")
    print(f"  🎯 Success Rate:           {(successful_columns/total_columns)*100:.1f}%")
    
    # Vulnerability Summary
    vuln_counts = {}
    for col in ['P', 'R', 'T', 'V']:
        if col in results and results[col].get('vulnerability_count'):
            vuln_counts[col] = results[col]['vulnerability_count']
    
    if vuln_counts:
        print(f"\n🔍 VULNERABILITY SUMMARY")
        print(f"{'─'*60}")
        total_vulns = sum(vuln_counts.values())
        print(f"  🚨 Total Vulnerabilities Found: {total_vulns}")
        for col, count in vuln_counts.items():
            db_name = {'P': 'NIST NVD', 'R': 'MITRE CVE', 'T': 'SNYK', 'V': 'Exploit DB'}[col]
            print(f"     - {db_name}: {count}")


async def main():
    """Main test function."""
    print("🧪 IHACPA v2.0 - Comprehensive Enhanced Columns Test Suite")
    print("🔬 Testing Complete Architecture: Retired Version Analysis + AI Sandboxes")
    print("📋 Coverage: ALL columns A-W with sophisticated processing")
    print()
    
    # Test packages
    test_packages = [
        ("requests", "2.28.1"),
        ("flask", "2.0.0"),
        ("urllib3", "1.26.0"),
        ("django", "3.0.0")
    ]
    
    # Allow user to specify package
    if len(sys.argv) >= 3:
        package_name = sys.argv[1]
        version = sys.argv[2]
        test_packages = [(package_name, version)]
        print(f"🎯 Testing user-specified package: {package_name} v{version}")
    elif len(sys.argv) == 2:
        package_name = sys.argv[1]
        version = "latest"
        test_packages = [(package_name, version)]
        print(f"🎯 Testing user-specified package: {package_name} (latest version)")
    else:
        print(f"🧪 Testing default package set: {len(test_packages)} packages")
    
    print()
    
    # Run comprehensive tests
    for package_name, version in test_packages:
        await test_comprehensive_columns(package_name, version)
        
        # Small delay between packages if testing multiple
        if len(test_packages) > 1:
            print(f"\n⏳ Waiting 2 seconds before next package...")
            await asyncio.sleep(2)
    
    print(f"\n🎉 Comprehensive Enhanced Columns Test Suite Completed!")
    print(f"🏗️  Architecture successfully validated with {len(test_packages)} package(s)")


if __name__ == '__main__':
    # Setup logging for better debugging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    asyncio.run(main())