#!/usr/bin/env python3
"""
Demonstration of Enhanced Column Processing for IHACPA v2.0

This script demonstrates the new column processing functionality for columns E, F, K, L, M, W
that was implemented based on the old_files analysis and color definitions.
"""

import asyncio
import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config.config_manager import ConfigManager
from src.services.enhanced_excel_processor import EnhancedExcelProcessor
from src.integrations.column_processors import ColumnProcessors
from src.core.ai_analyzer import AIAnalyzer


async def demo_single_package(package_name: str, version: str = None):
    """Demonstrate enhanced column processing for a single package"""
    print(f"\n🔍 Demonstrating Enhanced Column Processing for: {package_name}")
    print("=" * 60)
    
    try:
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Initialize AI analyzer (using mock)
        ai_analyzer = AIAnalyzer(config.ai.__dict__)
        
        # Initialize column processors
        column_processors = ColumnProcessors(config, ai_analyzer)
        
        # Demonstrate each column function
        print("\n📅 Column E (date_published):")
        result_e = await column_processors.process_column_E_date_published(package_name, version or "1.0.0")
        print(f"   Value: {result_e['value']}")
        print(f"   Color: {result_e['color']}")
        print(f"   Note: {result_e['note']}")
        
        print("\n📦 Column F (latest_version):")
        result_f = await column_processors.process_column_F_latest_version(package_name, version or "1.0.0")
        print(f"   Value: {result_f['value']}")
        print(f"   Color: {result_f['color']}")
        print(f"   Note: {result_f['note']}")
        
        print("\n🐙 Column K (github_url):")
        result_k = await column_processors.process_column_K_github_url(package_name)
        print(f"   Value: {result_k['value']}")
        print(f"   Color: {result_k['color']}")
        print(f"   Note: {result_k['note']}")
        
        print("\n🔒 Column L (github_security_url):")
        github_url = result_k.get('hyperlink') or result_k.get('value')
        result_l = await column_processors.process_column_L_github_security_url(package_name, github_url)
        print(f"   Value: {result_l['value']}")
        print(f"   Color: {result_l['color']}")
        print(f"   Note: {result_l['note']}")
        
        print("\n🛡️ Column M (github_security_result) - AI/Browser/Sandbox Integration:")
        github_security_url = result_l.get('hyperlink') or result_l.get('value')
        result_m = await column_processors.process_column_M_github_security_result(
            package_name, version or "1.0.0", github_security_url
        )
        print(f"   Value: {result_m['value']}")
        print(f"   Color: {result_m['color']}")
        print(f"   Note: {result_m['note']}")
        print(f"   Analysis Method: {result_m.get('analysis_method', 'N/A')}")
        print(f"   AI Enhanced: {result_m.get('ai_enhanced', False)}")
        
        print("\n💡 Column W (recommendation):")
        # Mock vulnerability results for demonstration
        vulnerability_results = {
            'critical_vulnerabilities': 0,
            'high_risk_vulnerabilities': 1,
            'medium_risk_vulnerabilities': 2,
            'low_risk_vulnerabilities': 1,
            'total_vulnerabilities': 4,
            'nvd_results': 'NVD: 2 vulnerabilities found',
            'mitre_results': 'MITRE: 1 vulnerability found',
            'snyk_results': 'SNYK: 1 vulnerability found',
            'github_results': result_m['value']
        }
        
        result_w = await column_processors.process_column_W_recommendation(package_name, vulnerability_results)
        print(f"   Value: {result_w['value']}")
        print(f"   Color: {result_w['color']}")
        print(f"   Note: {result_w['note']}")
        print(f"   Risk Score: {result_w.get('risk_score', 'N/A')}")
        
        print("\n✅ Enhanced Column Processing Demo Completed!")
        
        # Cleanup
        await column_processors.close()
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        logging.error(f"Demo failed: {e}", exc_info=True)


async def demo_excel_processing(excel_file: str = None):
    """Demonstrate enhanced Excel processing"""
    if not excel_file:
        excel_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    
    print(f"\n📊 Demonstrating Enhanced Excel Processing")
    print("=" * 60)
    
    try:
        # Check if file exists
        if not Path(excel_file).exists():
            print(f"❌ Excel file not found: {excel_file}")
            print("   Please provide a valid Excel file path")
            return
        
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Initialize enhanced Excel processor
        enhanced_processor = EnhancedExcelProcessor(config)
        
        print(f"📁 Processing Excel file: {excel_file}")
        print("🚀 Starting enhanced processing (this may take a while)...")
        
        # Process the Excel file with enhanced columns
        results = await enhanced_processor.process_excel_file(excel_file)
        
        print("\n📈 Processing Results:")
        print(f"   Input File: {results['input_file']}")
        print(f"   Output File: {results['output_file']}")
        print(f"   Packages Processed: {results['packages_processed']}")
        print(f"   Packages Failed: {results['packages_failed']}")
        print(f"   Columns Updated: {', '.join(results['columns_updated'])}")
        print(f"   Enhanced Columns: {', '.join(results['enhanced_columns'])}")
        print(f"   AI Enhanced: {results['ai_enhanced']}")
        print(f"   Processing Time: {results['processing_time']:.2f} seconds")
        
        print(f"\n✅ Enhanced Excel processing completed!")
        print(f"📝 Output saved to: {results['output_file']}")
        
        # Cleanup
        await enhanced_processor.cleanup()
        
    except Exception as e:
        print(f"❌ Excel processing failed: {e}")
        logging.error(f"Excel processing failed: {e}", exc_info=True)


def print_color_definitions():
    """Print the color definitions used in Excel formatting"""
    print("\n🎨 Color Definitions for Excel Formatting")
    print("=" * 50)
    
    colors = {
        'updated': 'Light Blue (#E6F3FF) - Updated/modified data',
        'new_data': 'Light Green (#E6FFE6) - New data or no issues found',
        'security_risk': 'Light Red (#FFE6E6) - Security vulnerabilities found',
        'version_update': 'Light Orange (#FFF0E6) - Version updates needed',
        'ai_enhanced': 'Light Purple (#F0E6FF) - AI-enhanced results',
        'critical': 'Red (#FF4444) - Critical security issues',
        'high_risk': 'Light Red (#FF8888) - High-risk vulnerabilities'
    }
    
    for color_name, description in colors.items():
        print(f"   🔸 {color_name}: {description}")


async def main():
    """Main demonstration function"""
    print("🎉 IHACPA v2.0 Enhanced Column Processing Demonstration")
    print("=" * 70)
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Print color definitions
    print_color_definitions()
    
    # Demo 1: Single package processing
    print(f"\n{'='*70}")
    print("DEMO 1: Single Package Enhanced Column Processing")
    print(f"{'='*70}")
    
    demo_packages = [
        ("requests", "2.28.0"),
        ("numpy", "1.21.0"),
        ("flask", "2.0.1")
    ]
    
    for package_name, version in demo_packages:
        await demo_single_package(package_name, version)
        await asyncio.sleep(1)  # Small delay between packages
    
    # Demo 2: Excel file processing (if file exists)
    print(f"\n{'='*70}")
    print("DEMO 2: Enhanced Excel File Processing")
    print(f"{'='*70}")
    
    excel_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    if Path(excel_file).exists():
        print(f"📊 Excel file found: {excel_file}")
        response = input("Do you want to run enhanced Excel processing? (y/N): ").strip().lower()
        if response == 'y':
            await demo_excel_processing(excel_file)
        else:
            print("📋 Skipping Excel processing demo")
    else:
        print(f"📋 Excel file not found: {excel_file}")
        print("   To run Excel processing demo, place your Excel file in the current directory")
    
    print(f"\n{'='*70}")
    print("✅ IHACPA v2.0 Enhanced Column Processing Demonstration Complete!")
    print(f"{'='*70}")
    
    print("\n📚 Summary of Implemented Features:")
    print("   ✅ Column E: Publication date extraction from PyPI")
    print("   ✅ Column F: Latest version comparison with current")
    print("   ✅ Column K: GitHub repository URL extraction")
    print("   ✅ Column L: GitHub Security Advisories URL generation")
    print("   ✅ Column M: GitHub security analysis with AI/Browser/Sandbox integration")
    print("   ✅ Column W: IHACPA recommendation generation")
    print("   ✅ Color-coded Excel formatting based on old_files definitions")
    print("   ✅ AI enhancement integration (with mock fallback)")
    print("   ✅ Browser automation for web-based security analysis")


if __name__ == "__main__":
    asyncio.run(main())