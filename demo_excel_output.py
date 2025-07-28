#!/usr/bin/env python3
"""
Demo IHACPA v2.0 Excel Output - Shows actual Excel file modifications
"""

import asyncio
import sys
import shutil
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import with fallback for io module conflict
try:
    from config.config_manager import ConfigManager
    from io.excel_handler import ExcelHandler
    from core.logger_manager import setup_logging
    from integrations.pypi_client import PyPIClient
except ImportError:
    import src.config.config_manager as config_manager
    import src.io.excel_handler as excel_handler
    import src.core.logger_manager as logger_manager
    import src.integrations.pypi_client as pypi_client
    
    ConfigManager = config_manager.ConfigManager
    ExcelHandler = excel_handler.ExcelHandler
    setup_logging = logger_manager.setup_logging
    PyPIClient = pypi_client.PyPIClient


async def create_demo_excel_output():
    """Create a demo Excel file showing IHACPA v2.0 output format"""
    print("📊 Creating Demo Excel Output...")
    
    original_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    demo_file = "IHACPA_v2_Demo_Output.xlsx"
    
    if not Path(original_file).exists():
        print(f"   ❌ Original Excel file not found: {original_file}")
        return False
    
    try:
        # Copy original file to create demo output
        shutil.copy2(original_file, demo_file)
        print(f"   ✅ Created demo file: {demo_file}")
        
        # Setup configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Setup logging
        logger, logger_manager = setup_logging(config)
        
        # Load Excel file for modification
        excel_handler = ExcelHandler(demo_file, config)
        if not excel_handler.load_workbook():
            print("   ❌ Failed to load demo Excel file")
            return False
        
        print("   📝 Processing first 5 packages with real PyPI data...")
        
        # Get packages to process (skip header, get first 5 real packages)
        all_packages = excel_handler.get_all_packages()
        test_packages = all_packages[1:6]  # Skip header row
        
        # Process packages and update Excel
        async with PyPIClient() as pypi_client:
            for i, package_data in enumerate(test_packages):
                package_name = package_data.get('package_name', 'Unknown')
                current_version = package_data.get('version', 'Unknown')
                row_number = package_data.get('row_number', 0)
                
                print(f"      📦 Processing {package_name}...")
                
                try:
                    # Get PyPI information
                    package_info = await pypi_client.get_package_info(package_name)
                    
                    if package_info:
                        # Simulate vulnerability scan results
                        mock_vulnerabilities = {
                            'nvd_result': f"NVD: {i} vulnerabilities found (AI Enhanced)",
                            'mitre_result': f"MITRE: {i + 1} vulnerabilities found", 
                            'snyk_result': f"SNYK: {max(0, i - 1)} vulnerabilities found (AI Enhanced)",
                            'exploit_db_result': f"EXPLOIT-DB: {max(0, i - 2)} vulnerabilities found"
                        }
                        
                        # Prepare comprehensive updates
                        updates = {
                            # Version information
                            'latest_version': package_info.version,
                            'version_status': 'OUTDATED' if package_info.version != current_version else 'CURRENT',
                            
                            # Vulnerability results (simulated)
                            **mock_vulnerabilities,
                            
                            # Package information
                            'pypi_summary': package_info.summary[:150] + "..." if len(package_info.summary) > 150 else package_info.summary,
                            'github_url': package_info.github_url or 'Not found',
                            'dependencies_count': len(package_info.dependencies),
                            'last_release_date': package_info.latest_release_date.strftime('%Y-%m-%d') if package_info.latest_release_date else 'Unknown',
                            
                            # IHACPA analysis
                            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'scan_status': 'COMPLETED',
                            'total_vulnerabilities': sum([i, i + 1, max(0, i - 1), max(0, i - 2)]),
                            
                            # AI recommendation
                            'ai_recommendation': _generate_demo_recommendation(i, package_info.version, current_version)
                        }
                        
                        # Update Excel with color coding
                        excel_handler.update_package_data(row_number, updates)
                        
                        print(f"         ✅ Updated with {updates['total_vulnerabilities']} total vulnerabilities")
                        
                    else:
                        # Handle package not found
                        updates = {
                            'scan_status': 'ERROR - Package not found on PyPI',
                            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'ai_recommendation': 'INVESTIGATE - Package may be deprecated'
                        }
                        excel_handler.update_package_data(row_number, updates)
                        print(f"         ❌ Package not found on PyPI")
                
                except Exception as e:
                    # Handle errors
                    error_updates = {
                        'scan_status': f'ERROR - {str(e)[:50]}...',
                        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'ai_recommendation': 'RETRY - Scan failed'
                    }
                    excel_handler.update_package_data(row_number, error_updates)
                    print(f"         ⚠️  Error: {e}")
                
                # Small delay to avoid rate limiting
                await asyncio.sleep(0.5)
        
        # Save the updated Excel file
        if excel_handler.save_workbook():
            print(f"   ✅ Demo Excel file saved successfully!")
            
            # Show what was updated
            changes_summary = excel_handler.get_changes_summary()
            print(f"   📊 Changes made:")
            print(f"      • Rows updated: {changes_summary['rows_updated']}")
            print(f"      • Cells modified: {changes_summary['cells_modified']}")
            print(f"      • Timestamp: {changes_summary['last_update']}")
            
            # Export to additional formats
            print(f"   📄 Exporting to additional formats...")
            
            # Export to CSV
            csv_file = demo_file.replace('.xlsx', '.csv')
            excel_handler.export_to_csv(csv_file)
            print(f"      ✅ CSV export: {csv_file}")
            
            # Export to JSON
            json_file = demo_file.replace('.xlsx', '.json')
            excel_handler.export_to_json(json_file)
            print(f"      ✅ JSON export: {json_file}")
            
        else:
            print("   ❌ Failed to save Excel file")
            return False
        
        # Cleanup
        excel_handler.close()
        logger_manager.close_handlers()
        
        return True
        
    except Exception as e:
        print(f"   ❌ Demo creation failed: {e}")
        return False


def _generate_demo_recommendation(index, latest_version, current_version):
    """Generate demo AI recommendation based on package analysis"""
    if index == 0:
        return "AI: LOW RISK - Monitor for updates"
    elif index == 1:
        return "AI: MODERATE RISK - Plan update soon"
    elif index == 2:
        return "AI: HIGH RISK - URGENT UPDATE RECOMMENDED"
    elif index == 3:
        return "AI: CRITICAL - IMMEDIATE ACTION REQUIRED"
    else:
        return "AI: PROCEED - No significant risks detected"


async def show_excel_structure():
    """Show the Excel file structure and column mappings"""
    print("\n📋 IHACPA v2.0 Excel Output Structure:")
    print("=" * 80)
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Show column mappings
        column_mapping = config.excel.column_mapping
        print("📊 Column Mappings:")
        for field, column in column_mapping.items():
            print(f"   {column:2d}. {field}")
        
        print(f"\n📝 Additional Output Columns (dynamically added):")
        print("   • latest_version - Latest version from PyPI")
        print("   • version_status - CURRENT/OUTDATED status") 
        print("   • nvd_result - NVD vulnerability scan results")
        print("   • mitre_result - MITRE vulnerability scan results")
        print("   • snyk_result - Snyk vulnerability scan results")
        print("   • exploit_db_result - Exploit-DB scan results")
        print("   • pypi_summary - Package description from PyPI")
        print("   • github_url - GitHub repository URL")
        print("   • dependencies_count - Number of dependencies")
        print("   • last_release_date - Date of last release")
        print("   • scan_date - When the scan was performed")
        print("   • scan_status - COMPLETED/ERROR/IN_PROGRESS")
        print("   • total_vulnerabilities - Sum of all vulnerabilities found")
        print("   • ai_recommendation - AI-generated security recommendation")
        
        print(f"\n🎨 Color Coding:")
        print("   • 🟦 Blue: Updated/modified cells")
        print("   • 🟥 Red: High-risk packages with vulnerabilities")
        print("   • 🟪 Purple: AI-enhanced results")
        print("   • 🟨 Yellow: Warnings or outdated packages")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Failed to show structure: {e}")
        return False


async def main():
    """Create demo Excel output"""
    print("🚀 IHACPA v2.0 Excel Output Demo")
    print("=" * 60)
    print("📋 This demo will:")
    print("   • Create a copy of your Excel file")
    print("   • Process 5 packages with real PyPI data")
    print("   • Add vulnerability scan results (simulated)")
    print("   • Apply color coding and formatting")
    print("   • Export to CSV and JSON formats")
    print("   • Show you the complete output structure")
    print("=" * 60)
    
    # Show Excel structure first
    structure_success = await show_excel_structure()
    
    # Create demo output
    demo_success = await create_demo_excel_output()
    
    print("\n" + "=" * 60)
    print("📊 DEMO RESULTS")
    print("=" * 60)
    
    if demo_success:
        print("🎉 SUCCESS! Demo Excel output created successfully!")
        print("\n📁 Files created:")
        print("   • IHACPA_v2_Demo_Output.xlsx - Main Excel output with updates")
        print("   • IHACPA_v2_Demo_Output.csv - CSV export for analysis")
        print("   • IHACPA_v2_Demo_Output.json - JSON export for integration")
        
        print("\n📊 Open IHACPA_v2_Demo_Output.xlsx to see:")
        print("   ✅ Updated package information")
        print("   ✅ Vulnerability scan results") 
        print("   ✅ AI-generated recommendations")
        print("   ✅ Color-coded cells for easy identification")
        print("   ✅ Version comparison (current vs latest)")
        print("   ✅ GitHub repository links")
        print("   ✅ Dependency counts")
        print("   ✅ Scan timestamps")
        
        print(f"\n🚀 Ready to process all 487 packages!")
        return 0
    else:
        print("❌ Demo creation failed - please check the issues above")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)