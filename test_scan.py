#!/usr/bin/env python3
"""
Test IHACPA v2.0 scanning functionality with real Excel file
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import with fallback for io module conflict
try:
    from config.config_manager import ConfigManager
    from io.excel_handler import ExcelHandler
    from core.logger_manager import setup_logging
    from core.app_controller import AppController
except ImportError:
    import src.config.config_manager as config_manager
    import src.io.excel_handler as excel_handler
    import src.core.logger_manager as logger_manager
    import src.core.app_controller as app_controller
    
    ConfigManager = config_manager.ConfigManager
    ExcelHandler = excel_handler.ExcelHandler
    setup_logging = logger_manager.setup_logging
    AppController = app_controller.AppController


async def test_excel_reading():
    """Test reading the actual Excel file"""
    print("📊 Testing Excel file reading...")
    
    excel_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    
    if not Path(excel_file).exists():
        print(f"   ❌ Excel file not found: {excel_file}")
        return False
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        excel_handler = ExcelHandler(excel_file, config)
        
        if excel_handler.load_workbook():
            print("   ✅ Excel file loaded successfully")
            
            # Get package count
            package_count = excel_handler.get_package_count()
            print(f"   📦 Total packages found: {package_count}")
            
            # Get first 10 packages to show
            packages = excel_handler.get_all_packages()[:10]
            print("   📋 First 10 packages:")
            for i, pkg in enumerate(packages, 1):
                name = pkg.get('package_name', 'Unknown')
                version = pkg.get('version', 'No version')
                print(f"      {i:2d}. {name:<20} - {version}")
            
            excel_handler.close()
            return True, package_count
        else:
            print("   ❌ Failed to load Excel file")
            return False, 0
            
    except Exception as e:
        print(f"   ❌ Excel reading test failed: {e}")
        return False, 0


async def test_dry_run_scan():
    """Test a dry-run scan with a few packages"""
    print("\n🔍 Testing dry-run scan with first 3 packages...")
    
    excel_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Disable AI for faster testing (optional)
        config.ai.enabled = False
        
        # Create app controller in dry-run mode
        app_controller = AppController(config, dry_run=True)
        
        # Setup
        setup_success = await app_controller.setup(input_file=excel_file)
        if not setup_success:
            print("   ❌ Setup failed")
            return False
        
        print("   ✅ App controller setup successful")
        
        # Scan first 3 packages only (rows 3-5, since header is row 2)
        scan_success = await app_controller.scan_packages(
            start_row=3,
            end_row=5
        )
        
        if scan_success:
            print("   ✅ Dry-run scan completed successfully")
            
            # Get results summary
            summary = app_controller.get_results_summary()
            print(f"   📊 Packages processed: {summary['packages_processed']}")
            print(f"   ✅ Successful: {summary['packages_successful']}")
            print(f"   ❌ Failed: {summary['packages_failed']}")
            print(f"   📈 Success rate: {summary['success_rate']:.1f}%")
            
        else:
            print("   ❌ Scan failed")
            
        # Cleanup
        await app_controller.cleanup()
        
        return scan_success
        
    except Exception as e:
        print(f"   ❌ Dry-run scan test failed: {e}")
        return False


async def main():
    """Run scan tests"""
    print("🚀 Testing IHACPA v2.0 with Real Excel File")
    print("=" * 60)
    
    # Test 1: Excel file reading
    excel_success, package_count = await test_excel_reading()
    
    if not excel_success:
        print("\n❌ Excel file test failed. Cannot proceed with scan tests.")
        return 1
    
    # Test 2: Dry-run scan (only if Excel reading worked)
    if package_count > 0:
        scan_success = await test_dry_run_scan()
        
        print("\n" + "=" * 60)
        print("📊 SCAN TEST RESULTS")
        print("=" * 60)
        print(f"Excel Reading: {'✅ PASSED' if excel_success else '❌ FAILED'}")
        print(f"Dry-run Scan:  {'✅ PASSED' if scan_success else '❌ FAILED'}")
        print(f"Total Packages: {package_count}")
        
        if excel_success and scan_success:
            print("\n🎉 All scan tests passed! IHACPA v2.0 is ready for use.")
            print(f"\n📋 To scan all {package_count} packages, run:")
            print("   python -m src.main scan \"2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx\"")
            return 0
        else:
            print("\n⚠️  Some tests failed. Please check the issues above.")
            return 1
    else:
        print("\n⚠️  No packages found in Excel file.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)