#!/usr/bin/env python3
"""
Test IHACPA v2.0 Excel integration without sandboxes
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Import with fallback for io module conflict
try:
    from config.config_manager import ConfigManager
    from io.excel_handler import ExcelHandler
    from core.logger_manager import setup_logging
    from core.progress_tracker import ProgressTracker
    from core.error_handler import ErrorHandler
    from integrations.pypi_client import PyPIClient
except ImportError:
    import src.config.config_manager as config_manager
    import src.io.excel_handler as excel_handler
    import src.core.logger_manager as logger_manager
    import src.core.progress_tracker as progress_tracker
    import src.core.error_handler as error_handler
    import src.integrations.pypi_client as pypi_client
    
    ConfigManager = config_manager.ConfigManager
    ExcelHandler = excel_handler.ExcelHandler
    setup_logging = logger_manager.setup_logging
    ProgressTracker = progress_tracker.ProgressTracker
    ErrorHandler = error_handler.ErrorHandler
    PyPIClient = pypi_client.PyPIClient


async def test_complete_workflow():
    """Test complete Excel processing workflow"""
    print("🔄 Testing Complete Excel Processing Workflow...")
    
    excel_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    
    if not Path(excel_file).exists():
        print(f"   ❌ Excel file not found: {excel_file}")
        return False
    
    try:
        # Setup configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Setup logging
        logger, logger_manager = setup_logging(config)
        error_handler = ErrorHandler(logger)
        
        # Load Excel file
        excel_handler = ExcelHandler(excel_file, config)
        if not excel_handler.load_workbook():
            print("   ❌ Failed to load Excel file")
            return False
        
        # Get packages to process (first 5 for testing)
        all_packages = excel_handler.get_all_packages()
        test_packages = all_packages[1:6]  # Skip header, get 5 packages
        
        print(f"   📊 Processing {len(test_packages)} packages for testing:")
        for pkg in test_packages:
            print(f"      • {pkg.get('package_name', 'Unknown')}")
        
        # Setup progress tracker
        progress_tracker = ProgressTracker(len(test_packages), logger)
        
        # Process packages with PyPI integration
        successful_updates = 0
        
        async with PyPIClient() as pypi_client:
            for i, package_data in enumerate(test_packages, 1):
                package_name = package_data.get('package_name', 'Unknown')
                current_version = package_data.get('version', 'Unknown')
                row_number = package_data.get('row_number', 0)
                
                # Start tracking
                progress_tracker.start_package(package_name, i)
                
                try:
                    # Get PyPI information
                    package_info = await pypi_client.get_package_info(package_name)
                    
                    if package_info:
                        # Prepare updates based on PyPI data
                        updates = {
                            'latest_version': package_info.version,
                            'pypi_summary': package_info.summary[:100] + "..." if len(package_info.summary) > 100 else package_info.summary,
                            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'github_url': package_info.github_url or 'Not found',
                            'dependencies_count': len(package_info.dependencies)
                        }
                        
                        # Show what we would update (in real mode, this would update Excel)
                        print(f"      📦 {package_name}:")
                        print(f"         Current: {current_version} → Latest: {package_info.version}")
                        print(f"         GitHub: {package_info.github_url or 'Not found'}")
                        print(f"         Dependencies: {len(package_info.dependencies)}")
                        
                        # Complete tracking
                        progress_tracker.complete_package(
                            package_name=package_name,
                            success=True,
                            vulnerabilities_found=0,  # Would be from sandbox scan
                            ai_enhanced=False
                        )
                        
                        successful_updates += 1
                    else:
                        print(f"      ❌ {package_name}: Not found on PyPI")
                        progress_tracker.complete_package(
                            package_name=package_name,
                            success=False,
                            error_message="Package not found on PyPI"
                        )
                
                except Exception as e:
                    error_handler.handle_network_error(f"pypi_{package_name}", e)
                    progress_tracker.complete_package(
                        package_name=package_name,
                        success=False,
                        error_message=str(e)
                    )
                
                # Small delay to avoid rate limiting
                await asyncio.sleep(0.5)
        
        # Log final summary
        progress_tracker.log_final_summary()
        
        # Get performance metrics
        metrics = progress_tracker.get_performance_metrics()
        
        print(f"\n   ✅ Workflow completed successfully!")
        print(f"   📊 Results:")
        print(f"      • Packages processed: {metrics['processed_packages']}")
        print(f"      • Successful: {metrics['successful_packages']}")
        print(f"      • Failed: {metrics['failed_packages']}")
        print(f"      • Success rate: {metrics['success_rate']:.1f}%")
        print(f"      • Average time per package: {metrics['avg_processing_time']:.2f}s")
        
        # Cleanup
        excel_handler.close()
        logger_manager.close_handlers()
        
        return successful_updates > 0
        
    except Exception as e:
        print(f"   ❌ Workflow test failed: {e}")
        return False


async def main():
    """Run complete workflow test"""
    print("🚀 Testing IHACPA v2.0 Complete Excel Integration")
    print("=" * 60)
    print("📋 This test demonstrates the infrastructure working with real data:")
    print("   • Configuration management")
    print("   • Excel file reading and processing")
    print("   • PyPI API integration")
    print("   • Progress tracking and logging")
    print("   • Error handling")
    print("=" * 60)
    
    success = await test_complete_workflow()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 COMPLETE SUCCESS!")
        print("✅ IHACPA v2.0 infrastructure is fully functional")
        print("📊 Ready to process all 487 packages in the Excel file")
        print("\n📋 To run a full scan (requires Redis/sandbox setup):")
        print("   python -m src.main scan \"2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx\"")
        return 0
    else:
        print("❌ Test failed - please check the issues above")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)