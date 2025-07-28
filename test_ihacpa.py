#!/usr/bin/env python3
"""
Test script for IHACPA v2.0 updated system
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from config.config_manager import ConfigManager
    from io.excel_handler import ExcelHandler
    from core.logger_manager import setup_logging
    from core.progress_tracker import ProgressTracker
    from core.error_handler import ErrorHandler
    from integrations.pypi_client import PyPIClient
    from utils.version_utils import VersionUtils
except ImportError as e:
    print(f"Import error: {e}")
    print("This might be due to a conflict with Python's built-in 'io' module")
    print("Let me try alternative imports...")
    
    import src.config.config_manager as config_manager
    import src.io.excel_handler as excel_handler
    import src.core.logger_manager as logger_manager
    import src.core.progress_tracker as progress_tracker
    import src.core.error_handler as error_handler
    import src.integrations.pypi_client as pypi_client
    import src.utils.version_utils as version_utils
    
    ConfigManager = config_manager.ConfigManager
    ExcelHandler = excel_handler.ExcelHandler
    setup_logging = logger_manager.setup_logging
    ProgressTracker = progress_tracker.ProgressTracker
    ErrorHandler = error_handler.ErrorHandler
    PyPIClient = pypi_client.PyPIClient
    VersionUtils = version_utils.VersionUtils


async def test_configuration_system():
    """Test configuration management"""
    print("🔧 Testing Configuration Management System...")
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        print(f"   ✅ Configuration loaded successfully")
        print(f"   📊 App version: {config.app.version}")
        print(f"   🤖 AI enabled: {config.ai.enabled}")
        print(f"   📝 Logging level: {config.logging.level}")
        
        return True
    except Exception as e:
        print(f"   ❌ Configuration test failed: {e}")
        return False


async def test_excel_handler():
    """Test Excel handling"""
    print("\n📊 Testing Excel Handler...")
    
    excel_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    
    if not Path(excel_file).exists():
        print(f"   ⚠️  Excel file not found: {excel_file}")
        return False
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        excel_handler = ExcelHandler(excel_file, config)
        
        if excel_handler.load_workbook():
            print("   ✅ Excel file loaded successfully")
            
            # Validate structure
            is_valid, errors = excel_handler.validate_file_structure()
            if is_valid:
                package_count = excel_handler.get_package_count()
                print(f"   📦 Found {package_count} packages")
                
                # Get first few packages
                packages = excel_handler.get_all_packages()[:3]
                for pkg in packages:
                    print(f"      • {pkg.get('package_name', 'Unknown')} - {pkg.get('version', 'No version')}")
                
                excel_handler.close()
                return True
            else:
                print("   ❌ Excel structure validation failed:")
                for error in errors:
                    print(f"      • {error}")
                excel_handler.close()
                return False
        else:
            print("   ❌ Failed to load Excel file")
            return False
            
    except Exception as e:
        print(f"   ❌ Excel handler test failed: {e}")
        return False


async def test_logging_system():
    """Test logging infrastructure"""
    print("\n📝 Testing Logging System...")
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        logger, logger_manager = setup_logging(config)
        
        # Test different log levels
        logger.debug("Debug message test")
        logger.info("Info message test")
        logger.warning("Warning message test")
        logger.error("Error message test")
        
        print("   ✅ Logging system initialized successfully")
        print(f"   📁 Log directory: {config.logging.log_directory}")
        
        # Close handlers
        logger_manager.close_handlers()
        return True
        
    except Exception as e:
        print(f"   ❌ Logging system test failed: {e}")
        return False


async def test_progress_tracker():
    """Test progress tracking"""
    print("\n📈 Testing Progress Tracker...")
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        logger, logger_manager = setup_logging(config)
        
        # Create progress tracker for 5 packages
        tracker = ProgressTracker(5, logger)
        
        # Simulate processing
        for i in range(1, 6):
            package_name = f"test-package-{i}"
            tracker.start_package(package_name, i)
            
            # Simulate some work
            await asyncio.sleep(0.1)
            
            # Complete package
            tracker.complete_package(
                package_name=package_name,
                success=True,
                vulnerabilities_found=i * 2,
                ai_enhanced=i % 2 == 0
            )
        
        # Get final metrics
        metrics = tracker.get_performance_metrics()
        print(f"   ✅ Progress tracking completed")
        print(f"   📊 Processed: {metrics['processed_packages']}")
        # Use the correct key name
        avg_time_key = 'avg_processing_time' if 'avg_processing_time' in metrics else 'average_processing_time'
        if avg_time_key in metrics:
            print(f"   ⏱️  Average time: {metrics[avg_time_key]:.2f}s")
        else:
            print(f"   ⏱️  Available metrics: {list(metrics.keys())}")
        
        logger_manager.close_handlers()
        return True
        
    except Exception as e:
        print(f"   ❌ Progress tracker test failed: {e}")
        return False


async def test_error_handler():
    """Test error handling"""
    print("\n🚨 Testing Error Handler...")
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        logger, logger_manager = setup_logging(config)
        
        error_handler = ErrorHandler(logger)
        
        # Test different error types
        error_handler.handle_excel_error("test", Exception("Test Excel error"))
        error_handler.handle_network_error("test_url", Exception("Test network error"))
        error_handler.handle_validation_error("test_field", "Test validation error")
        
        # Get error summary
        summary = error_handler.get_error_summary()
        print(f"   ✅ Error handler working correctly")
        print(f"   📊 Total errors logged: {summary['total_errors']}")
        
        logger_manager.close_handlers()
        return True
        
    except Exception as e:
        print(f"   ❌ Error handler test failed: {e}")
        return False


async def test_pypi_integration():
    """Test PyPI integration"""
    print("\n🐍 Testing PyPI Integration...")
    
    try:
        async with PyPIClient() as client:
            # Test with a well-known package
            package_info = await client.get_package_info("requests")
            
            if package_info:
                print(f"   ✅ PyPI client working correctly")
                print(f"   📦 Package: {package_info.name}")
                print(f"   🔢 Version: {package_info.version}")
                print(f"   📝 Summary: {package_info.summary[:100]}...")
                
                # Test version comparison
                comparison = await client.compare_versions("requests", "2.25.0")
                if comparison:
                    print(f"   🔄 Version comparison: 2.25.0 vs {comparison['latest_version']}")
                
                return True
            else:
                print("   ❌ Failed to get package info")
                return False
                
    except Exception as e:
        print(f"   ❌ PyPI integration test failed: {e}")
        return False


async def test_version_utils():
    """Test version utilities"""
    print("\n🔢 Testing Version Utils...")
    
    try:
        # Test version comparison
        result = VersionUtils.compare_versions("1.0.0", "1.2.0")
        print(f"   ✅ Version comparison working")
        print(f"   📊 1.0.0 vs 1.2.0: outdated={result['is_outdated']}")
        
        # Test version parsing
        parsed = VersionUtils.parse_version_string("2.1.3")
        if parsed:
            print(f"   🔍 Parsed version: {parsed['major']}.{parsed['minor']}.{parsed['micro']}")
        
        # Test latest stable version
        versions = ["1.0.0", "1.1.0", "1.2.0", "2.0.0a1", "1.1.5"]
        latest_stable = VersionUtils.get_latest_stable_version(versions)
        print(f"   🎯 Latest stable from {versions}: {latest_stable}")
        
        return True
        
    except Exception as e:
        print(f"   ❌ Version utils test failed: {e}")
        return False


async def main():
    """Run all tests"""
    print("🚀 Starting IHACPA v2.0 Infrastructure Tests")
    print("=" * 60)
    
    tests = [
        ("Configuration System", test_configuration_system),
        ("Excel Handler", test_excel_handler),
        ("Logging System", test_logging_system),
        ("Progress Tracker", test_progress_tracker),
        ("Error Handler", test_error_handler),
        ("PyPI Integration", test_pypi_integration),
        ("Version Utils", test_version_utils),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"   ❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    failed = 0
    
    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status:<10} {test_name}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print("-" * 60)
    print(f"Total Tests: {len(results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(results)*100):.1f}%")
    
    if failed == 0:
        print("\n🎉 All tests passed! IHACPA v2.0 infrastructure is working correctly.")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please check the issues above.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)