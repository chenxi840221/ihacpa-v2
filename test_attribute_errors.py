#!/usr/bin/env python3
"""
Test for potential 'object has no attribute' errors with various data types
"""

import asyncio
from datetime import datetime

# Test various components that might receive non-string data
async def test_attribute_errors():
    """Test various components with different data types"""
    print("🔍 Testing for Potential Attribute Errors")
    print("=" * 60)
    
    # Test cases with different types that might come from Excel
    test_values = [
        ("string_version", "3.9.0", str),
        ("float_version", 3.9, float),
        ("int_version", 3, int),
        ("none_value", None, type(None)),
        ("datetime_value", datetime.now(), datetime),
        ("bool_value", True, bool),
    ]
    
    print("\n📋 Testing Excel Handler Color Type Determination:")
    from src.io.excel_handler import ExcelHandler
    
    # Create a mock config for testing
    class MockConfig:
        def __init__(self):
            pass
    
    handler = ExcelHandler("test.xlsx", MockConfig())
    
    # Test _determine_color_type with various field types
    for name, value, val_type in test_values:
        try:
            # Test with field as the non-string value
            result = handler._determine_color_type(value, "new_value", "old_value")
            print(f"  ✅ Field {name} ({val_type.__name__}): {result}")
        except Exception as e:
            print(f"  ❌ Field {name} ({val_type.__name__}): {e}")
    
    print("\n📋 Testing Enhanced Excel Processor:")
    # Test package processing with different version types
    test_packages = [
        {'package_name': 'test1', 'version': '1.0.0', 'row_number': 1},
        {'package_name': 'test2', 'version': 2.0, 'row_number': 2},
        {'package_name': 'test3', 'version': 3, 'row_number': 3},
        {'package_name': 'test4', 'version': None, 'row_number': 4},
    ]
    
    from src.services.enhanced_excel_processor import EnhancedExcelProcessor
    
    # Mock the necessary config
    class MockConfig:
        class Processing:
            max_concurrent_scans = 3
        processing = Processing()
    
    processor = EnhancedExcelProcessor(MockConfig())
    
    for pkg in test_packages:
        try:
            # Extract version like the processor does
            package_name = pkg.get('package_name', '')
            current_version = str(pkg.get('version', ''))
            print(f"  ✅ Package {package_name}: version={pkg['version']} -> '{current_version}'")
        except Exception as e:
            print(f"  ❌ Package {pkg.get('package_name', '?')}: {e}")
    
    print("\n📋 Testing Version Utils:")
    from src.utils.version_utils import VersionUtils
    
    # Test version comparison with different types
    version_pairs = [
        ("1.0.0", "2.0.0"),
        (1.0, 2.0),
        (1, 2),
        ("1.0", 2),
        (None, "1.0"),
    ]
    
    for current, latest in version_pairs:
        try:
            result = VersionUtils.compare_versions(current, latest)
            print(f"  ✅ Compare {current} ({type(current).__name__}) vs {latest} ({type(latest).__name__}): {result['is_outdated']}")
        except Exception as e:
            print(f"  ❌ Compare {current} vs {latest}: {e}")
    
    print("\n✅ Test completed - check for any ❌ marks above")

if __name__ == "__main__":
    asyncio.run(test_attribute_errors())