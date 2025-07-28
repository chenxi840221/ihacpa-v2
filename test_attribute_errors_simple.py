#!/usr/bin/env python3
"""
Simple test for potential 'object has no attribute' errors
"""

# Test the specific methods that might have issues
def test_determine_color_type():
    """Test the _determine_color_type method with various field types"""
    print("🔍 Testing _determine_color_type with Various Field Types")
    print("=" * 60)
    
    # Simulate the method logic
    def _determine_color_type(field, new_value, old_value):
        """Simulated method to test"""
        if old_value is None and new_value is not None:
            return 'new_data'
        
        # Security-related fields
        field_str = str(field).lower()
        if 'result' in field_str and new_value:
            value_str = str(new_value).upper()
            if any(term in value_str for term in ['CRITICAL', 'VULNERABLE', 'HIGH']):
                return 'security_risk'
            elif 'AI' in value_str or 'ENHANCED' in value_str:
                return 'ai_enhanced'
        
        # Version updates
        if 'version' in field_str and old_value != new_value:
            return 'version_update'
        
        # Default update highlighting
        return 'updated'
    
    # Test cases
    test_fields = [
        ("package_version", "string field"),
        (3.14, "float field"),
        (42, "int field"),
        (None, "None field"),
        (True, "bool field"),
    ]
    
    print("\n📋 Testing various field types:")
    for field, description in test_fields:
        try:
            result = _determine_color_type(field, "new_value", "old_value")
            print(f"  ✅ {description} ({type(field).__name__}): {result}")
        except Exception as e:
            print(f"  ❌ {description} ({type(field).__name__}): {e}")

def test_version_handling():
    """Test version handling with different types"""
    print("\n\n🔍 Testing Version Handling")
    print("=" * 60)
    
    # Test version conversion
    test_versions = [
        "3.9.0",
        3.9,
        3,
        None,
        True,
        "",
    ]
    
    print("\n📋 Testing version to string conversion:")
    for version in test_versions:
        try:
            # This is what the enhanced processor now does
            version_str = str(version) if version is not None else ""
            print(f"  ✅ {version} ({type(version).__name__}) -> '{version_str}'")
            
            # Test string methods on converted version
            _ = version_str.lower()
            _ = version_str.strip()
            _ = version_str.split('.')
            
        except Exception as e:
            print(f"  ❌ {version} ({type(version).__name__}): {e}")

def test_exploit_version_checking():
    """Test the fixed exploit version checking"""
    print("\n\n🔍 Testing Exploit Version Checking")
    print("=" * 60)
    
    # Simulate the fixed method
    def check_version_lower(current_version):
        version_lower = str(current_version).lower()
        return version_lower
    
    test_versions = [
        "3.9.0",
        3.9,
        3,
        None,
    ]
    
    print("\n📋 Testing version .lower() with str() conversion:")
    for version in test_versions:
        try:
            result = check_version_lower(version)
            print(f"  ✅ {version} ({type(version).__name__}) -> '{result}'")
        except Exception as e:
            print(f"  ❌ {version} ({type(version).__name__}): {e}")

if __name__ == "__main__":
    test_determine_color_type()
    test_version_handling()
    test_exploit_version_checking()
    print("\n\n✅ All tests completed - check for any ❌ marks above")