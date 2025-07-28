#!/usr/bin/env python3
"""
Test Enhanced Columns for IHACPA v2.0
"""

import asyncio
import sys
import json
from pathlib import Path
from typing import Dict, Any
import logging

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.integrations.column_processors import ColumnProcessors
from src.core.ai_analyzer import AIAnalyzer
from src.config import ConfigManager


async def test_package(package_name: str, version: str, processors: ColumnProcessors):
    """Test enhanced columns for a specific package"""
    print(f"\nTesting Enhanced Columns for: {package_name} v{version}")
    print("=" * 80)
    
    results = {}
    
    # Test Column E
    print("\nTesting Column E - Date Published...")
    try:
        result_e = await processors.process_column_E_date_published(package_name, version)
        results['E'] = result_e
        print(f"  Result: {result_e.get('value', 'N/A')}")
    except Exception as e:
        print(f"  Error: {e}")
        results['E'] = {'error': str(e)}
    
    # Test Column F
    print("\nTesting Column F - Latest Version...")
    try:
        result_f = await processors.process_column_F_latest_version(package_name, version)
        results['F'] = result_f
        print(f"  Result: {result_f.get('value', 'N/A')}")
    except Exception as e:
        print(f"  Error: {e}")
        results['F'] = {'error': str(e)}
    
    # Test Column K
    print("\nTesting Column K - GitHub URL...")
    try:
        result_k = await processors.process_column_K_github_url(package_name)
        results['K'] = result_k
        print(f"  Result: {result_k.get('value', 'N/A')}")
    except Exception as e:
        print(f"  Error: {e}")
        results['K'] = {'error': str(e)}
    
    # Test Column L
    print("\nTesting Column L - GitHub Security URL...")
    try:
        github_url = results.get('K', {}).get('value', '')
        result_l = await processors.process_column_L_github_security_url(package_name, github_url)
        results['L'] = result_l
        print(f"  Result: {result_l.get('value', 'N/A')}")
    except Exception as e:
        print(f"  Error: {e}")
        results['L'] = {'error': str(e)}
    
    # Test Column M
    print("\nTesting Column M - GitHub Security Result...")
    try:
        github_url = results.get('K', {}).get('value', '')
        result_m = await processors.process_column_M_github_security_result(package_name, version, github_url)
        results['M'] = result_m
        print(f"  Result: {result_m.get('value', 'N/A')}")
    except Exception as e:
        print(f"  Error: {e}")
        results['M'] = {'error': str(e)}
    
    # Test Column W
    print("\nTesting Column W - IHACPA Recommendation...")
    try:
        result_w = await processors.process_column_W_recommendation(package_name, results)
        results['W'] = result_w
        print(f"  Result: {result_w.get('value', 'N/A')}")
    except Exception as e:
        print(f"  Error: {e}")
        results['W'] = {'error': str(e)}
    
    return results


async def main():
    """Main test function"""
    logging.basicConfig(level=logging.INFO)
    
    # Load configuration
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        print("Configuration loaded")
    except Exception as e:
        print(f"Failed to load configuration: {e}")
        return
    
    # Initialize processors
    try:
        ai_analyzer = AIAnalyzer(config.ai.__dict__ if hasattr(config, 'ai') else {})
        processors = ColumnProcessors(config, ai_analyzer)
        print("Column processors initialized")
    except Exception as e:
        print(f"Failed to initialize processors: {e}")
        return
    
    # Get package from command line or use default
    if len(sys.argv) >= 3:
        package_name = sys.argv[1]
        version = sys.argv[2]
    else:
        package_name = "requests"
        version = "2.28.1"
    
    # Test the package
    results = await test_package(package_name, version, processors)
    
    # Print summary
    print("\nSUMMARY:")
    for column, result in results.items():
        if 'error' in result:
            print(f"Column {column}: ERROR - {result['error']}")
        else:
            print(f"Column {column}: {result.get('value', 'N/A')}")


if __name__ == '__main__':
    print("IHACPA Enhanced Columns Test")
    print("Usage: python test_enhanced_columns.py [package_name] [version]")
    asyncio.run(main())