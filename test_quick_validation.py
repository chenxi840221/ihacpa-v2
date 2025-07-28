#!/usr/bin/env python3
"""
Quick validation test for the core fixes
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.integrations.pypi_client import PyPIClient
from src.integrations.enhanced_column_orchestrator import EnhancedColumnOrchestrator
from src.core.ai_analyzer import AIAnalyzer
from src.core.sandbox_manager import SandboxManager
from src.config import ConfigManager


async def test_pypi_client():
    """Test PyPI client with new methods"""
    print("🔍 Testing PyPI Client...")
    
    client = PyPIClient()
    info = await client.get_package_info('requests')
    
    if info:
        print(f"  ✅ Latest version: {info.get_latest_version()}")
        print(f"  ✅ Dependencies: {len(info.get_dependencies())} deps")
        print(f"  ✅ Classifiers: {len(info.get_classifiers())} classifiers")
    else:
        print("  ❌ Failed to get package info")
    
    await client.close()


async def test_column_processors():
    """Test individual column processors"""
    print("\n🔍 Testing Column Processors...")
    
    try:
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Initialize components  
        ai_analyzer = AIAnalyzer(config.ai.__dict__ if hasattr(config, 'ai') else {})
        
        # Test PyPI columns only (faster)
        from src.integrations.columns.pypi_data import (
            DatePublishedProcessor,
            LatestVersionProcessor, 
            LatestReleaseDateProcessor
        )
        
        pypi_client = PyPIClient()
        
        # Test Column E
        e_processor = DatePublishedProcessor(pypi_client)
        e_result = await e_processor.process("requests", "2.28.1")
        print(f"  ✅ Column E: {e_result.get('value', 'N/A')}")
        
        # Test Column F  
        f_processor = LatestVersionProcessor(pypi_client)
        f_result = await f_processor.process("requests", "2.28.1")
        print(f"  ✅ Column F: {f_result.get('value', 'N/A')}")
        
        # Test Column H
        h_processor = LatestReleaseDateProcessor(pypi_client)
        h_result = await h_processor.process("requests", "2.28.1")
        print(f"  ✅ Column H: {h_result.get('value', 'N/A')}")
        
        await pypi_client.close()
        
    except Exception as e:
        print(f"  ❌ Error: {e}")


async def test_sandbox_manager():
    """Test sandbox manager initialization"""
    print("\n🔍 Testing Sandbox Manager...")
    
    try:
        config_manager = ConfigManager()
        config = config_manager.load_config()
        config_dict = config.__dict__ if hasattr(config, '__dict__') else config
        
        sandbox_manager = SandboxManager(config_dict)
        await sandbox_manager.initialize()
        
        print(f"  ✅ Sandboxes registered: {len(sandbox_manager.sandboxes)}")
        for name in sandbox_manager.sandboxes.keys():
            print(f"    - {name}")
        
        await sandbox_manager.cleanup()
        
    except Exception as e:
        print(f"  ❌ Error: {e}")


async def main():
    """Run all tests"""
    print("🧪 Quick Validation Test Suite")
    print("=" * 50)
    
    await test_pypi_client()
    await test_column_processors()  
    await test_sandbox_manager()
    
    print("\n🎉 Quick validation completed!")


if __name__ == '__main__':
    asyncio.run(main())