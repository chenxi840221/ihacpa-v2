#!/usr/bin/env python3
"""
Test the enhanced logging functionality
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.services.enhanced_excel_processor import EnhancedExcelProcessor
from src.config import ConfigManager
import logging

async def test_enhanced_logging():
    """Test the enhanced logging with a small subset"""
    print("🧪 Testing Enhanced Logging Functionality")
    print("=" * 60)
    
    try:
        # Load configuration
        config_manager = ConfigManager()
        config = config_manager.load_config()
        
        # Create enhanced Excel processor
        processor = EnhancedExcelProcessor(config)
        
        # Test with the original file but simulate package filtering
        file_path = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
        
        print(f"📊 Processing {file_path} with enhanced logging...")
        
        # Process just a few packages to test logging
        # This will show us the detailed progress tracking
        results = await processor.process_excel_file(file_path)
        
        print("✅ Enhanced logging test completed!")
        print(f"📈 Results: {results}")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Setup basic logging to see output
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    asyncio.run(test_enhanced_logging())