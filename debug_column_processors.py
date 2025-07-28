#!/usr/bin/env python3
"""
Debug script to test column processor sandbox access
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager
from src.integrations.columns.vulnerability_dbs import SNYKProcessor, MITRECVEProcessor, ExploitDBProcessor

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(name)s - %(message)s')

async def debug_column_processors():
    """Test column processor sandbox access specifically"""
    print("🔍 Debug: Testing Column Processor Sandbox Access")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    await manager.initialize()
    
    print(f"1. Sandbox manager initialized with: {list(manager.sandboxes.keys())}")
    
    try:
        # Test direct sandbox access (like our debug script)
        print("\n2. Testing direct sandbox access:")
        for name in ['snyk', 'mitre', 'exploit_db']:
            sandbox = await manager.get_sandbox(name)
            print(f"   - Direct get_sandbox('{name}'): {sandbox}")
        
        # Test column processor access (like actual workflow)
        print("\n3. Testing column processor sandbox access:")
        
        # Initialize SNYK processor
        snyk_processor = SNYKProcessor(manager)
        print(f"   - SNYKProcessor initialized with manager: {manager}")
        
        # Test the specific call that's failing
        print(f"   - SNYKProcessor.sandbox_manager: {snyk_processor.sandbox_manager}")
        
        snyk_sandbox = await snyk_processor.sandbox_manager.get_sandbox('snyk')
        print(f"   - SNYKProcessor get_sandbox('snyk'): {snyk_sandbox}")
        
        # Test MITRE processor
        mitre_processor = MITRECVEProcessor(manager)
        mitre_sandbox = await mitre_processor.sandbox_manager.get_sandbox('mitre')
        print(f"   - MITREProcessor get_sandbox('mitre'): {mitre_sandbox}")
        
        # Test ExploitDB processor
        exploit_processor = ExploitDBProcessor(manager)
        exploit_sandbox = await exploit_processor.sandbox_manager.get_sandbox('exploit_db')
        print(f"   - ExploitDBProcessor get_sandbox('exploit_db'): {exploit_sandbox}")
        
        # Test actual column processing
        print("\n4. Testing actual column processing:")
        
        if snyk_sandbox:
            print("   - Testing SNYK result processing...")
            result = await snyk_processor.process_result("requests", "2.25.1")
            print(f"   - SNYK result: {result.get('value', 'N/A')}")
        else:
            print("   - ❌ SNYK sandbox not available, cannot test processing")
        
    except Exception as e:
        print(f"❌ Error during debugging: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        print("\n5. Cleaning up...")
        await manager.cleanup()

if __name__ == "__main__":
    asyncio.run(debug_column_processors())