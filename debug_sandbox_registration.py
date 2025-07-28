#!/usr/bin/env python3
"""
Debug script to test sandbox registration and availability
"""

import asyncio
import logging
from src.core.sandbox_manager import SandboxManager

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(name)s - %(message)s')

async def debug_sandbox_registration():
    """Test sandbox registration process step by step"""
    print("🔍 Debug: Testing Sandbox Registration Process")
    print("=" * 60)
    
    # Initialize sandbox manager
    manager = SandboxManager(config={})
    
    try:
        print("1. Initializing SandboxManager...")
        await manager.initialize()
        
        print(f"\n2. Registered sandboxes: {list(manager.sandboxes.keys())}")
        print(f"   Total count: {len(manager.sandboxes)}")
        
        print("\n3. Testing individual sandbox availability:")
        test_sandboxes = ["snyk", "mitre", "exploit_db", "nvd"]
        
        for sandbox_name in test_sandboxes:
            print(f"\n   Testing {sandbox_name}:")
            
            # Check if sandbox exists in dict
            exists_in_dict = sandbox_name in manager.sandboxes
            print(f"   - Exists in sandboxes dict: {exists_in_dict}")
            
            # Try to get sandbox via get_sandbox method
            sandbox = await manager.get_sandbox(sandbox_name)
            print(f"   - get_sandbox() returns: {sandbox}")
            
            if sandbox:
                print(f"   - Sandbox type: {type(sandbox)}")
                print(f"   - Sandbox name: {sandbox.name}")
                
                # Test health check
                try:
                    health = await sandbox.health_check()
                    print(f"   - Health check: {health}")
                except Exception as e:
                    print(f"   - Health check error: {e}")
            else:
                print(f"   - ❌ Sandbox not available")
        
        print("\n4. Testing sandbox registration debug info:")
        for name, sandbox in manager.sandboxes.items():
            print(f"   - {name}: {type(sandbox)} (name: {sandbox.name})")
        
        print(f"\n5. Sandbox manager stats:")
        stats = await manager.get_stats()
        print(f"   - Registered: {stats.get('registered_sandboxes', [])}")
        print(f"   - Health status: {stats.get('sandbox_health', {})}")
        
    except Exception as e:
        print(f"❌ Error during debugging: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        print("\n6. Cleaning up...")
        await manager.cleanup()

if __name__ == "__main__":
    asyncio.run(debug_sandbox_registration())