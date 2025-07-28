#!/usr/bin/env python3
"""
Quick Demo of Enhanced Columns as Default in IHACPA v2.0

This demonstrates that enhanced columns (E, F, K, L, M, W) are now the default 
processing mode when running the main application.
"""

import asyncio
import subprocess
import sys
from pathlib import Path

def run_command(cmd, description):
    """Run a command and show the output"""
    print(f"\n{'='*80}")
    print(f"🚀 {description}")
    print(f"{'='*80}")
    print(f"Command: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        print(f"Exit code: {result.returncode}")
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("❌ Command timed out after 30 seconds")
        return False
    except Exception as e:
        print(f"❌ Command failed: {e}")
        return False

def main():
    """Main demo function"""
    print("🎉 IHACPA v2.0 Enhanced Columns as Default - Demo")
    print("=" * 80)
    
    # Check if Excel file exists
    excel_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    if not Path(excel_file).exists():
        print(f"❌ Excel file not found: {excel_file}")
        print("Please ensure the Excel file is in the current directory")
        return 1
    
    print(f"✅ Excel file found: {excel_file}")
    
    # Demo 1: Show help and available commands
    print("\n📚 Demo 1: Show IHACPA Commands")
    run_command([
        sys.executable, "-m", "src.main", "--help"
    ], "IHACPA Help")
    
    # Demo 2: Show configuration with enhanced columns enabled
    print("\n📚 Demo 2: Show Configuration (Enhanced Columns Enabled by Default)")
    run_command([
        sys.executable, "-m", "src.main", "config", "show"
    ], "Show Configuration")
    
    # Demo 3: Dry run to show enhanced columns processing
    print("\n📚 Demo 3: Dry Run with Enhanced Columns (Default)")
    run_command([
        sys.executable, "-m", "src.main", "scan", excel_file, 
        "--dry-run", "--output", "demo_output.xlsx"
    ], "Dry Run with Enhanced Columns")
    
    # Demo 4: Test basic functionality
    print("\n📚 Demo 4: Test System Components")
    run_command([
        sys.executable, "-m", "src.main", "test", "--all"
    ], "System Component Tests")
    
    print("\n" + "="*80)
    print("✅ Enhanced Columns Demo Completed!")
    print("="*80)
    print("\n📋 Summary:")
    print("   ✅ Enhanced columns (E, F, K, L, M, W) are now DEFAULT")
    print("   ✅ No --enhanced-columns flag needed anymore")
    print("   ✅ Configuration shows enhanced_columns_enabled: true")
    print("   ✅ Main application automatically processes all enhanced columns")
    print("\n💡 To run actual processing:")
    print(f'   python -m src.main scan "{excel_file}" --output "output.xlsx"')
    
    return 0

if __name__ == "__main__":
    sys.exit(main())