#!/usr/bin/env python3
"""
Examine the Excel file structure to understand the package data
"""

import pandas as pd
from pathlib import Path

def examine_excel_file(excel_file):
    """Examine the structure of the Excel file"""
    
    print(f"📊 Examining Excel file: {excel_file}")
    print("=" * 80)
    
    try:
        # Read Excel file
        df = pd.read_excel(excel_file)
        print(f"✅ Loaded {len(df)} rows from Excel")
        
        # Display basic info
        print(f"📋 Shape: {df.shape}")
        print(f"📋 Columns: {list(df.columns)}")
        
        # Show first few rows
        print(f"\n🔍 First 10 rows:")
        print(df.head(10))
        
        # Check first column for actual package names
        first_col = df.columns[0]
        print(f"\n📦 First column '{first_col}' values:")
        unique_vals = df[first_col].dropna().unique()[:20]  # First 20 unique values
        for i, val in enumerate(unique_vals, 1):
            print(f"   {i}. {val}")
        
        # Look for actual package names in the data
        print(f"\n🔍 Looking for Python package patterns...")
        
        # Check all columns for potential package names
        for col in df.columns:
            col_data = df[col].dropna().astype(str)
            
            # Look for common Python package patterns
            potential_packages = []
            for val in col_data.unique()[:50]:  # Check first 50 values
                val_str = str(val).strip()
                # Skip numbers, single characters, and common non-package strings
                if (len(val_str) > 2 and 
                    not val_str.isdigit() and 
                    val_str not in ['#', 'nan', 'NaN'] and
                    not val_str.startswith('Unnamed') and
                    val_str.lower() not in ['bulk', 'python', 'june', 'july']):
                    potential_packages.append(val_str)
            
            if potential_packages:
                print(f"\n📦 Column '{col}' potential packages:")
                for pkg in potential_packages[:10]:  # Show first 10
                    print(f"   • {pkg}")
        
        # Try to find a row that might contain headers
        print(f"\n🔍 Searching for header row...")
        for i in range(min(10, len(df))):
            row_data = df.iloc[i].dropna().astype(str).tolist()
            print(f"   Row {i}: {row_data[:5]}...")  # Show first 5 values
            
            # Check if this row contains package-like names
            if any(name for name in row_data if len(str(name)) > 2 and not str(name).isdigit()):
                print(f"   ↳ Potential package names in row {i}")
        
    except Exception as e:
        print(f"❌ Error examining Excel file: {e}")
        import traceback
        traceback.print_exc()

def main():
    excel_file = "2025-07-09 IHACPA Review of ALL existing PYTHON Packages - org.xlsx"
    
    if not Path(excel_file).exists():
        print(f"❌ Excel file not found: {excel_file}")
        return
    
    examine_excel_file(excel_file)

if __name__ == "__main__":
    main()