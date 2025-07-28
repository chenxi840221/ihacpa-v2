#!/usr/bin/env python3
"""
Analyze the enhanced Excel output file
"""

import pandas as pd
import sys
from pathlib import Path

def analyze_excel_output(file_path):
    """Analyze the enhanced Excel file output"""
    try:
        print(f"📊 Analyzing Enhanced Output: {file_path}")
        print("=" * 80)
        
        # Read the Excel file
        df = pd.read_excel(file_path)
        
        print(f"📦 Total packages: {len(df)}")
        print(f"📋 Total columns: {len(df.columns)}")
        print(f"📝 Column names: {list(df.columns)}")
        
        # Check enhanced columns
        enhanced_columns = ['E', 'F', 'H', 'K', 'L', 'M', 'W']
        print(f"\n🔧 Enhanced Columns Analysis:")
        print("-" * 40)
        
        for col in enhanced_columns:
            if col in df.columns:
                # Check how many cells have been filled
                non_empty = df[col].notna().sum()
                empty = len(df) - non_empty
                fill_rate = (non_empty / len(df)) * 100
                
                print(f"Column {col}: {non_empty}/{len(df)} filled ({fill_rate:.1f}%)")
                
                # Show sample values
                sample_values = df[col].dropna().head(3).tolist()
                if sample_values:
                    print(f"  Sample values: {sample_values}")
            else:
                print(f"Column {col}: NOT FOUND")
        
        # Look for any columns with "enhanced" data
        print(f"\n📈 Data Sample (first 5 rows):")
        print("-" * 40)
        
        # Show first few rows for key columns
        key_cols = ['B', 'C'] + [col for col in enhanced_columns if col in df.columns]
        key_cols = [col for col in key_cols if col in df.columns]
        
        if key_cols:
            sample_df = df[key_cols].head(5)
            print(sample_df.to_string())
        
        print(f"\n📊 Summary:")
        print("-" * 40)
        print(f"✅ File successfully loaded")
        print(f"📦 {len(df)} packages found")
        
        # Check if any processing occurred
        processed_columns = 0
        for col in enhanced_columns:
            if col in df.columns and df[col].notna().sum() > 0:
                processed_columns += 1
        
        print(f"🔧 {processed_columns}/{len(enhanced_columns)} enhanced columns have data")
        
        if processed_columns > 0:
            print("✅ Enhanced processing appears to have occurred!")
        else:
            print("⚠️  No enhanced data found - processing may not have completed")
            
    except Exception as e:
        print(f"❌ Error analyzing file: {e}")
        return False
    
    return True

def main():
    """Main function"""
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        # Look for the enhanced file
        enhanced_files = list(Path(".").glob("*enhanced*.xlsx"))
        if enhanced_files:
            file_path = str(enhanced_files[0])
        else:
            print("❌ No enhanced Excel file found. Please specify file path.")
            return
    
    if not Path(file_path).exists():
        print(f"❌ File not found: {file_path}")
        return
    
    analyze_excel_output(file_path)

if __name__ == "__main__":
    main()