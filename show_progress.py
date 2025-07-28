#!/usr/bin/env python3
"""
Real-time progress viewer for IHACPA v2.0

Shows current processing status and progress.
"""

import sys
import time
import json
from pathlib import Path
from datetime import datetime
import subprocess


def find_latest_log():
    """Find the latest IHACPA log file"""
    log_dir = Path("logs")
    if not log_dir.exists():
        log_dir = Path(".")
        
    today = datetime.now().strftime('%Y%m%d')
    log_files = list(log_dir.glob(f"ihacpa_{today}.log"))
    
    if not log_files:
        log_files = list(log_dir.glob("ihacpa_*.log"))
    
    if not log_files:
        print("No log files found")
        return None
        
    return max(log_files, key=lambda p: p.stat().st_mtime)


def extract_progress(log_file):
    """Extract progress information from log"""
    total_rows = 0
    processed_rows = 0
    current_package = ""
    column_stats = {}
    recent_activities = []
    errors = []
    
    try:
        # Read last 1000 lines
        result = subprocess.run(
            ['tail', '-n', '1000', str(log_file)],
            capture_output=True,
            text=True
        )
        
        lines = result.stdout.split('\n')
        
        for line in lines:
            # Look for total rows
            if "Total rows to process:" in line:
                try:
                    total_rows = int(line.split("Total rows to process:")[1].strip())
                except:
                    pass
            
            # Look for processing row
            if "Processing row" in line:
                try:
                    row_num = int(line.split("Processing row")[1].split()[0])
                    processed_rows = max(processed_rows, row_num)
                except:
                    pass
            
            # Look for package being processed
            if "Processing package:" in line or "Analyzing package:" in line:
                try:
                    package = line.split("package:")[1].strip().split()[0]
                    current_package = package
                except:
                    pass
            
            # Track column processing
            if "[Column" in line:
                try:
                    col = line.split("[Column")[1].split("]")[0].strip()
                    column_stats[col] = column_stats.get(col, 0) + 1
                except:
                    pass
            
            # Track recent activities
            if any(x in line for x in ['Processing', 'Analyzing', 'Fetching', 'Scanning']):
                timestamp = line.split(' - ')[0]
                activity = ' - '.join(line.split(' - ')[2:])
                recent_activities.append((timestamp, activity))
            
            # Track errors
            if "ERROR" in line:
                errors.append(line)
        
        return {
            'total_rows': total_rows,
            'processed_rows': processed_rows,
            'current_package': current_package,
            'column_stats': column_stats,
            'recent_activities': recent_activities[-10:],  # Last 10 activities
            'errors': errors[-5:]  # Last 5 errors
        }
        
    except Exception as e:
        print(f"Error reading log: {e}")
        return None


def display_progress(info):
    """Display progress information"""
    # Clear screen
    print("\033[2J\033[H")
    
    print("=" * 80)
    print("IHACPA v2.0 - Real-time Progress Monitor")
    print("=" * 80)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    if info['total_rows'] > 0:
        progress = (info['processed_rows'] / info['total_rows']) * 100
        bar_length = 50
        filled = int(bar_length * progress / 100)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        print(f"Progress: [{bar}] {progress:.1f}%")
        print(f"Rows: {info['processed_rows']} / {info['total_rows']}")
    else:
        print("Progress: Initializing...")
    
    print()
    print(f"Current Package: {info['current_package'] or 'N/A'}")
    print()
    
    # Column statistics
    if info['column_stats']:
        print("Column Processing Stats:")
        for col in sorted(info['column_stats'].keys()):
            print(f"  Column {col}: {info['column_stats'][col]:>5} operations")
    print()
    
    # Recent activities
    if info['recent_activities']:
        print("Recent Activities:")
        for timestamp, activity in info['recent_activities'][-5:]:
            # Truncate long activities
            if len(activity) > 70:
                activity = activity[:67] + "..."
            print(f"  {timestamp} - {activity}")
    print()
    
    # Errors
    if info['errors']:
        print("Recent Errors:")
        for error in info['errors'][-3:]:
            error_msg = error.split(' - ERROR - ')[-1]
            if len(error_msg) > 70:
                error_msg = error_msg[:67] + "..."
            print(f"  ❌ {error_msg}")
    
    print()
    print("Press Ctrl+C to exit")


def main():
    """Main monitoring loop"""
    log_file = find_latest_log()
    if not log_file:
        print("No log file found!")
        sys.exit(1)
    
    print(f"Monitoring: {log_file}")
    time.sleep(1)
    
    try:
        while True:
            info = extract_progress(log_file)
            if info:
                display_progress(info)
            time.sleep(2)  # Update every 2 seconds
            
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped.")


if __name__ == '__main__':
    main()