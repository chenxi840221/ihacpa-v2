#!/usr/bin/env python3
"""
Real-time log monitor for IHACPA v2.0

Monitors and displays logs with color coding and filtering.
"""

import sys
import time
import subprocess
from pathlib import Path
from datetime import datetime
import re
from typing import Optional
import argparse


class LogMonitor:
    """Real-time log monitor with color coding"""
    
    # ANSI color codes
    COLORS = {
        'ERROR': '\033[91m',      # Red
        'WARNING': '\033[93m',    # Yellow
        'INFO': '\033[92m',       # Green
        'DEBUG': '\033[94m',      # Blue
        'CRITICAL': '\033[95m',   # Magenta
        'RESET': '\033[0m',       # Reset
        'BOLD': '\033[1m',        # Bold
        'DIM': '\033[2m',         # Dim
    }
    
    def __init__(self, log_file: Optional[str] = None, filter_level: str = "INFO"):
        """Initialize log monitor"""
        self.log_file = log_file or self._find_latest_log()
        self.filter_level = filter_level
        self.level_priority = {
            'DEBUG': 10,
            'INFO': 20,
            'WARNING': 30,
            'ERROR': 40,
            'CRITICAL': 50
        }
        self.min_priority = self.level_priority.get(filter_level.upper(), 20)
        
    def _find_latest_log(self) -> str:
        """Find the latest IHACPA log file"""
        log_dir = Path("logs")
        if not log_dir.exists():
            log_dir = Path(".")
            
        # Look for today's log file
        today = datetime.now().strftime('%Y%m%d')
        log_pattern = f"ihacpa_{today}.log"
        
        # Find matching log files
        log_files = list(log_dir.glob(f"ihacpa_*.log"))
        if not log_files:
            print(f"No log files found in {log_dir}")
            sys.exit(1)
            
        # Get the most recent
        latest_log = max(log_files, key=lambda p: p.stat().st_mtime)
        return str(latest_log)
    
    def _colorize_line(self, line: str) -> str:
        """Add color to log line based on level"""
        # Extract log level
        level_match = re.search(r' - (DEBUG|INFO|WARNING|ERROR|CRITICAL) - ', line)
        if not level_match:
            return line
            
        level = level_match.group(1)
        color = self.COLORS.get(level, self.COLORS['RESET'])
        
        # Highlight important patterns
        line = re.sub(r'(\[Column [A-Z]\])', f"{self.COLORS['BOLD']}\\1{self.COLORS['RESET']}", line)
        line = re.sub(r'(✅|✓)', f"{self.COLORS['BOLD']}{self.COLORS['INFO']}\\1{self.COLORS['RESET']}", line)
        line = re.sub(r'(❌|✗)', f"{self.COLORS['BOLD']}{self.COLORS['ERROR']}\\1{self.COLORS['RESET']}", line)
        line = re.sub(r'(⚠️|!)', f"{self.COLORS['BOLD']}{self.COLORS['WARNING']}\\1{self.COLORS['RESET']}", line)
        line = re.sub(r'(Processing row \d+)', f"{self.COLORS['DIM']}\\1{self.COLORS['RESET']}", line)
        
        # Color the entire line based on level
        return f"{color}{line}{self.COLORS['RESET']}"
    
    def _should_display(self, line: str) -> bool:
        """Check if line should be displayed based on filter level"""
        level_match = re.search(r' - (DEBUG|INFO|WARNING|ERROR|CRITICAL) - ', line)
        if not level_match:
            return True
            
        level = level_match.group(1)
        priority = self.level_priority.get(level, 0)
        return priority >= self.min_priority
    
    def tail_file(self):
        """Tail the log file with color coding"""
        print(f"{self.COLORS['BOLD']}=== IHACPA Log Monitor ==={self.COLORS['RESET']}")
        print(f"Log file: {self.log_file}")
        print(f"Filter level: {self.filter_level}")
        print(f"{self.COLORS['DIM']}Press Ctrl+C to stop{self.COLORS['RESET']}")
        print("-" * 80)
        
        try:
            # Use tail command for real-time monitoring
            process = subprocess.Popen(
                ['tail', '-f', self.log_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in process.stdout:
                line = line.rstrip()
                if self._should_display(line):
                    print(self._colorize_line(line))
                    
        except KeyboardInterrupt:
            print(f"\n{self.COLORS['DIM']}Monitoring stopped{self.COLORS['RESET']}")
            process.terminate()
        except FileNotFoundError:
            print(f"{self.COLORS['ERROR']}Error: tail command not found{self.COLORS['RESET']}")
            print("Falling back to Python-based monitoring...")
            self.tail_file_python()
    
    def tail_file_python(self):
        """Python-based file tailing (fallback)"""
        try:
            with open(self.log_file, 'r') as f:
                # Go to end of file
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        line = line.rstrip()
                        if self._should_display(line):
                            print(self._colorize_line(line))
                    else:
                        time.sleep(0.1)
                        
        except KeyboardInterrupt:
            print(f"\n{self.COLORS['DIM']}Monitoring stopped{self.COLORS['RESET']}")
        except Exception as e:
            print(f"{self.COLORS['ERROR']}Error: {e}{self.COLORS['RESET']}")
    
    def show_summary(self):
        """Show a summary of the log file"""
        print(f"\n{self.COLORS['BOLD']}=== Log Summary ==={self.COLORS['RESET']}")
        
        counts = {
            'DEBUG': 0,
            'INFO': 0,
            'WARNING': 0,
            'ERROR': 0,
            'CRITICAL': 0
        }
        
        column_stats = {}
        
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    # Count log levels
                    level_match = re.search(r' - (DEBUG|INFO|WARNING|ERROR|CRITICAL) - ', line)
                    if level_match:
                        counts[level_match.group(1)] += 1
                    
                    # Track column processing
                    col_match = re.search(r'\[Column ([A-Z])\]', line)
                    if col_match:
                        col = col_match.group(1)
                        column_stats[col] = column_stats.get(col, 0) + 1
            
            # Display counts
            for level, count in counts.items():
                if count > 0:
                    color = self.COLORS.get(level, self.COLORS['RESET'])
                    print(f"{color}{level:8}: {count:6}{self.COLORS['RESET']}")
            
            if column_stats:
                print(f"\n{self.COLORS['BOLD']}Column Processing:{self.COLORS['RESET']}")
                for col, count in sorted(column_stats.items()):
                    print(f"  Column {col}: {count} entries")
                    
        except Exception as e:
            print(f"{self.COLORS['ERROR']}Error reading log file: {e}{self.COLORS['RESET']}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Monitor IHACPA logs in real-time')
    parser.add_argument('-f', '--file', help='Specific log file to monitor')
    parser.add_argument('-l', '--level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                       help='Minimum log level to display (default: INFO)')
    parser.add_argument('-s', '--summary', action='store_true',
                       help='Show log summary instead of tailing')
    
    args = parser.parse_args()
    
    monitor = LogMonitor(log_file=args.file, filter_level=args.level)
    
    if args.summary:
        monitor.show_summary()
    else:
        monitor.tail_file()


if __name__ == '__main__':
    main()