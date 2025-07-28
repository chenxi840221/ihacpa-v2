"""
Command Line Argument Parser for IHACPA v2.0

Provides comprehensive command line interface with argument parsing
and validation.
"""

import argparse
from pathlib import Path
from typing import Optional, List
import sys


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure command line argument parser.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='ihacpa',
        description='IHACPA v2.0 - AI-Enhanced Python Package Security Automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all packages in Excel file
  python -m ihacpa scan packages.xlsx

  # Scan specific packages
  python -m ihacpa scan packages.xlsx --packages requests flask django

  # Dry run mode (no file modifications)
  python -m ihacpa scan packages.xlsx --dry-run

  # Custom configuration
  python -m ihacpa scan packages.xlsx --config custom-config.yaml

  # Enable debug mode
  python -m ihacpa scan packages.xlsx --debug --verbose

  # Generate reports only
  python -m ihacpa report results.json --output-dir reports/
        """
    )
    
    # Add version
    parser.add_argument(
        '--version',
        action='version',
        version='IHACPA v2.0.0'
    )
    
    # Global options
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file (YAML format)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode with verbose logging'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress console output (log to file only)'
    )
    
    # Create subparsers for commands
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        metavar='COMMAND'
    )
    
    # Scan command
    scan_parser = subparsers.add_parser(
        'scan',
        help='Scan packages for vulnerabilities',
        description='Scan Python packages for security vulnerabilities using AI-enhanced analysis'
    )
    
    scan_parser.add_argument(
        'excel_file',
        type=str,
        help='Path to Excel file containing package list'
    )
    
    scan_parser.add_argument(
        '--output',
        type=str,
        help='Output file path (default: input file with timestamp)'
    )
    
    scan_parser.add_argument(
        '--packages',
        nargs='+',
        help='Specific package names to scan (default: all packages in file)'
    )
    
    scan_parser.add_argument(
        '--start-row',
        type=int,
        help='Start scanning from specific row number'
    )
    
    scan_parser.add_argument(
        '--end-row',
        type=int,
        help='Stop scanning at specific row number'
    )
    
    scan_parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Perform scan without modifying files'
    )
    
    scan_parser.add_argument(
        '--no-ai',
        action='store_true',
        help='Disable AI enhancements (basic scanning only)'
    )
    
    scan_parser.add_argument(
        '--no-correlation',
        action='store_true',
        help='Disable cross-database correlation analysis'
    )
    
    scan_parser.add_argument(
        '--no-risk-assessment',
        action='store_true',
        help='Disable AI risk assessment'
    )
    
    scan_parser.add_argument(
        '--backup',
        action='store_true',
        default=True,
        help='Create backup of original file (default: True)'
    )
    
    scan_parser.add_argument(
        '--no-backup',
        action='store_false',
        dest='backup',
        help='Skip creating backup of original file'
    )
    
    # Report command
    report_parser = subparsers.add_parser(
        'report',
        help='Generate reports from scan results',
        description='Generate comprehensive reports from previous scan results'
    )
    
    report_parser.add_argument(
        'input_file',
        type=str,
        help='Path to scan results file (JSON format)'
    )
    
    report_parser.add_argument(
        '--output-dir',
        type=str,
        default='reports',
        help='Output directory for reports (default: reports/)'
    )
    
    report_parser.add_argument(
        '--format',
        choices=['txt', 'json', 'csv', 'all'],
        default='all',
        help='Report format (default: all)'
    )
    
    # Config command
    config_parser = subparsers.add_parser(
        'config',
        help='Configuration management',
        description='Manage IHACPA configuration settings'
    )
    
    config_subparsers = config_parser.add_subparsers(
        dest='config_action',
        help='Configuration actions'
    )
    
    # Config init
    config_init_parser = config_subparsers.add_parser(
        'init',
        help='Initialize configuration file'
    )
    config_init_parser.add_argument(
        '--path',
        type=str,
        default='config/settings.yaml',
        help='Path for configuration file'
    )
    
    # Config validate
    config_validate_parser = config_subparsers.add_parser(
        'validate',
        help='Validate configuration file'
    )
    config_validate_parser.add_argument(
        'config_file',
        type=str,
        help='Path to configuration file to validate'
    )
    
    # Test command
    test_parser = subparsers.add_parser(
        'test',
        help='Test system components',
        description='Test various system components and connections'
    )
    
    test_parser.add_argument(
        '--ai',
        action='store_true',
        help='Test AI service connection'
    )
    
    test_parser.add_argument(
        '--sandboxes',
        action='store_true',
        help='Test sandbox health'
    )
    
    test_parser.add_argument(
        '--excel',
        type=str,
        help='Test Excel file reading with specified file'
    )
    
    test_parser.add_argument(
        '--all',
        action='store_true',
        help='Run all tests'
    )
    
    return parser


def parse_arguments(args: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parse command line arguments with validation.
    
    Args:
        args: Optional list of arguments (default: sys.argv)
        
    Returns:
        Parsed arguments namespace
        
    Raises:
        SystemExit: If arguments are invalid
    """
    parser = create_argument_parser()
    parsed_args = parser.parse_args(args)
    
    # Validate arguments
    if not parsed_args.command:
        parser.print_help()
        sys.exit(1)
    
    # Command-specific validation
    if parsed_args.command == 'scan':
        _validate_scan_arguments(parsed_args)
    elif parsed_args.command == 'report':
        _validate_report_arguments(parsed_args)
    elif parsed_args.command == 'config':
        _validate_config_arguments(parsed_args)
    elif parsed_args.command == 'test':
        _validate_test_arguments(parsed_args)
    
    return parsed_args


def _validate_scan_arguments(args: argparse.Namespace):
    """Validate scan command arguments"""
    # Check Excel file exists
    excel_path = Path(args.excel_file)
    if not excel_path.exists():
        print(f"Error: Excel file not found: {args.excel_file}")
        sys.exit(1)
    
    if not excel_path.suffix.lower() in ['.xlsx', '.xls']:
        print(f"Error: File must be Excel format (.xlsx or .xls): {args.excel_file}")
        sys.exit(1)
    
    # Validate row numbers
    if args.start_row and args.start_row < 1:
        print("Error: Start row must be greater than 0")
        sys.exit(1)
    
    if args.end_row and args.end_row < 1:
        print("Error: End row must be greater than 0")
        sys.exit(1)
    
    if args.start_row and args.end_row and args.start_row > args.end_row:
        print("Error: Start row must be less than or equal to end row")
        sys.exit(1)
    
    # Validate output path
    if args.output:
        output_path = Path(args.output)
        if output_path.exists() and not args.dry_run:
            response = input(f"Output file {args.output} already exists. Overwrite? (y/N): ")
            if response.lower() != 'y':
                print("Operation cancelled")
                sys.exit(1)
    
    # Validate package names
    if args.packages:
        invalid_packages = [pkg for pkg in args.packages if not pkg.strip()]
        if invalid_packages:
            print("Error: Package names cannot be empty")
            sys.exit(1)


def _validate_report_arguments(args: argparse.Namespace):
    """Validate report command arguments"""
    # Check input file exists
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: Input file not found: {args.input_file}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Error: Cannot create output directory {args.output_dir}: {e}")
        sys.exit(1)


def _validate_config_arguments(args: argparse.Namespace):
    """Validate config command arguments"""
    if not args.config_action:
        print("Error: Config action required (init, validate)")
        sys.exit(1)
    
    if args.config_action == 'validate':
        config_path = Path(args.config_file)
        if not config_path.exists():
            print(f"Error: Configuration file not found: {args.config_file}")
            sys.exit(1)


def _validate_test_arguments(args: argparse.Namespace):
    """Validate test command arguments"""
    if args.excel:
        excel_path = Path(args.excel)
        if not excel_path.exists():
            print(f"Error: Excel test file not found: {args.excel}")
            sys.exit(1)
    
    # If no specific test specified, default to all
    if not any([args.ai, args.sandboxes, args.excel, args.all]):
        args.all = True


def print_help():
    """Print help message"""
    parser = create_argument_parser()
    parser.print_help()