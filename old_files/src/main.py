#!/usr/bin/env python3
"""
Main entry point for IHACPA Python Package Review Automation
Handles CLI interface and orchestrates the complete automation process
"""

import asyncio
import argparse
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent.parent / '.env')
except ImportError:
    pass  # dotenv is optional

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import ConfigManager, Config
from logger import setup_application_logging, ProgressLogger, ErrorHandler
from excel_handler import ExcelHandler
from pypi_client import PyPIClient
from vulnerability_scanner import VulnerabilityScanner
import logging


class IHACPAAutomation:
    """Main automation class that orchestrates the entire process"""
    
    def __init__(self, config: Config, dry_run: bool = False):
        """Initialize automation with configuration"""
        self.config = config
        self.dry_run = dry_run
        self.original_file_path = None
        self.output_file_path = None
        self.logger = None
        self.progress_logger = None
        self.error_handler = None
        self.excel_handler = None
        self.pypi_client = None
        self.vulnerability_scanner = None
        
    def setup(self, input_file: str, output_file: str = None) -> bool:
        """Setup all components"""
        try:
            # Store file paths
            self.original_file_path = input_file
            
            # Create output file path (copy of input)
            if output_file:
                self.output_file_path = output_file
            else:
                # Create output file name based on input
                input_path = Path(input_file)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                self.output_file_path = str(input_path.parent / f"{input_path.stem}_updated_{timestamp}{input_path.suffix}")
            
            # Setup logging
            self.logger, self.progress_logger, self.error_handler = setup_application_logging(self.config)
            
            # Create copy of input file for output
            if not self.dry_run:
                self.logger.info(f"Creating copy of input file: {self.original_file_path} -> {self.output_file_path}")
                import shutil
                shutil.copy2(self.original_file_path, self.output_file_path)
            else:
                self.logger.info(f"DRY RUN: Would create copy: {self.original_file_path} -> {self.output_file_path}")
                # In dry run, work with original file but don't save
                self.output_file_path = self.original_file_path
            
            # Setup Excel handler with the output file (copy)
            self.excel_handler = ExcelHandler(self.output_file_path)
            if not self.excel_handler.load_workbook():
                self.logger.error("Failed to load Excel workbook")
                return False
            
            # Validate Excel file structure
            is_valid, errors = self.excel_handler.validate_file_structure()
            if not is_valid:
                self.logger.error("Excel file validation failed:")
                for error in errors:
                    self.logger.error(f"  - {error}")
                return False
            
            # Setup PyPI client
            self.pypi_client = PyPIClient(
                timeout=self.config.processing.request_timeout,
                max_retries=self.config.processing.retry_attempts
            )
            
            # Setup vulnerability scanner with OpenAI/Azure API configuration
            openai_api_key = self.config.get('openai_api_key') or None
            azure_endpoint = self.config.get('azure_openai_endpoint') or None
            azure_model = self.config.get('azure_openai_model') or os.getenv('AZURE_OPENAI_MODEL')
            
            self.vulnerability_scanner = VulnerabilityScanner(
                timeout=self.config.processing.request_timeout,
                max_retries=self.config.processing.retry_attempts,
                rate_limit=self.config.processing.rate_limit_delay,
                openai_api_key=openai_api_key,
                azure_endpoint=azure_endpoint,
                azure_model=azure_model
            )
            
            self.logger.info("All components initialized successfully")
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Setup failed: {e}")
            else:
                print(f"Setup failed: {e}")
            return False
    
    async def process_packages(self, start_row: Optional[int] = None, end_row: Optional[int] = None, 
                             package_names: Optional[List[str]] = None) -> bool:
        """Process packages with PyPI and vulnerability data"""
        try:
            # Get packages to process - NEW LOGIC: Process ALL packages for complete output
            if package_names:
                # If specific packages requested, find them or create new ones
                packages = []
                for name in package_names:
                    pkg = self.excel_handler.find_package_by_name(name)
                    if pkg:
                        packages.append(pkg)
                    else:
                        # Package not found - create new package entry
                        self.logger.info(f"Package '{name}' not found in Excel file. Adding as new package.")
                        
                        # Get basic package info from PyPI first to determine if it exists
                        pypi_info = self.pypi_client.get_package_info(name)
                        if pypi_info:
                            # Get date published for the current version
                            current_version = pypi_info.get('version', 'Unknown')
                            date_published = self.pypi_client.extract_version_date_from_package_info(pypi_info, current_version)
                            
                            # Create new package data structure with enhanced PyPI information
                            new_package = {
                                'package_name': name,
                                'current_version': current_version,
                                'pypi_current_link': pypi_info.get('pypi_url', f'https://pypi.org/project/{name}/'),  # Column D
                                'date_published': self._format_date_for_excel(date_published),  # Column E - Fixed format
                                'latest_version': pypi_info.get('latest_version', current_version),
                                'pypi_latest_link': pypi_info.get('pypi_latest_url', f'https://pypi.org/project/{name}/{pypi_info.get("latest_version", current_version)}/'),
                                'latest_release_date': self._format_date_for_excel(pypi_info.get('latest_release_date')),  # Column H - Fixed format
                                'requires': ', '.join(pypi_info.get('dependencies', [])[:10]) if pypi_info.get('dependencies') else '',  # Limit to first 10 deps
                                'development_status': self._extract_dev_status(pypi_info.get('classifiers', [])),
                                'github_url': pypi_info.get('github_url', ''),
                                'row_number': 0  # Will be set when added to Excel
                            }
                            
                            # Add the new package to Excel file
                            new_row = self.excel_handler.add_new_package(name, new_package)
                            if new_row > 0:
                                # Update the package data with the actual row number
                                new_package['row_number'] = new_row
                                packages.append(new_package)
                                self.logger.info(f"Successfully added new package '{name}' at row {new_row}")
                            else:
                                self.logger.error(f"Failed to add new package '{name}' to Excel file")
                        else:
                            self.logger.warning(f"Package '{name}' not found on PyPI. Skipping.")
                
                if packages:
                    self.logger.warning("Processing specific packages only. For complete output, process all packages.")
                else:
                    self.logger.warning("No valid packages found to process.")
            elif start_row and end_row:
                # If row range specified, process that range but warn about incomplete output
                packages = self.excel_handler.get_packages_by_range(start_row, end_row)
                self.logger.warning(f"Processing rows {start_row}-{end_row} only. For complete output, process all packages.")
            else:
                # DEFAULT: Process ALL packages to ensure complete output
                packages = self.excel_handler.get_all_packages()
                self.logger.info(f"Processing ALL packages to ensure complete output file")
            
            if not packages:
                self.logger.info("No packages to process")
                return True
            
            self.logger.info(f"Processing {len(packages)} packages")
            
            # Process packages in batches
            batch_size = self.config.processing.batch_size
            
            for i in range(0, len(packages), batch_size):
                batch = packages[i:i + batch_size]
                self.logger.info(f"Processing batch {i//batch_size + 1}/{(len(packages) + batch_size - 1)//batch_size}")
                
                # Process batch
                await self._process_batch(batch)
                
                # Save progress after each batch (unless dry-run)
                if not self.dry_run:
                    self.excel_handler.save_workbook(backup=False)  # No backup needed since we're working with a copy
                
                self.logger.info(f"Completed batch {i//batch_size + 1}")
            
            # Final save (unless dry-run)
            if not self.dry_run:
                self.excel_handler.save_workbook(backup=False)  # No backup needed since we're working with a copy
                self.logger.info(f"All packages processed successfully. Output saved to: {self.output_file_path}")
            else:
                self.logger.info("All packages processed successfully (DRY RUN - no changes saved)")
            
            return True
            
        except Exception as e:
            self.error_handler.handle_config_error("process_packages", e)
            return False
    
    async def _process_batch(self, packages: List[Dict[str, Any]]):
        """Process a batch of packages"""
        tasks = []
        
        for package in packages:
            task = self._process_single_package(package)
            tasks.append(task)
        
        # Process packages concurrently with limit
        semaphore = asyncio.Semaphore(self.config.processing.concurrent_requests)
        
        async def process_with_semaphore(package_task):
            async with semaphore:
                return await package_task
        
        # Execute all tasks
        results = await asyncio.gather(*[process_with_semaphore(task) for task in tasks], return_exceptions=True)
        
        # Handle results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                package_name = packages[i].get('package_name', 'unknown')
                self.error_handler.handle_config_error(f"process_package_{package_name}", result)
    
    async def _process_single_package(self, package: Dict[str, Any]) -> bool:
        """Process a single package - check and update if needed"""
        package_name = package.get('package_name', '')
        row_number = package.get('row_number', 0)
        current_version = str(package.get('current_version', '')) if package.get('current_version') is not None else ''
        
        if not package_name:
            return False
        
        start_time = datetime.now()
        self.progress_logger.log_package_start(package_name, row_number)
        
        try:
            updates = {}
            
            # Check if this package needs updates (has empty automated fields)
            # Note: Always update date_published to ensure it's based on current version
            automated_fields = [
                'latest_version', 'pypi_latest_link', 'latest_release_date',
                'requires', 'development_status', 'github_url', 'github_advisory_url',
                'github_advisory_result', 'nist_nvd_url', 'nist_nvd_result',
                'mitre_cve_url', 'mitre_cve_result', 'snyk_url', 'snyk_result',
                'exploit_db_url', 'exploit_db_result', 'recommendation'
            ]
            
            needs_update = False
            for field in automated_fields:
                if not package.get(field):
                    needs_update = True
                    break
            
            # Always update date_published to ensure it's based on current version
            force_update_date_published = True
            
            if not needs_update and not force_update_date_published:
                # Package already has all data, skip processing
                self.logger.debug(f"Package {package_name} already has complete data, skipping")
                processing_time = (datetime.now() - start_time).total_seconds()
                self.progress_logger.log_package_success(package_name, processing_time)
                return True
            
            # Get PyPI information
            pypi_info = self.pypi_client.get_package_info(package_name)
            if pypi_info:
                # Get publication date for the CURRENT version (Column C), not latest version
                # Always extract current version date to ensure it's based on installed version
                current_version_date = None
                if current_version:
                    current_version_date = self.pypi_client.extract_version_date_from_package_info(pypi_info, current_version)
                
                updates.update({
                    'latest_version': pypi_info.get('latest_version', ''),
                    'pypi_latest_link': pypi_info.get('pypi_latest_url', ''),
                    'latest_release_date': pypi_info.get('latest_release_date'),
                    'requires': ', '.join(pypi_info.get('dependencies', [])[:5]),  # Limit to first 5
                    'development_status': self._extract_dev_status(pypi_info.get('classifiers', [])),
                    'github_url': pypi_info.get('github_url', '')
                })
                
                # Always include date_published - either valid date or "Not Available"
                if current_version_date:
                    updates['date_published'] = current_version_date
                else:
                    self.logger.warning(f"Could not retrieve publication date for {package_name} v{current_version}")
                    updates['date_published'] = "Not Available"
                
                # Check for updates
                if current_version != pypi_info.get('latest_version'):
                    self.progress_logger.log_package_update_available(
                        package_name, current_version, pypi_info.get('latest_version', '')
                    )
            
            # Get vulnerability information (include current_version for AI analysis)
            vuln_results = await self.vulnerability_scanner.scan_all_databases(
                package_name, 
                github_url=pypi_info.get('github_url') if pypi_info else None,
                current_version=current_version
            )
            
            # Update vulnerability data
            if vuln_results:
                scan_results = vuln_results.get('scan_results', {})
                
                # Update database URLs and results
                for db_name, result in scan_results.items():
                    url_field = f"{db_name}_url"
                    result_field = f"{db_name}_result"
                    
                    if url_field in self.excel_handler.COLUMN_MAPPING:
                        # Generate hyperlink formula instead of plain URL
                        hyperlink_formula = self._generate_hyperlink_formula(db_name, row_number, result.get('search_url', ''))
                        updates[url_field] = hyperlink_formula
                    
                    if result_field in self.excel_handler.COLUMN_MAPPING:
                        updates[result_field] = result.get('summary', '')
                
                # Log vulnerabilities found
                total_vulns = vuln_results.get('total_vulnerabilities', 0)
                if total_vulns > 0:
                    for db_name, result in scan_results.items():
                        if result.get('found_vulnerabilities'):
                            self.progress_logger.log_vulnerability_found(
                                package_name, result.get('database', db_name), 
                                result.get('vulnerability_count', 0)
                            )
                
                # Generate recommendations
                recommendations = self.vulnerability_scanner.generate_recommendations(
                    package_name, current_version, 
                    pypi_info.get('latest_version', '') if pypi_info else '',
                    vuln_results
                )
                updates['recommendation'] = recommendations
            
            # Update Excel file (unless dry-run)
            if updates and not self.dry_run:
                self.excel_handler.update_package_data(row_number, updates)
            elif updates and self.dry_run:
                self.logger.debug(f"DRY RUN: Would update {len(updates)} fields for {package_name}")
            
            # Log success
            processing_time = (datetime.now() - start_time).total_seconds()
            self.progress_logger.log_package_success(package_name, processing_time)
            
            return True
            
        except Exception as e:
            self.error_handler.handle_config_error(f"process_single_package_{package_name}", e)
            self.progress_logger.log_package_failure(package_name, str(e))
            return False
    
    def _extract_dev_status(self, classifiers: List[str]) -> str:
        """Extract development status from classifiers"""
        for classifier in classifiers:
            if 'Development Status' in classifier:
                return classifier.split('::')[-1].strip()
        return "Unknown"
    
    def _format_date_for_excel(self, date_obj):
        """Format datetime object to a clean datetime object for Excel display (without microseconds)"""
        if not date_obj:
            return None
        
        try:
            from datetime import datetime
            
            # Handle different datetime formats
            if hasattr(date_obj, 'strftime'):
                # Convert timezone-aware datetime to naive if needed
                if hasattr(date_obj, 'tzinfo') and date_obj.tzinfo is not None:
                    date_obj = date_obj.replace(tzinfo=None)
                # Remove microseconds for cleaner display
                clean_date = date_obj.replace(microsecond=0)
                return clean_date
            elif isinstance(date_obj, str):
                # Try to parse string dates
                try:
                    parsed_date = datetime.fromisoformat(date_obj.replace('Z', '+00:00'))
                    if hasattr(parsed_date, 'tzinfo') and parsed_date.tzinfo is not None:
                        parsed_date = parsed_date.replace(tzinfo=None)
                    # Remove microseconds for cleaner display
                    clean_date = parsed_date.replace(microsecond=0)
                    return clean_date
                except ValueError:
                    # If can't parse, try to return a string format
                    return date_obj
            else:
                return date_obj
        except Exception as e:
            self.logger.warning(f"Error formatting date {date_obj}: {e}")
            return date_obj if date_obj else None
    
    def _generate_hyperlink_formula(self, db_name: str, row_number: int, search_url: str) -> str:
        """Generate Excel hyperlink formula for vulnerability database URLs"""
        if not search_url:
            return ""
        
        # Define database display names and base URL patterns
        db_configs = {
            'nist_nvd': {
                'display_name': 'NVD NIST',
                'base_url': 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=',
                'suffix': '&search_type=all&isCpeNameSearch=false'
            },
            'mitre_cve': {
                'display_name': 'CVE MITRE', 
                'base_url': 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=',
                'suffix': ''
            },
            'snyk': {
                'display_name': 'Snyk',
                'base_url': 'https://security.snyk.io/vuln/pip?search=',
                'suffix': ''
            },
            'exploit_db': {
                'display_name': 'Exploit-DB',
                'base_url': 'https://www.exploit-db.com/search?text=',
                'suffix': ''
            }
        }
        
        if db_name not in db_configs:
            return search_url  # fallback to plain URL
        
        config = db_configs[db_name]
        cell_ref = f"$B{row_number}"  # Package name is in column B
        
        # Generate hyperlink formula using CONCATENATE for URL construction
        if config['suffix']:
            url_formula = f'CONCATENATE("{config["base_url"]}",{cell_ref},"{config["suffix"]}")'
        else:
            url_formula = f'CONCATENATE("{config["base_url"]}",{cell_ref})'
        
        # Generate display text
        display_text = f'CONCATENATE("{config["display_name"]} ",{cell_ref}," link")'
        
        # Combine into HYPERLINK formula
        hyperlink_formula = f'=HYPERLINK({url_formula},{display_text})'
        
        return hyperlink_formula
    
    def generate_report(self, output_path: Optional[str] = None) -> bool:
        """Generate summary report"""
        try:
            if not output_path:
                output_path = f"data/output/ihacpa_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            # Get file info
            file_info = self.excel_handler.get_file_info()
            
            # Generate report
            report = []
            report.append("IHACPA Python Package Review Automation Report")
            report.append("=" * 60)
            report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"Excel file: {file_info.get('file_path', 'N/A')}")
            report.append(f"Total packages: {file_info.get('package_count', 'N/A')}")
            report.append("")
            
            # Add processing summary
            if self.progress_logger:
                report.append("Processing Summary:")
                report.append("-" * 30)
                report.append(f"Processed: {self.progress_logger.processed_packages}")
                report.append(f"Failed: {self.progress_logger.failed_packages}")
                report.append("")
            
            # Add error summary
            if self.error_handler:
                error_summary = self.error_handler.get_error_summary()
                if error_summary:
                    report.append("Error Summary:")
                    report.append("-" * 30)
                    for category, errors in error_summary.items():
                        report.append(f"{category.upper()}: {sum(errors.values())} errors")
                    report.append("")
            
            # Write report
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write('\n'.join(report))
            
            self.logger.info(f"Report generated: {output_path}")
            return True
            
        except Exception as e:
            self.error_handler.handle_config_error("generate_report", e)
            return False
    
    def generate_changes_report(self, output_path: Optional[str] = None) -> bool:
        """Generate a detailed report of changes made to the Excel file"""
        try:
            if not self.original_file_path or not self.excel_handler:
                self.logger.error("Cannot generate changes report: missing original file or Excel handler")
                return False
            
            if not output_path:
                output_path = f"data/output/changes_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            # Compare output file (copy) with original file
            if self.dry_run:
                # In dry run mode, there's no actual output file to compare
                self.logger.info("DRY RUN: No changes report generated (no output file created)")
                return True
            
            comparison_results = self.excel_handler.compare_with_original(self.original_file_path)
            
            if 'error' in comparison_results:
                self.logger.error(f"Error comparing files: {comparison_results['error']}")
                return False
            
            # Generate detailed report
            changes_report = self.excel_handler.generate_changes_report(comparison_results)
            
            # Generate color summary
            color_summary = self.excel_handler.generate_color_summary_report()
            
            # Add processing summary
            full_report = []
            full_report.append("IHACPA AUTOMATION CHANGES REPORT")
            full_report.append("=" * 60)
            full_report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            full_report.append(f"Original file: {self.original_file_path}")
            full_report.append(f"Output file: {self.output_file_path}")
            full_report.append(f"Dry run mode: {self.dry_run}")
            full_report.append("")
            full_report.append(changes_report)
            full_report.append("")
            full_report.append(color_summary)
            
            # Add processing statistics
            if self.progress_logger:
                full_report.append("")
                full_report.append("PROCESSING STATISTICS:")
                full_report.append("-" * 30)
                full_report.append(f"Packages processed: {self.progress_logger.processed_packages}")
                full_report.append(f"Packages failed: {self.progress_logger.failed_packages}")
                if self.progress_logger.processed_packages > 0:
                    success_rate = (self.progress_logger.processed_packages / 
                                  (self.progress_logger.processed_packages + self.progress_logger.failed_packages)) * 100
                    full_report.append(f"Success rate: {success_rate:.1f}%")
            
            # Write report
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(full_report))
            
            self.logger.info(f"Changes report generated: {output_path}")
            
            # Log summary to console
            if comparison_results['total_changes'] > 0:
                self.logger.info(f"📊 Changes made: {comparison_results['total_changes']} fields in {comparison_results['packages_modified']} packages")
            else:
                self.logger.info("📊 No changes detected")
            
            return True
            
        except Exception as e:
            self.error_handler.handle_config_error("generate_changes_report", e)
            return False
    
    def run_format_check(self, fix: bool = True) -> bool:
        """
        Run format check and optionally fix formatting issues
        
        Args:
            fix: If True, fix formatting issues. If False, only report them.
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.excel_handler:
                self.logger.error("Excel handler not initialized")
                return False
            
            self.logger.info("🔍 Running format check...")
            
            # Run format check
            results = self.excel_handler.check_and_fix_formatting(dry_run=not fix)
            
            if 'error' in results:
                self.logger.error(f"Format check failed: {results['error']}")
                return False
            
            # Log summary
            self.logger.info(f"📊 Format check completed:")
            self.logger.info(f"   Packages checked: {results['total_packages_checked']}")
            self.logger.info(f"   Issues found: {results['formatting_issues_found']}")
            
            if fix:
                self.logger.info(f"   Fixes applied: {results['fixes_applied']}")
            else:
                self.logger.info("   No fixes applied (dry run mode)")
            
            # Report issues by column
            if results['issues_by_column']:
                self.logger.info("   Issues by column:")
                for column, count in results['issues_by_column'].items():
                    self.logger.info(f"     {column}: {count} issues")
            
            # Generate detailed report
            if results['fixes_by_package']:
                report_path = f"data/output/format_check_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                self._generate_format_check_report(results, report_path)
                self.logger.info(f"   Detailed report: {report_path}")
            
            return True
            
        except Exception as e:
            self.error_handler.handle_config_error("format_check", e) if self.error_handler else None
            return False
    
    def _generate_format_check_report(self, results: Dict[str, Any], output_path: str):
        """Generate detailed format check report"""
        try:
            report = []
            report.append("IHACPA FORMAT CHECK REPORT")
            report.append("=" * 60)
            report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"Excel file: {self.excel_handler.file_path}")
            report.append("")
            
            # Summary
            report.append("SUMMARY:")
            report.append("-" * 30)
            report.append(f"Total packages checked: {results['total_packages_checked']}")
            report.append(f"Formatting issues found: {results['formatting_issues_found']}")
            report.append(f"Fixes applied: {results['fixes_applied']}")
            report.append("")
            
            # Issues by column
            if results['issues_by_column']:
                report.append("ISSUES BY COLUMN:")
                report.append("-" * 30)
                for column, count in sorted(results['issues_by_column'].items()):
                    report.append(f"{column}: {count} issues")
                report.append("")
            
            # Detailed fixes by package
            if results['fixes_by_package']:
                report.append("DETAILED FIXES BY PACKAGE:")
                report.append("-" * 30)
                
                for package_info in results['fixes_by_package']:
                    report.append(f"📦 {package_info['package_name']} (Row {package_info['row']}):")
                    
                    for fix in package_info['fixes']:
                        report.append(f"  🔧 {fix['column']} - {fix['status']}")
                        report.append(f"     Value: {fix['value']}")
                        report.append(f"     Expected format: {fix['expected_format']}")
                        report.append(f"     Issues: {', '.join(fix['issues'])}")
                        report.append("")
            
            # Write report
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report))
                
        except Exception as e:
            self.logger.error(f"Error generating format check report: {e}")

    async def cleanup(self):
        """Cleanup resources"""
        if self.excel_handler:
            self.excel_handler.close()
        
        if self.vulnerability_scanner:
            await self.vulnerability_scanner.close()
        
        if self.pypi_client:
            await self.pypi_client.close()


def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="IHACPA Python Package Review Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # RECOMMENDED: Process all packages (creates complete output copy)
  python main.py --input packages.xlsx
  
  # Test first with dry run (recommended before production run)
  python main.py --input packages.xlsx --dry-run
  
  # Specify output file location
  python main.py --input packages.xlsx --output updated_packages.xlsx
  
  # TESTING ONLY: Process specific packages (for testing individual packages)
  python main.py --input packages.xlsx --packages requests pandas numpy
  
  # TESTING ONLY: Process specific row range (for testing specific rows)
  python main.py --input packages.xlsx --start-row 10 --end-row 50
  
  # Generate report only
  python main.py --input packages.xlsx --report-only
  
  # Generate changes comparison report only
  python main.py --input packages.xlsx --changes-only
  
  # Use custom configuration
  python main.py --input packages.xlsx --config custom_config.yaml
        """
    )
    
    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Path to input Excel file'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Path to output Excel file (default: overwrites input with backup)'
    )
    
    parser.add_argument(
        '--config', '-c',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--start-row',
        type=int,
        help='Start processing from this row number (WARNING: Output will be incomplete)'
    )
    
    parser.add_argument(
        '--end-row',
        type=int,
        help='End processing at this row number (WARNING: Output will be incomplete)'
    )
    
    parser.add_argument(
        '--packages', '-p',
        nargs='+',
        help='Process specific packages by name (WARNING: Output will be incomplete - use for testing only)'
    )
    
    parser.add_argument(
        '--report-only',
        action='store_true',
        help='Generate report only, do not process packages'
    )
    
    parser.add_argument(
        '--changes-only',
        action='store_true',
        help='Generate changes report only, comparing current file with original'
    )
    
    parser.add_argument(
        '--format-check',
        action='store_true',
        help='Run format check and fix formatting issues'
    )
    
    parser.add_argument(
        '--format-check-only',
        action='store_true',
        help='Run format check only (dry run - report issues without fixing)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be processed without making changes'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Quiet mode - minimal output'
    )
    
    return parser


async def main():
    """Main entry point"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Load configuration
    config_manager = ConfigManager(args.config)
    config = config_manager.load_config()
    
    # Adjust logging level based on arguments
    if args.verbose:
        config.logging.level = "DEBUG"
    elif args.quiet:
        config.logging.level = "ERROR"
    
    # Validate input file
    input_file = Path(args.input)
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        return 1
    
    # Initialize automation
    automation = IHACPAAutomation(config, dry_run=args.dry_run)
    
    try:
        # Setup
        if not automation.setup(str(input_file), args.output):
            print("Failed to setup automation")
            return 1
        
        # Handle format check operations
        if args.format_check or args.format_check_only:
            automation.logger.info("Running format check...")
            success = automation.run_format_check(fix=args.format_check)
            
            if not success:
                automation.logger.error("Format check failed")
                return 1
            
            # If format check only, save and exit
            if args.format_check_only:
                automation.logger.info("Format check completed")
                return 0
        
        # Process packages (unless report-only or changes-only)
        if not args.report_only and not args.changes_only and not args.format_check_only:
            if args.dry_run:
                automation.logger.info("DRY RUN MODE - No changes will be made")
                # In dry-run mode, still process packages but don't save changes
                success = await automation.process_packages(
                    start_row=args.start_row,
                    end_row=args.end_row,
                    package_names=args.packages
                )
                
                if not success:
                    automation.logger.error("Package processing failed")
                    return 1
            else:
                success = await automation.process_packages(
                    start_row=args.start_row,
                    end_row=args.end_row,
                    package_names=args.packages
                )
                
                if not success:
                    automation.logger.error("Package processing failed")
                    return 1
                
                # Run format check after processing if enabled
                if args.format_check:
                    automation.logger.info("Running post-processing format check...")
                    automation.run_format_check(fix=True)
        
        # Generate report
        if config.output.create_reports and not args.changes_only:
            automation.generate_report()  # Don't pass output file path, let it generate its own report file
        
        # Generate changes report (compare output with original)
        if not args.report_only:
            automation.generate_changes_report()
        
        # Log final summary
        if automation.progress_logger:
            automation.progress_logger.log_final_summary()
        
        if automation.error_handler:
            automation.error_handler.log_error_summary()
        
        automation.logger.info("Automation completed successfully")
        return 0
        
    except KeyboardInterrupt:
        automation.logger.info("Process interrupted by user")
        return 130
    except Exception as e:
        if automation.logger:
            automation.logger.error(f"Unexpected error: {e}")
        else:
            print(f"Unexpected error: {e}")
        return 1
    finally:
        await automation.cleanup()


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
