"""
Enhanced Excel Processor for IHACPA v2.0

Integrates the new column processors (E, F, K, L, W, M) with the existing 
Excel handler to provide comprehensive package analysis and formatting.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from ..io.excel_handler import ExcelHandler
from ..integrations.enhanced_column_orchestrator import EnhancedColumnOrchestrator
from ..core.ai_analyzer import AIAnalyzer
from ..core.browser_automation import BrowserAutomation, MockBrowserAutomation
from ..core.progress_tracker import ProgressTracker
from ..config import Config


class EnhancedExcelProcessor:
    """Enhanced Excel processor with new column functionality"""
    
    def __init__(self, config: Config, sandbox_manager=None):
        """
        Initialize enhanced Excel processor.
        
        Args:
            config: Application configuration
            sandbox_manager: Optional sandbox manager for vulnerability scanning
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.excel_handler: Optional[ExcelHandler] = None
        self.column_orchestrator: Optional[EnhancedColumnOrchestrator] = None
        self.ai_analyzer: Optional[AIAnalyzer] = None
        self.progress_tracker: Optional[ProgressTracker] = None
        
        # Initialize AI analyzer if enabled
        if config.ai.enabled:
            try:
                self.ai_analyzer = AIAnalyzer(config.ai.__dict__)
            except Exception as e:
                self.logger.warning(f"AI analyzer initialization failed: {e}")
                self.ai_analyzer = None
        
        # Initialize enhanced column orchestrator
        try:
            self.column_orchestrator = EnhancedColumnOrchestrator(
                config, 
                self.ai_analyzer,
                sandbox_manager
            )
        except Exception as e:
            self.logger.error(f"Enhanced column orchestrator initialization failed: {e}")
            raise
    
    async def process_excel_file(self, file_path: str, output_path: Optional[str] = None, 
                                 package_names: Optional[List[str]] = None,
                                 start_row: Optional[int] = None,
                                 end_row: Optional[int] = None) -> Dict[str, Any]:
        """
        Process Excel file with enhanced column functionality.
        
        Args:
            file_path: Path to input Excel file
            output_path: Optional path for output file
            
        Returns:
            Processing results dictionary
        """
        try:
            self.logger.info(f"Starting enhanced Excel processing for {file_path}")
            
            # Initialize Excel handler
            self.excel_handler = ExcelHandler(file_path, self.config)
            if not self.excel_handler.load_workbook():
                raise Exception("Failed to load Excel workbook")
            
            # Validate file structure
            is_valid, errors = self.excel_handler.validate_file_structure()
            if not is_valid:
                raise Exception(f"Invalid file structure: {errors}")
            
            # Get all packages to process
            packages = self.excel_handler.get_all_packages()
            if not packages:
                raise Exception("No packages found in Excel file")
            
            self.logger.info(f"Found {len(packages)} packages to process")
            
            # Initialize progress tracker
            self.progress_tracker = ProgressTracker(len(packages), self.logger)
            start_msg = f"🚀 Starting enhanced processing of {len(packages)} packages"
            self.logger.info(start_msg)
            print(start_msg)  # Also print to console
            
            # Process packages with enhanced columns
            results = await self._process_packages_enhanced(packages, package_names)
            
            # Save results
            output_file = output_path or self._generate_output_filename(file_path)
            save_success = self.excel_handler.save_workbook(Path(output_file))
            
            if not save_success:
                raise Exception(f"Failed to save Excel file to {output_file}")
            
            # Generate summary
            processing_summary = {
                'input_file': file_path,
                'output_file': output_file,
                'packages_processed': len(results['processed']),
                'packages_failed': len(results['failed']),
                'columns_updated': results['columns_updated'],
                'processing_time': results['processing_time'],
                'enhanced_columns': ['E', 'F', 'H', 'K', 'L', 'M', 'P', 'R', 'T', 'V', 'W'],
                'ai_enhanced': self.ai_analyzer is not None and self.ai_analyzer.is_enabled()
            }
            
            self.logger.info(f"Enhanced Excel processing completed: {processing_summary}")
            return processing_summary
            
        except Exception as e:
            self.logger.error(f"Enhanced Excel processing failed: {e}")
            raise
        finally:
            # Cleanup resources
            if self.column_orchestrator:
                await self.column_orchestrator.cleanup()
    
    async def _process_packages_enhanced(self, packages: List[Dict[str, Any]], 
                                         package_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process packages with enhanced column functionality"""
        start_time = datetime.now()
        processed = []
        failed = []
        columns_updated = set()
        
        # Filter packages if specific package names are provided
        if package_names:
            original_count = len(packages)
            packages = [pkg for pkg in packages if pkg.get('package_name', '').lower() in [name.lower() for name in package_names]]
            filtered_msg = f"🔍 Filtered from {original_count} to {len(packages)} packages based on --packages parameter: {', '.join(package_names)}"
            self.logger.info(filtered_msg)
            print(filtered_msg)  # Also print to console
        
        # Process packages in batches to avoid overwhelming APIs
        batch_size = self.config.processing.max_concurrent_scans
        total_packages = len(packages)
        
        for i in range(0, total_packages, batch_size):
            batch = packages[i:i + batch_size]
            batch_num = i//batch_size + 1
            total_batches = (total_packages + batch_size - 1)//batch_size
            
            batch_msg = f"📦 Processing batch {batch_num}/{total_batches} (packages {i+1}-{min(i+batch_size, total_packages)})"
            self.logger.info(batch_msg)
            print(batch_msg)  # Also print to console
            
            # Process each package individually for detailed tracking
            for j, pkg in enumerate(batch):
                package_index = i + j + 1
                package_name = pkg.get('package_name', 'unknown')
                row_number = pkg.get('row_number', 0)
                
                # Start package tracking
                if self.progress_tracker:
                    self.progress_tracker.start_package(package_name, package_index)
                
                progress_msg = f"🔍 [{package_index}/{total_packages}] Row {row_number}: Processing {package_name}"
                self.logger.info(progress_msg)
                print(progress_msg)  # Also print to console for immediate visibility
                
                try:
                    package_start_time = datetime.now()
                    result = await self._process_single_package_enhanced(pkg)
                    package_time = (datetime.now() - package_start_time).total_seconds()
                    
                    # Log successful completion
                    vulnerabilities = sum(col_result.get('vulnerability_count', 0) 
                                        for col_result in result.get('column_results', {}).values()
                                        if isinstance(col_result, dict))
                    
                    ai_enhanced = any(col_result.get('ai_enhanced', False) 
                                    for col_result in result.get('column_results', {}).values()
                                    if isinstance(col_result, dict))
                    
                    processed.append(result)
                    columns_updated.update(result.get('columns_updated', []))
                    
                    # Log completion to console
                    status_emoji = "✅"
                    if vulnerabilities > 0:
                        if vulnerabilities >= 5:
                            status_emoji = "🚨"
                        elif vulnerabilities >= 2:
                            status_emoji = "⚠️"
                        vuln_info = f", {vulnerabilities} vulnerabilities"
                    else:
                        vuln_info = ""
                    
                    ai_indicator = " (AI)" if ai_enhanced else ""
                    completion_msg = f"{status_emoji} [{package_index}/{total_packages}] Row {row_number}: Completed {package_name} in {package_time:.2f}s{vuln_info}{ai_indicator}"
                    print(completion_msg)  # Console output
                    
                    # Update progress tracker
                    if self.progress_tracker:
                        self.progress_tracker.complete_package(
                            package_name=package_name,
                            success=True,
                            vulnerabilities_found=vulnerabilities,
                            ai_enhanced=ai_enhanced
                        )
                    
                except Exception as e:
                    package_time = (datetime.now() - package_start_time).total_seconds()
                    error_msg = str(e)
                    
                    error_msg_console = f"❌ [{package_index}/{total_packages}] Row {row_number}: Failed to process {package_name} after {package_time:.2f}s: {error_msg}"
                    self.logger.error(error_msg_console)
                    print(error_msg_console)  # Also print to console
                    
                    failed.append({
                        'package': package_name,
                        'row_number': row_number,
                        'error': error_msg,
                        'processing_time': package_time
                    })
                    
                    # Update progress tracker
                    if self.progress_tracker:
                        self.progress_tracker.complete_package(
                            package_name=package_name,
                            success=False,
                            error_message=error_msg
                        )
            
            # Small delay between batches to be respectful to APIs
            if i + batch_size < total_packages:
                self.logger.debug(f"⏳ Pausing 1 second between batches...")
                await asyncio.sleep(1)
        
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Log final summary
        if self.progress_tracker:
            self.progress_tracker.log_final_summary()
        
        completion_msg = f"🎉 Enhanced processing completed: {len(processed)} successful, {len(failed)} failed in {processing_time:.1f}s"
        self.logger.info(completion_msg)
        print(completion_msg)  # Also print to console
        
        return {
            'processed': processed,
            'failed': failed,
            'columns_updated': list(columns_updated),
            'processing_time': processing_time
        }
    
    async def _process_single_package_enhanced(self, package: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single package with enhanced column functionality"""
        package_name = package.get('package_name', '')
        current_version = package.get('version', '')
        row_number = package.get('row_number', 0)
        
        if not package_name:
            raise Exception("Package name is required")
        
        self.logger.debug(f"🔧 Row {row_number}: Processing enhanced columns for {package_name} v{current_version}")
        
        results = {
            'package_name': package_name,
            'current_version': current_version,
            'row_number': row_number,
            'columns_updated': [],
            'column_results': {}
        }
        
        # Use the enhanced column orchestrator to process all columns
        self.logger.debug(f"🔧 Row {row_number}: Processing all enhanced columns for {package_name} v{current_version}")
        
        try:
            # Process all columns using the enhanced orchestrator
            all_column_results = await self.column_orchestrator.process_all_columns(package_name, current_version)
            
            # Update Excel cells and track results
            for column, result in all_column_results.items():
                if result and result.get('value'):
                    # Map column letter to Excel field name
                    field_name = self._map_column_to_field(column)
                    if field_name:
                        # Update Excel cell
                        self._update_excel_cell(row_number, field_name, result)
                        
                        # Track results
                        results['column_results'][column] = result
                        results['columns_updated'].append(column)
                        self.logger.debug(f"✅ Row {row_number}: Column {column} updated for {package_name}: {str(result.get('value', ''))[:50]}...")
                    else:
                        self.logger.debug(f"⚪ Row {row_number}: Column {column} - no mapping for {package_name}")
                else:
                    self.logger.debug(f"⚪ Row {row_number}: Column {column} - no data for {package_name}")
                    
        except Exception as e:
            self.logger.error(f"📍 Row {row_number}: Enhanced column processing failed for {package_name}: {e}")
            # Create error results for all columns
            error_columns = ['E', 'F', 'H', 'K', 'L', 'M', 'P', 'R', 'T', 'V', 'W']
            for column in error_columns:
                results['column_results'][column] = {
                    'value': 'Error',
                    'color': 'critical',
                    'font': 'critical',
                    'note': f'Processing error: {str(e)}'
                }
        
        return results
    
    def _map_column_to_field(self, column: str) -> Optional[str]:
        """Map column letter to Excel field name"""
        column_mapping = {
            'E': 'date_published',
            'F': 'latest_version', 
            'H': 'latest_date',
            'K': 'github_url',
            'L': 'github_security_url',
            'M': 'github_security_result',
            'P': 'nvd_result',
            'R': 'mitre_result',
            'T': 'snyk_result',
            'V': 'exploit_db_result',
            'W': 'recommendation'
        }
        return column_mapping.get(column)
    
    
    
    def _update_excel_cell(self, row_number: int, column_field: str, result: Dict[str, Any]):
        """Update Excel cell with result data and formatting"""
        try:
            # Update cell value
            self.excel_handler.update_cell(
                row_number, 
                column_field, 
                result.get('value', ''),
                color=result.get('color'),
                font=result.get('font')
            )
            
            # Track the change
            self.excel_handler.changes_made.append({
                'row': row_number,
                'column': column_field,
                'old_value': '',  # Could be tracked if needed
                'new_value': result.get('value', ''),
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            self.logger.error(f"Failed to update Excel cell {column_field} for row {row_number}: {e}")
    
    def _generate_output_filename(self, input_file: str) -> str:
        """Generate output filename based on input file"""
        input_path = Path(input_file)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        output_name = f"{input_path.stem}_enhanced_{timestamp}.xlsx"
        output_dir = Path(self.config.output.output_directory)
        output_dir.mkdir(exist_ok=True)
        
        return str(output_dir / output_name)
    
    async def process_single_package(self, package_name: str, current_version: str = None) -> Dict[str, Any]:
        """
        Process a single package for testing or individual analysis.
        
        Args:
            package_name: Name of the Python package
            current_version: Optional current version
            
        Returns:
            Processing results for the package
        """
        try:
            self.logger.info(f"Processing single package: {package_name} v{current_version}")
            
            # Create a mock package dictionary
            package = {
                'package_name': package_name,
                'version': current_version or 'latest',
                'row_number': 1  # Mock row number
            }
            
            # Process with enhanced columns
            result = await self._process_single_package_enhanced(package)
            
            self.logger.info(f"Single package processing completed for {package_name}")
            return result
            
        except Exception as e:
            self.logger.error(f"Single package processing failed for {package_name}: {e}")
            raise
    
    async def cleanup(self):
        """Clean up resources"""
        if self.column_orchestrator:
            await self.column_orchestrator.cleanup()
        
        self.logger.debug("Enhanced Excel processor cleanup completed")