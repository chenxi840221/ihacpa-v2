"""
Application Controller for IHACPA v2.0

Main orchestrator that coordinates all application components and workflows.
Now uses enhanced Excel processing with columns E, F, K, L, M, W by default.
"""

import asyncio
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import json
import sys

from ..config import Config, ConfigManager
from ..core.logger_manager import setup_logging
from ..core.progress_tracker import ProgressTracker
from ..core.error_handler import ErrorHandler, ErrorCategory, ErrorSeverity
from ..core.sandbox_manager import SandboxManager
from ..io.excel_handler import ExcelHandler
from ..io.report_generator import ReportGenerator
from ..services.enhanced_excel_processor import EnhancedExcelProcessor


class AppController:
    """Main application controller that orchestrates the entire IHACPA workflow with enhanced columns"""
    
    def __init__(self, config: Config, dry_run: bool = False):
        """
        Initialize application controller.
        
        Args:
            config: Application configuration
            dry_run: Whether to run in dry-run mode (no file modifications)
        """
        self.config = config
        self.dry_run = dry_run
        
        # Core components (initialized in setup)
        self.logger: Optional[logging.Logger] = None
        self.logger_manager = None
        self.error_handler: Optional[ErrorHandler] = None
        self.progress_tracker: Optional[ProgressTracker] = None
        self.sandbox_manager: Optional[SandboxManager] = None
        self.excel_handler: Optional[ExcelHandler] = None
        self.report_generator: Optional[ReportGenerator] = None
        self.enhanced_excel_processor: Optional[EnhancedExcelProcessor] = None
        
        # File paths
        self.input_file_path: Optional[Path] = None
        self.output_file_path: Optional[Path] = None
        self.backup_file_path: Optional[Path] = None
        
        # Results storage
        self.scan_results: Dict[str, Any] = {}
        self.packages_processed = 0
        self.packages_successful = 0
        self.packages_failed = 0
    
    async def setup(self, input_file: str, output_file: Optional[str] = None) -> bool:
        """
        Setup all application components.
        
        Args:
            input_file: Path to input Excel file
            output_file: Optional path to output file
            
        Returns:
            True if setup successful, False otherwise
        """
        try:
            # Setup file paths
            self.input_file_path = Path(input_file)
            
            if output_file:
                self.output_file_path = Path(output_file)
            else:
                # Generate timestamped output filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_name = f"{self.input_file_path.stem}_enhanced_{timestamp}{self.input_file_path.suffix}"
                self.output_file_path = self.input_file_path.parent / output_name
            
            # Setup logging
            self.logger, self.logger_manager = setup_logging(self.config)
            self.logger.info(f"IHACPA v{self.config.app.version} starting with Enhanced Columns (default)")
            
            # Setup error handler
            self.error_handler = ErrorHandler(self.logger)
            
            # Validate input file
            if not self._validate_input_file():
                return False
            
            # Create file backup if not in dry-run mode
            if not self.dry_run and self.config.excel.backup_original:
                self.backup_file_path = self._create_backup()
                if not self.backup_file_path:
                    self.logger.warning("Failed to create backup, continuing without backup")
            
            # Copy input to output file (unless dry-run)
            if not self.dry_run:
                try:
                    shutil.copy2(self.input_file_path, self.output_file_path)
                    self.logger.info(f"Created working copy: {self.output_file_path}")
                except Exception as e:
                    self.error_handler.handle_excel_error("copy", e, str(self.input_file_path))
                    return False
            else:
                self.output_file_path = self.input_file_path
                self.logger.info("Dry-run mode: Using original file for reading only")
            
            # Setup Excel handler (for compatibility)
            self.excel_handler = ExcelHandler(self.output_file_path, self.config)
            if not self.excel_handler.load_workbook():
                self.error_handler.handle_excel_error("load", Exception("Failed to load workbook"))
                return False
            
            # Validate Excel structure
            is_valid, errors = self.excel_handler.validate_file_structure()
            if not is_valid:
                for error in errors:
                    self.error_handler.handle_validation_error("excel_structure", error)
                return False
            
            # Setup progress tracker
            total_packages = self.excel_handler.get_package_count()
            self.progress_tracker = ProgressTracker(total_packages, self.logger)
            self.logger.info(f"Found {total_packages} packages to process with enhanced columns")
            
            # Setup enhanced Excel processor (now default) - without sandbox_manager initially
            self.enhanced_excel_processor = EnhancedExcelProcessor(self.config)
            self.logger.info("Enhanced Excel processor initialized (default mode)")
            self.logger.info("Columns E, F, H, K, L, M, P, R, T, V, W will be processed automatically")
            
            # Setup sandbox manager (try real first, fallback to mock)
            try:
                # Convert config objects to dictionary format for SandboxManager
                config_dict = {
                    'redis': {
                        'enabled': True,
                        'url': 'redis://localhost:6379'
                    },
                    'ai': {
                        'enabled': False,  # Disable AI in SandboxManager to avoid missing module error
                        'provider': self.config.ai.provider,
                        'model': self.config.ai.model,
                        'temperature': self.config.ai.temperature
                    }
                }
                
                self.sandbox_manager = SandboxManager(config_dict)
                await self.sandbox_manager.initialize()
                self.logger.info("Sandbox manager initialized")
                
                # Reinitialize enhanced Excel processor with sandbox_manager
                self.enhanced_excel_processor = EnhancedExcelProcessor(self.config, self.sandbox_manager)
                self.logger.info("Enhanced Excel processor updated with sandbox manager")
            except Exception as e:
                self.logger.warning(f"Failed to initialize SandboxManager: {e}")
                self.logger.info("Falling back to Mock Sandbox Manager for demo...")
                from .mock_sandbox_manager import MockSandboxManager
                self.sandbox_manager = MockSandboxManager(self.config.__dict__)
                await self.sandbox_manager.initialize()
                self.logger.info("Mock Sandbox Manager initialized for demo")
                
                # Reinitialize enhanced Excel processor with mock sandbox_manager
                self.enhanced_excel_processor = EnhancedExcelProcessor(self.config, self.sandbox_manager)
                self.logger.info("Enhanced Excel processor updated with mock sandbox manager")
            
            # Setup report generator
            self.report_generator = ReportGenerator(self.config)
            
            # Log successful setup
            self.logger.info("Application setup completed successfully with Enhanced Columns")
            return True
            
        except Exception as e:
            if self.error_handler:
                self.error_handler.handle_system_error("setup", e)
            else:
                print(f"Critical setup error: {e}")
            return False
    
    def _validate_input_file(self) -> bool:
        """Validate input file exists and is accessible"""
        if not self.input_file_path.exists():
            self.error_handler.handle_validation_error(
                "input_file", 
                f"File not found: {self.input_file_path}"
            )
            return False
        
        if not self.input_file_path.suffix.lower() in ['.xlsx', '.xls']:
            self.error_handler.handle_validation_error(
                "input_file",
                f"File must be Excel format: {self.input_file_path}"
            )
            return False
        
        return True
    
    def _create_backup(self) -> Optional[Path]:
        """Create backup of input file"""
        try:
            backup_dir = Path(self.config.output.backup_directory)
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{self.input_file_path.stem}_backup_{timestamp}{self.input_file_path.suffix}"
            backup_path = backup_dir / backup_name
            
            shutil.copy2(self.input_file_path, backup_path)
            self.logger.info(f"Backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.error_handler.handle_excel_error("backup", e, str(self.input_file_path))
            return None
    
    async def scan_packages(self, 
                          package_names: Optional[List[str]] = None,
                          start_row: Optional[int] = None,
                          end_row: Optional[int] = None) -> bool:
        """
        Scan packages with enhanced columns processing (default behavior).
        
        Args:
            package_names: Optional list of specific packages to scan
            start_row: Optional starting row number
            end_row: Optional ending row number
            
        Returns:
            True if scanning completed successfully, False otherwise
        """
        try:
            self.logger.info("Starting enhanced vulnerability scanning with columns E, F, K, L, M, W")
            
            # Use enhanced Excel processor for full processing
            if not self.dry_run:
                self.logger.info("Processing Excel file with enhanced columns...")
                
                processing_results = await self.enhanced_excel_processor.process_excel_file(
                    str(self.input_file_path),
                    str(self.output_file_path),
                    package_names=package_names,
                    start_row=start_row,
                    end_row=end_row
                )
                
                # Store enhanced results
                self.scan_results = {
                    'metadata': {
                        'scan_date': datetime.now().isoformat(),
                        'excel_file': str(self.input_file_path),
                        'output_file': processing_results['output_file'],
                        'ihacpa_version': self.config.app.version,
                        'enhanced_columns': True,
                        'columns_processed': processing_results['enhanced_columns']
                    },
                    'summary': {
                        'packages_processed': processing_results['packages_processed'],
                        'packages_failed': processing_results['packages_failed'],
                        'success_rate': ((processing_results['packages_processed'] - processing_results['packages_failed']) / max(1, processing_results['packages_processed'])) * 100,
                        'columns_updated': processing_results['columns_updated'],
                        'processing_time': processing_results['processing_time'],
                        'ai_enhanced': processing_results['ai_enhanced']
                    },
                    'enhanced_processing': processing_results
                }
                
                self.packages_processed = processing_results['packages_processed']
                self.packages_successful = processing_results['packages_processed'] - processing_results['packages_failed']
                self.packages_failed = processing_results['packages_failed']
                
                self.logger.info(f"Enhanced processing completed:")
                self.logger.info(f"  - Packages processed: {self.packages_processed}")
                self.logger.info(f"  - Success rate: {self.scan_results['summary']['success_rate']:.1f}%")
                self.logger.info(f"  - Columns updated: {', '.join(processing_results['columns_updated'])}")
                self.logger.info(f"  - AI enhanced: {processing_results['ai_enhanced']}")
                
            else:
                # Dry run mode - just analyze without processing
                self.logger.info("Dry run mode: Analyzing packages without processing")
                packages = self._get_packages_by_rows(start_row, end_row)
                
                self.scan_results = {
                    'metadata': {
                        'scan_date': datetime.now().isoformat(),
                        'excel_file': str(self.input_file_path),
                        'ihacpa_version': self.config.app.version,
                        'dry_run': True,
                        'enhanced_columns': True
                    },
                    'summary': {
                        'packages_found': len(packages),
                        'would_process_columns': ['E', 'F', 'K', 'L', 'M', 'W'],
                        'ai_available': self.config.ai.enabled
                    }
                }
                
                self.logger.info(f"Dry run analysis: Found {len(packages)} packages")
                self.logger.info("Would process enhanced columns: E, F, K, L, M, W")
            
            return True
            
        except Exception as e:
            self.error_handler.handle_system_error("scan_packages", e)
            return False
    
    def _get_packages_by_rows(self, start_row: Optional[int] = None, 
                            end_row: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get packages within specified row range"""
        try:
            all_packages = self.excel_handler.get_all_packages()
            
            if start_row is None and end_row is None:
                return all_packages
                
            filtered_packages = []
            for package in all_packages:
                row_num = package.get('row_number', 0)
                
                # Check if row is within range
                if start_row and row_num < start_row:
                    continue
                if end_row and row_num > end_row:
                    continue
                    
                filtered_packages.append(package)
            
            return filtered_packages
            
        except Exception as e:
            self.logger.error(f"Error getting packages by rows: {e}")
            return []
    
    async def generate_reports(self) -> bool:
        """Generate comprehensive reports"""
        try:
            if not self.scan_results:
                self.logger.warning("No scan results available for reporting")
                return True
            
            self.logger.info("Generating enhanced reports...")
            
            # Generate summary report
            await self.report_generator.generate_summary_report(self.scan_results)
            
            # Generate detailed report if available
            if 'enhanced_processing' in self.scan_results:
                await self.report_generator.generate_detailed_report(
                    self.scan_results['enhanced_processing']
                )
            
            # Generate change tracking report
            if self.excel_handler and hasattr(self.excel_handler, 'changes_made'):
                changes_report = {
                    'changes': self.excel_handler.changes_made,
                    'timestamp': datetime.now().isoformat(),
                    'enhanced_columns': True
                }
                await self.report_generator.generate_changes_report(changes_report)
            
            self.logger.info("Enhanced reports generated successfully")
            return True
            
        except Exception as e:
            self.error_handler.handle_system_error("generate_reports", e)
            return False
    
    async def cleanup(self):
        """Clean up all resources"""
        try:
            self.logger.info("Cleaning up resources...")
            
            # Cleanup enhanced Excel processor
            if self.enhanced_excel_processor:
                await self.enhanced_excel_processor.cleanup()
            
            # Cleanup sandbox manager
            if self.sandbox_manager:
                await self.sandbox_manager.cleanup()
            
            # Close logger
            if self.logger_manager:
                self.logger_manager.close_handlers()
            
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error during cleanup: {e}")
    
    def get_processing_summary(self) -> Dict[str, Any]:
        """Get summary of processing results"""
        return {
            'input_file': str(self.input_file_path) if self.input_file_path else None,
            'output_file': str(self.output_file_path) if self.output_file_path else None,
            'backup_file': str(self.backup_file_path) if self.backup_file_path else None,
            'packages_processed': self.packages_processed,
            'packages_successful': self.packages_successful,
            'packages_failed': self.packages_failed,
            'success_rate': (self.packages_successful / max(1, self.packages_processed)) * 100,
            'enhanced_columns_enabled': True,
            'columns_processed': ['E', 'F', 'K', 'L', 'M', 'W'],
            'ai_enhanced': self.config.ai.enabled,
            'scan_results_available': bool(self.scan_results)
        }