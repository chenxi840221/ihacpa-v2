#!/usr/bin/env python3
"""
Logging System for IHACPA Python Package Review Automation
Handles logging configuration and setup for the application
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from config import Config, LoggingConfig


class LoggerSetup:
    """Setup and manage logging for the application"""
    
    def __init__(self, config: LoggingConfig):
        """Initialize logger setup with configuration"""
        self.config = config
        self.logger = None
        self.handlers = []
        
    def setup_logging(self) -> logging.Logger:
        """Setup logging with configuration"""
        # Create logs directory if it doesn't exist
        log_dir = Path(self.config.log_directory)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create main logger
        self.logger = logging.getLogger('ihacpa_automation')
        self.logger.setLevel(getattr(logging, self.config.level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Setup console handler
        if self.config.console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, self.config.level.upper()))
            
            # Console formatter (simpler format)
            console_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
            self.handlers.append(console_handler)
        
        # Setup file handler
        log_file = log_dir / f"ihacpa_automation_{datetime.now().strftime('%Y%m%d')}.log"
        
        if self.config.file_rotation:
            # Use rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=self._parse_size(self.config.max_file_size),
                backupCount=self.config.backup_count
            )
        else:
            # Use regular file handler
            file_handler = logging.FileHandler(log_file)
        
        file_handler.setLevel(getattr(logging, self.config.level.upper()))
        
        # File formatter (detailed format)
        file_formatter = logging.Formatter(
            self.config.log_format,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        self.handlers.append(file_handler)
        
        # Setup error file handler for ERROR and CRITICAL messages
        error_log_file = log_dir / f"ihacpa_automation_errors_{datetime.now().strftime('%Y%m%d')}.log"
        error_handler = logging.FileHandler(error_log_file)
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        self.logger.addHandler(error_handler)
        self.handlers.append(error_handler)
        
        return self.logger
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10MB' to bytes"""
        size_str = size_str.upper()
        if size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)
    
    def add_database_logger(self, database_name: str) -> logging.Logger:
        """Add a separate logger for database operations"""
        db_logger = logging.getLogger(f'ihacpa_automation.{database_name}')
        db_logger.setLevel(getattr(logging, self.config.level.upper()))
        
        # Database-specific log file
        log_dir = Path(self.config.log_directory)
        db_log_file = log_dir / f"{database_name}_{datetime.now().strftime('%Y%m%d')}.log"
        
        db_handler = logging.FileHandler(db_log_file)
        db_handler.setLevel(getattr(logging, self.config.level.upper()))
        
        db_formatter = logging.Formatter(
            f'%(asctime)s - {database_name.upper()} - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        db_handler.setFormatter(db_formatter)
        db_logger.addHandler(db_handler)
        
        return db_logger
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """Get a logger instance"""
        if name:
            return logging.getLogger(f'ihacpa_automation.{name}')
        return self.logger or logging.getLogger('ihacpa_automation')
    
    def close_handlers(self):
        """Close all logging handlers"""
        for handler in self.handlers:
            handler.close()
        self.handlers.clear()


class ProgressLogger:
    """Logger for tracking progress during package processing"""
    
    def __init__(self, logger: logging.Logger, total_packages: int):
        """Initialize progress logger"""
        self.logger = logger
        self.total_packages = total_packages
        self.processed_packages = 0
        self.failed_packages = 0
        self.start_time = datetime.now()
        
    def log_package_start(self, package_name: str, package_index: int):
        """Log start of package processing"""
        self.logger.info(f"Processing package {package_index}/{self.total_packages}: {package_name}")
    
    def log_package_success(self, package_name: str, processing_time: float):
        """Log successful package processing"""
        self.processed_packages += 1
        self.logger.info(f"✅ Completed {package_name} in {processing_time:.2f}s")
        self._log_progress()
    
    def log_package_failure(self, package_name: str, error: str):
        """Log failed package processing"""
        self.failed_packages += 1
        self.logger.error(f"❌ Failed to process {package_name}: {error}")
        self._log_progress()
    
    def log_vulnerability_found(self, package_name: str, database: str, count: int):
        """Log vulnerability findings"""
        self.logger.warning(f"🔍 {package_name}: Found {count} vulnerabilities in {database}")
    
    def log_package_update_available(self, package_name: str, current_version: str, latest_version: str):
        """Log package update availability"""
        self.logger.info(f"📦 {package_name}: Update available {current_version} → {latest_version}")
    
    def _log_progress(self):
        """Log overall progress"""
        total_processed = self.processed_packages + self.failed_packages
        progress_percent = (total_processed / self.total_packages) * 100
        
        elapsed_time = (datetime.now() - self.start_time).total_seconds()
        if total_processed > 0:
            avg_time_per_package = elapsed_time / total_processed
            estimated_remaining = avg_time_per_package * (self.total_packages - total_processed)
            
            self.logger.info(
                f"Progress: {total_processed}/{self.total_packages} ({progress_percent:.1f}%) "
                f"| Success: {self.processed_packages} | Failed: {self.failed_packages} "
                f"| Est. remaining: {estimated_remaining/60:.1f}min"
            )
    
    def log_final_summary(self):
        """Log final processing summary"""
        total_time = (datetime.now() - self.start_time).total_seconds()
        
        self.logger.info("="*60)
        self.logger.info("PROCESSING SUMMARY")
        self.logger.info("="*60)
        self.logger.info(f"Total packages: {self.total_packages}")
        self.logger.info(f"Successfully processed: {self.processed_packages}")
        self.logger.info(f"Failed: {self.failed_packages}")
        self.logger.info(f"Success rate: {(self.processed_packages/self.total_packages)*100:.1f}%")
        self.logger.info(f"Total time: {total_time/60:.1f} minutes")
        self.logger.info(f"Average time per package: {total_time/self.total_packages:.2f} seconds")
        self.logger.info("="*60)


class ErrorHandler:
    """Enhanced error handling and logging"""
    
    def __init__(self, logger: logging.Logger):
        """Initialize error handler"""
        self.logger = logger
        self.error_counts = {}
        
    def handle_excel_error(self, operation: str, error: Exception, context: Dict[str, Any] = None):
        """Handle Excel operation errors"""
        error_msg = f"Excel {operation} error: {str(error)}"
        if context:
            error_msg += f" | Context: {context}"
        
        self.logger.error(error_msg)
        self._track_error('excel', operation)
    
    def handle_pypi_error(self, package_name: str, error: Exception, context: Dict[str, Any] = None):
        """Handle PyPI API errors"""
        error_msg = f"PyPI error for {package_name}: {str(error)}"
        if context:
            error_msg += f" | Context: {context}"
        
        self.logger.error(error_msg)
        self._track_error('pypi', package_name)
    
    def handle_vulnerability_error(self, package_name: str, database: str, error: Exception):
        """Handle vulnerability scanning errors"""
        error_msg = f"Vulnerability scan error for {package_name} in {database}: {str(error)}"
        self.logger.error(error_msg)
        self._track_error('vulnerability', f"{database}:{package_name}")
    
    def handle_config_error(self, operation: str, error: Exception):
        """Handle configuration errors"""
        error_msg = f"Configuration {operation} error: {str(error)}"
        self.logger.error(error_msg)
        self._track_error('config', operation)
    
    def _track_error(self, category: str, identifier: str):
        """Track error occurrences"""
        if category not in self.error_counts:
            self.error_counts[category] = {}
        
        if identifier not in self.error_counts[category]:
            self.error_counts[category][identifier] = 0
        
        self.error_counts[category][identifier] += 1
    
    def get_error_summary(self) -> Dict[str, Dict[str, int]]:
        """Get summary of all errors"""
        return self.error_counts.copy()
    
    def log_error_summary(self):
        """Log summary of all errors"""
        if not self.error_counts:
            self.logger.info("No errors encountered during processing")
            return
        
        self.logger.info("ERROR SUMMARY")
        self.logger.info("-" * 40)
        
        for category, errors in self.error_counts.items():
            self.logger.info(f"{category.upper()} ERRORS:")
            for identifier, count in errors.items():
                self.logger.info(f"  {identifier}: {count} occurrences")
        
        total_errors = sum(sum(errors.values()) for errors in self.error_counts.values())
        self.logger.info(f"Total errors: {total_errors}")


def setup_application_logging(config: Config) -> tuple[logging.Logger, ProgressLogger, ErrorHandler]:
    """Setup complete logging system for the application"""
    # Setup main logging
    logger_setup = LoggerSetup(config.logging)
    main_logger = logger_setup.setup_logging()
    
    # Setup progress logger
    progress_logger = ProgressLogger(main_logger, config.processing.total_packages)
    
    # Setup error handler
    error_handler = ErrorHandler(main_logger)
    
    # Log application startup
    main_logger.info("="*60)
    main_logger.info(f"IHACPA Python Package Review Automation v{config.app.version}")
    main_logger.info("="*60)
    main_logger.info(f"Configuration loaded from: {config.loaded_from}")
    main_logger.info(f"Total packages to process: {config.processing.total_packages}")
    main_logger.info(f"Logging level: {config.logging.level}")
    main_logger.info(f"Log directory: {config.logging.log_directory}")
    main_logger.info("="*60)
    
    return main_logger, progress_logger, error_handler