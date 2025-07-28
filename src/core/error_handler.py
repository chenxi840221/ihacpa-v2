"""
Error Handler for IHACPA v2.0

Provides comprehensive error handling with categorization, tracking,
and recovery mechanisms.
"""

import logging
import traceback
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass


class ErrorCategory(Enum):
    """Error categories for classification"""
    CONFIGURATION = "configuration"
    EXCEL_IO = "excel_io"
    NETWORK = "network"
    AI_SERVICE = "ai_service"
    SANDBOX = "sandbox"
    VALIDATION = "validation"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorRecord:
    """Record of an error occurrence"""
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    context: Dict[str, Any]
    timestamp: datetime
    traceback_info: Optional[str] = None
    component: Optional[str] = None
    package_name: Optional[str] = None
    resolution_attempted: bool = False
    resolution_successful: bool = False


class ErrorHandler:
    """Comprehensive error handling and tracking system"""
    
    def __init__(self, logger: logging.Logger):
        """
        Initialize error handler.
        
        Args:
            logger: Logger instance for error reporting
        """
        self.logger = logger
        self.error_records: List[ErrorRecord] = []
        self.error_counts: Dict[ErrorCategory, int] = {}
        self.recovery_handlers: Dict[ErrorCategory, List[Callable]] = {}
        
        # Initialize error counters
        for category in ErrorCategory:
            self.error_counts[category] = 0
    
    def handle_error(self,
                    category: ErrorCategory,
                    severity: ErrorSeverity,
                    message: str,
                    exception: Optional[Exception] = None,
                    context: Optional[Dict[str, Any]] = None,
                    component: Optional[str] = None,
                    package_name: Optional[str] = None,
                    attempt_recovery: bool = True) -> bool:
        """
        Handle an error with comprehensive logging and optional recovery.
        
        Args:
            category: Error category
            severity: Error severity level
            message: Error message
            exception: Optional exception object
            context: Additional context information
            component: Component where error occurred
            package_name: Package being processed when error occurred
            attempt_recovery: Whether to attempt automatic recovery
            
        Returns:
            True if error was handled successfully (possibly recovered), False otherwise
        """
        # Create error record
        error_record = ErrorRecord(
            category=category,
            severity=severity,
            message=message,
            context=context or {},
            timestamp=datetime.now(),
            component=component,
            package_name=package_name
        )
        
        # Add traceback if exception provided
        if exception:
            error_record.traceback_info = traceback.format_exc()
            # Enhance message with exception details
            error_record.message = f"{message}: {str(exception)}"
        
        # Log the error
        self._log_error(error_record)
        
        # Store error record
        self.error_records.append(error_record)
        self.error_counts[category] += 1
        
        # Attempt recovery if requested and handlers are available
        recovery_successful = False
        if attempt_recovery and category in self.recovery_handlers:
            recovery_successful = self._attempt_recovery(error_record)
            error_record.resolution_attempted = True
            error_record.resolution_successful = recovery_successful
        
        return recovery_successful
    
    def handle_configuration_error(self, operation: str, error: Exception, context: Optional[Dict[str, Any]] = None):
        """Handle configuration-related errors"""
        return self.handle_error(
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.HIGH,
            message=f"Configuration {operation} error",
            exception=error,
            context=context,
            component="configuration"
        )
    
    def handle_excel_error(self, operation: str, error: Exception, 
                          file_path: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        """Handle Excel I/O errors"""
        context = context or {}
        if file_path:
            context['file_path'] = file_path
            
        return self.handle_error(
            category=ErrorCategory.EXCEL_IO,
            severity=ErrorSeverity.MEDIUM,
            message=f"Excel {operation} error",
            exception=error,
            context=context,
            component="excel_io"
        )
    
    def handle_network_error(self, operation: str, error: Exception,
                           url: Optional[str] = None, package_name: Optional[str] = None):
        """Handle network-related errors"""
        context = {}
        if url:
            context['url'] = url
            
        return self.handle_error(
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.MEDIUM,
            message=f"Network {operation} error",
            exception=error,
            context=context,
            component="network",
            package_name=package_name
        )
    
    def handle_ai_service_error(self, operation: str, error: Exception,
                              provider: Optional[str] = None, model: Optional[str] = None,
                              package_name: Optional[str] = None):
        """Handle AI service errors"""
        context = {}
        if provider:
            context['provider'] = provider
        if model:
            context['model'] = model
            
        severity = ErrorSeverity.HIGH if 'auth' in str(error).lower() else ErrorSeverity.MEDIUM
            
        return self.handle_error(
            category=ErrorCategory.AI_SERVICE,
            severity=severity,
            message=f"AI service {operation} error",
            exception=error,
            context=context,
            component="ai_layer",
            package_name=package_name
        )
    
    def handle_sandbox_error(self, sandbox_name: str, operation: str, error: Exception,
                           package_name: Optional[str] = None):
        """Handle sandbox-specific errors"""
        return self.handle_error(
            category=ErrorCategory.SANDBOX,
            severity=ErrorSeverity.MEDIUM,
            message=f"Sandbox {sandbox_name} {operation} error",
            exception=error,
            context={'sandbox': sandbox_name},
            component="sandboxes",
            package_name=package_name
        )
    
    def handle_validation_error(self, item: str, message: str, context: Optional[Dict[str, Any]] = None):
        """Handle validation errors"""
        return self.handle_error(
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            message=f"Validation error for {item}: {message}",
            context=context,
            component="validation"
        )
    
    def handle_system_error(self, operation: str, error: Exception, context: Optional[Dict[str, Any]] = None):
        """Handle system-level errors"""
        return self.handle_error(
            category=ErrorCategory.SYSTEM,
            severity=ErrorSeverity.CRITICAL,
            message=f"System {operation} error",
            exception=error,
            context=context,
            component="system"
        )
    
    def _log_error(self, error_record: ErrorRecord):
        """Log error based on severity"""
        log_message = f"[{error_record.category.value.upper()}] {error_record.message}"
        
        if error_record.component:
            log_message = f"[{error_record.component}] {log_message}"
        
        if error_record.package_name:
            log_message = f"Package '{error_record.package_name}': {log_message}"
        
        # Add context information
        if error_record.context:
            context_str = ", ".join([f"{k}={v}" for k, v in error_record.context.items()])
            log_message = f"{log_message} (Context: {context_str})"
        
        # Log based on severity
        if error_record.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message)
        elif error_record.severity == ErrorSeverity.HIGH:
            self.logger.error(log_message)
        elif error_record.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Log traceback for higher severity errors
        if error_record.traceback_info and error_record.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            self.logger.debug(f"Traceback:\n{error_record.traceback_info}")
    
    def _attempt_recovery(self, error_record: ErrorRecord) -> bool:
        """Attempt automatic error recovery"""
        handlers = self.recovery_handlers.get(error_record.category, [])
        
        for handler in handlers:
            try:
                if handler(error_record):
                    self.logger.info(f"Successfully recovered from {error_record.category.value} error")
                    return True
            except Exception as e:
                self.logger.debug(f"Recovery handler failed: {e}")
        
        return False
    
    def register_recovery_handler(self, category: ErrorCategory, handler: Callable[[ErrorRecord], bool]):
        """
        Register a recovery handler for a specific error category.
        
        Args:
            category: Error category to handle
            handler: Callable that takes an ErrorRecord and returns True if recovery successful
        """
        if category not in self.recovery_handlers:
            self.recovery_handlers[category] = []
        
        self.recovery_handlers[category].append(handler)
    
    def get_error_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive error summary.
        
        Returns:
            Dictionary with error statistics and summaries
        """
        if not self.error_records:
            return {'total_errors': 0, 'error_free': True}
        
        # Count by category
        category_counts = {}
        for category in ErrorCategory:
            category_counts[category.value] = self.error_counts[category]
        
        # Count by severity
        severity_counts = {}
        for severity in ErrorSeverity:
            severity_counts[severity.value] = len([e for e in self.error_records if e.severity == severity])
        
        # Count by component
        component_counts = {}
        for record in self.error_records:
            if record.component:
                component_counts[record.component] = component_counts.get(record.component, 0) + 1
        
        # Recent errors (last 10)
        recent_errors = []
        for record in self.error_records[-10:]:
            recent_errors.append({
                'timestamp': record.timestamp.isoformat(),
                'category': record.category.value,
                'severity': record.severity.value,
                'message': record.message,
                'component': record.component,
                'package_name': record.package_name
            })
        
        # Recovery statistics
        recovery_attempted = len([e for e in self.error_records if e.resolution_attempted])
        recovery_successful = len([e for e in self.error_records if e.resolution_successful])
        
        return {
            'total_errors': len(self.error_records),
            'error_free': False,
            'category_breakdown': category_counts,
            'severity_breakdown': severity_counts,
            'component_breakdown': component_counts,
            'recovery_stats': {
                'attempted': recovery_attempted,
                'successful': recovery_successful,
                'success_rate': (recovery_successful / max(1, recovery_attempted)) * 100
            },
            'recent_errors': recent_errors
        }
    
    def log_error_summary(self):
        """Log comprehensive error summary"""
        summary = self.get_error_summary()
        
        if summary['error_free']:
            self.logger.info("✅ No errors encountered during processing")
            return
        
        self.logger.info("ERROR SUMMARY")
        self.logger.info("-" * 40)
        self.logger.info(f"Total errors: {summary['total_errors']}")
        
        # Log by category
        self.logger.info("Errors by category:")
        for category, count in summary['category_breakdown'].items():
            if count > 0:
                self.logger.info(f"  {category}: {count}")
        
        # Log by severity
        self.logger.info("Errors by severity:")
        for severity, count in summary['severity_breakdown'].items():
            if count > 0:
                emoji = {"critical": "🚨", "high": "⚠️", "medium": "📋", "low": "ℹ️"}.get(severity, "")
                self.logger.info(f"  {emoji} {severity}: {count}")
        
        # Log recovery stats
        recovery = summary['recovery_stats']
        if recovery['attempted'] > 0:
            self.logger.info(f"Recovery attempts: {recovery['attempted']} "
                           f"({recovery['success_rate']:.1f}% successful)")
    
    def get_critical_errors(self) -> List[ErrorRecord]:
        """Get all critical errors"""
        return [e for e in self.error_records if e.severity == ErrorSeverity.CRITICAL]
    
    def get_errors_by_package(self, package_name: str) -> List[ErrorRecord]:
        """Get all errors for a specific package"""
        return [e for e in self.error_records if e.package_name == package_name]
    
    def clear_errors(self):
        """Clear all error records (use with caution)"""
        self.error_records.clear()
        for category in ErrorCategory:
            self.error_counts[category] = 0
        self.logger.info("Error records cleared")