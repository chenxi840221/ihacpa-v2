"""
Advanced Logging Manager for IHACPA v2.0

Provides comprehensive logging capabilities with multiple handlers, rotation,
and component-specific loggers.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from ..config import Config


class LoggerManager:
    """Advanced logging manager with multiple handlers and configurations"""
    
    def __init__(self, config: Config):
        """
        Initialize logger manager.
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.handlers: Dict[str, logging.Handler] = {}
        self.loggers: Dict[str, logging.Logger] = {}
        self.main_logger: Optional[logging.Logger] = None
        
    def setup_logging(self) -> logging.Logger:
        """
        Setup comprehensive logging system.
        
        Returns:
            Main application logger
        """
        # Create logs directory
        log_dir = Path(self.config.logging.log_directory)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create main logger
        self.main_logger = logging.getLogger('ihacpa')
        self.main_logger.setLevel(getattr(logging, self.config.logging.level.upper()))
        
        # Clear existing handlers
        self.main_logger.handlers.clear()
        
        # Setup console handler
        if self.config.logging.console_output:
            self._setup_console_handler()
        
        # Setup file handlers
        self._setup_file_handlers(log_dir)
        
        # Setup component-specific loggers
        self._setup_component_loggers()
        
        # Log initialization
        self.main_logger.info("=" * 80)
        self.main_logger.info(f"{self.config.app.name} v{self.config.app.version}")
        self.main_logger.info("=" * 80)
        self.main_logger.info("Logging system initialized")
        self.main_logger.info(f"Log level: {self.config.logging.level}")
        self.main_logger.info(f"Log directory: {self.config.logging.log_directory}")
        
        return self.main_logger
    
    def _setup_console_handler(self):
        """Setup console logging handler"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, self.config.logging.level.upper()))
        
        # Console formatter (simpler format for readability)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        
        self.main_logger.addHandler(console_handler)
        self.handlers['console'] = console_handler
    
    def _setup_file_handlers(self, log_dir: Path):
        """Setup file logging handlers"""
        # Main log file
        main_log_file = log_dir / f"ihacpa_{datetime.now().strftime('%Y%m%d')}.log"
        
        if self.config.logging.file_rotation:
            main_handler = logging.handlers.RotatingFileHandler(
                main_log_file,
                maxBytes=self._parse_size(self.config.logging.max_file_size),
                backupCount=self.config.logging.backup_count,
                encoding='utf-8'
            )
        else:
            main_handler = logging.FileHandler(main_log_file, encoding='utf-8')
        
        main_handler.setLevel(getattr(logging, self.config.logging.level.upper()))
        
        # File formatter (detailed format)
        file_formatter = logging.Formatter(
            self.config.logging.log_format,
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        main_handler.setFormatter(file_formatter)
        
        self.main_logger.addHandler(main_handler)
        self.handlers['main_file'] = main_handler
        
        # Error-specific log file
        error_log_file = log_dir / f"ihacpa_errors_{datetime.now().strftime('%Y%m%d')}.log"
        error_handler = logging.FileHandler(error_log_file, encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        
        self.main_logger.addHandler(error_handler)
        self.handlers['error_file'] = error_handler
    
    def _setup_component_loggers(self):
        """Setup component-specific loggers"""
        components = [
            'ai_layer',
            'sandboxes', 
            'excel_io',
            'automation',
            'scanning'
        ]
        
        for component in components:
            logger = self.get_component_logger(component)
            self.loggers[component] = logger
    
    def get_component_logger(self, component_name: str) -> logging.Logger:
        """
        Get or create a component-specific logger.
        
        Args:
            component_name: Name of the component
            
        Returns:
            Logger instance for the component
        """
        logger_name = f'ihacpa.{component_name}'
        
        if logger_name in self.loggers:
            return self.loggers[logger_name]
        
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, self.config.logging.level.upper()))
        
        # Component loggers inherit from main logger but can have additional handlers
        if component_name in ['ai_layer', 'scanning']:
            # These components might need separate log files for detailed analysis
            self._add_component_file_handler(logger, component_name)
        
        self.loggers[logger_name] = logger
        return logger
    
    def _add_component_file_handler(self, logger: logging.Logger, component_name: str):
        """Add a dedicated file handler for a component"""
        log_dir = Path(self.config.logging.log_directory)
        component_log_file = log_dir / f"{component_name}_{datetime.now().strftime('%Y%m%d')}.log"
        
        component_handler = logging.FileHandler(component_log_file, encoding='utf-8')
        component_handler.setLevel(logging.DEBUG)  # More detailed for components
        
        component_formatter = logging.Formatter(
            f'%(asctime)s - {component_name.upper()} - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        component_handler.setFormatter(component_formatter)
        logger.addHandler(component_handler)
        
        self.handlers[f'{component_name}_file'] = component_handler
    
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
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """
        Get a logger instance.
        
        Args:
            name: Optional logger name (component name)
            
        Returns:
            Logger instance
        """
        if name:
            return self.get_component_logger(name)
        return self.main_logger or logging.getLogger('ihacpa')
    
    def log_system_info(self):
        """Log system and configuration information"""
        import platform
        import sys
        
        self.main_logger.info("System Information:")
        self.main_logger.info(f"  Platform: {platform.platform()}")
        self.main_logger.info(f"  Python: {sys.version}")
        self.main_logger.info(f"  Working Directory: {Path.cwd()}")
        
        self.main_logger.info("Configuration:")
        self.main_logger.info(f"  Environment: {self.config.app.environment}")
        self.main_logger.info(f"  Debug Mode: {self.config.app.debug_mode}")
        self.main_logger.info(f"  AI Enabled: {self.config.ai.enabled}")
        if self.config.ai.enabled:
            self.main_logger.info(f"  AI Provider: {self.config.ai.provider}")
            self.main_logger.info(f"  AI Model: {self.config.ai.model}")
    
    def close_handlers(self):
        """Close all logging handlers"""
        for handler_name, handler in self.handlers.items():
            try:
                handler.close()
            except Exception as e:
                print(f"Error closing handler {handler_name}: {e}")
        
        self.handlers.clear()
        
        if self.main_logger:
            self.main_logger.info("Logging system shutdown")


def setup_logging(config: Config) -> tuple[logging.Logger, LoggerManager]:
    """
    Setup logging system and return logger and manager.
    
    Args:
        config: Application configuration
        
    Returns:
        Tuple of (main_logger, logger_manager)
    """
    manager = LoggerManager(config)
    main_logger = manager.setup_logging()
    manager.log_system_info()
    
    return main_logger, manager