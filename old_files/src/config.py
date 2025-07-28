#!/usr/bin/env python3
"""
Configuration Management for IHACPA Python Package Review Automation
Handles loading and managing configuration settings from YAML files
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AppConfig:
    """Application configuration"""
    name: str = "IHACPA Python Package Review Automation"
    version: str = "1.5.0"
    log_level: str = "INFO"
    debug_mode: bool = False


@dataclass
class ProcessingConfig:
    """Processing configuration"""
    concurrent_requests: int = 5
    request_timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 2
    batch_size: int = 50
    total_packages: int = 486
    rate_limit_delay: float = 1.0


@dataclass
class ExcelConfig:
    """Excel file configuration"""
    backup_original: bool = True
    preserve_formatting: bool = True
    header_row: int = 3
    total_columns: int = 23
    data_start_row: int = 4
    timestamp_backups: bool = True
    sheet_name: str = "Sheet1"
    
    column_mapping: Dict[str, int] = field(default_factory=lambda: {
        'index': 1,
        'package_name': 2,
        'current_version': 3,
        'pypi_current_link': 4,
        'date_published': 5,
        'latest_version': 6,
        'pypi_latest_link': 7,
        'latest_release_date': 8,
        'requires': 9,
        'development_status': 10,
        'github_url': 11,
        'github_advisory_url': 12,
        'github_advisory_result': 13,
        'notes': 14,
        'nist_nvd_url': 15,
        'nist_nvd_result': 16,
        'mitre_cve_url': 17,
        'mitre_cve_result': 18,
        'snyk_url': 19,
        'snyk_result': 20,
        'exploit_db_url': 21,
        'exploit_db_result': 22,
        'recommendation': 23
    })


@dataclass
class OutputConfig:
    """Output configuration"""
    generate_summary: bool = True
    create_reports: bool = True
    timestamp_files: bool = True
    export_formats: list = field(default_factory=lambda: ["xlsx", "csv", "json"])
    backup_directory: str = "data/backups"
    output_directory: str = "data/output"
    report_directory: str = "data/reports"


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file_rotation: bool = True
    max_file_size: str = "10MB"
    backup_count: int = 5
    log_directory: str = "logs"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    console_output: bool = True


@dataclass
class DatabaseConfig:
    """Database configuration for vulnerability scanning"""
    enabled_databases: list = field(default_factory=lambda: [
        'nist_nvd', 'mitre_cve', 'snyk', 'exploit_db', 'github_advisory'
    ])
    
    database_settings: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        'nist_nvd': {
            'name': 'NIST NVD',
            'base_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'timeout': 30,
            'rate_limit': 2.0
        },
        'mitre_cve': {
            'name': 'MITRE CVE',
            'base_url': 'https://cve.mitre.org/cgi-bin/cvekey.cgi',
            'timeout': 30,
            'rate_limit': 2.0
        },
        'snyk': {
            'name': 'SNYK',
            'base_url': 'https://security.snyk.io/vuln/pip',
            'timeout': 30,
            'rate_limit': 2.0
        },
        'exploit_db': {
            'name': 'Exploit Database',
            'base_url': 'https://www.exploit-db.com/search',
            'timeout': 30,
            'rate_limit': 2.0
        },
        'github_advisory': {
            'name': 'GitHub Security Advisory',
            'base_url': 'https://github.com/advisories',
            'timeout': 30,
            'rate_limit': 2.0
        }
    })


@dataclass
class Config:
    """Main configuration class"""
    app: AppConfig = field(default_factory=AppConfig)
    processing: ProcessingConfig = field(default_factory=ProcessingConfig)
    excel: ExcelConfig = field(default_factory=ExcelConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    
    # API Keys and external services
    openai_api_key: Optional[str] = None
    azure_openai_endpoint: Optional[str] = None
    azure_openai_model: Optional[str] = None
    azure_openai_api_version: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization setup"""
        self.loaded_from: Optional[str] = None
        self.loaded_at: Optional[datetime] = None
        
        # Load API keys from environment if not set
        if not self.openai_api_key:
            self.openai_api_key = os.getenv('OPENAI_API_KEY') or os.getenv('AZURE_OPENAI_KEY')
        
        # Load Azure OpenAI settings from environment if not set
        if not self.azure_openai_endpoint:
            self.azure_openai_endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
        
        if not self.azure_openai_model:
            self.azure_openai_model = os.getenv('AZURE_OPENAI_MODEL')
            
        if not self.azure_openai_api_version:
            self.azure_openai_api_version = os.getenv('AZURE_OPENAI_API_VERSION')
            
        # Auto-detect Azure if endpoint is provided or key doesn't start with sk-
        if self.azure_openai_endpoint or (self.openai_api_key and not self.openai_api_key.startswith('sk-')):
            self.is_azure_openai = True
        else:
            self.is_azure_openai = False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        return getattr(self, key, default)


class ConfigManager:
    """Configuration manager for loading and managing settings"""
    
    DEFAULT_CONFIG_PATHS = [
        "config/settings.yaml",
        "05-Configuration-Templates/settings-template.yaml",
        "settings.yaml"
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager"""
        self.config_path = config_path
        self.config = Config()
        self.logger = logging.getLogger(__name__)
        
    def load_config(self, config_path: Optional[str] = None) -> Config:
        """Load configuration from YAML file"""
        if config_path:
            self.config_path = config_path
            
        # Try to find configuration file
        config_file = self._find_config_file()
        
        if config_file:
            try:
                self.config = self._load_from_file(config_file)
                self.logger.info(f"Configuration loaded from: {config_file}")
            except Exception as e:
                self.logger.error(f"Error loading configuration from {config_file}: {e}")
                self.logger.info("Using default configuration")
        else:
            self.logger.warning("No configuration file found, using defaults")
            
        # Ensure directories exist
        self._create_directories()
        
        return self.config
    
    def _find_config_file(self) -> Optional[Path]:
        """Find the configuration file"""
        if self.config_path:
            config_path = Path(self.config_path)
            if config_path.exists():
                return config_path
            else:
                self.logger.warning(f"Specified config file not found: {config_path}")
        
        # Try default paths
        for path in self.DEFAULT_CONFIG_PATHS:
            config_path = Path(path)
            if config_path.exists():
                return config_path
                
        return None
    
    def _load_from_file(self, config_file: Path) -> Config:
        """Load configuration from YAML file"""
        with open(config_file, 'r') as f:
            yaml_data = yaml.safe_load(f)
        
        config = Config()
        
        # Load app settings
        if 'app' in yaml_data:
            app_data = yaml_data['app']
            config.app = AppConfig(
                name=app_data.get('name', config.app.name),
                version=app_data.get('version', config.app.version),
                log_level=app_data.get('log_level', config.app.log_level),
                debug_mode=app_data.get('debug_mode', config.app.debug_mode)
            )
        
        # Load processing settings
        if 'processing' in yaml_data:
            proc_data = yaml_data['processing']
            config.processing = ProcessingConfig(
                concurrent_requests=proc_data.get('concurrent_requests', config.processing.concurrent_requests),
                request_timeout=proc_data.get('request_timeout', config.processing.request_timeout),
                retry_attempts=proc_data.get('retry_attempts', config.processing.retry_attempts),
                retry_delay=proc_data.get('retry_delay', config.processing.retry_delay),
                batch_size=proc_data.get('batch_size', config.processing.batch_size),
                total_packages=proc_data.get('total_packages', config.processing.total_packages),
                rate_limit_delay=proc_data.get('rate_limit_delay', config.processing.rate_limit_delay)
            )
        
        # Load Excel settings
        if 'excel' in yaml_data:
            excel_data = yaml_data['excel']
            config.excel = ExcelConfig(
                backup_original=excel_data.get('backup_original', config.excel.backup_original),
                preserve_formatting=excel_data.get('preserve_formatting', config.excel.preserve_formatting),
                header_row=excel_data.get('header_row', config.excel.header_row),
                total_columns=excel_data.get('total_columns', config.excel.total_columns),
                data_start_row=excel_data.get('data_start_row', config.excel.data_start_row),
                timestamp_backups=excel_data.get('timestamp_backups', config.excel.timestamp_backups),
                sheet_name=excel_data.get('sheet_name', config.excel.sheet_name)
            )
        
        # Load output settings
        if 'output' in yaml_data:
            output_data = yaml_data['output']
            config.output = OutputConfig(
                generate_summary=output_data.get('generate_summary', config.output.generate_summary),
                create_reports=output_data.get('create_reports', config.output.create_reports),
                timestamp_files=output_data.get('timestamp_files', config.output.timestamp_files),
                export_formats=output_data.get('export_formats', config.output.export_formats),
                backup_directory=output_data.get('backup_directory', config.output.backup_directory),
                output_directory=output_data.get('output_directory', config.output.output_directory),
                report_directory=output_data.get('report_directory', config.output.report_directory)
            )
        
        # Load logging settings
        if 'logging' in yaml_data:
            log_data = yaml_data['logging']
            config.logging = LoggingConfig(
                level=log_data.get('level', config.logging.level),
                file_rotation=log_data.get('file_rotation', config.logging.file_rotation),
                max_file_size=log_data.get('max_file_size', config.logging.max_file_size),
                backup_count=log_data.get('backup_count', config.logging.backup_count),
                log_directory=log_data.get('log_directory', config.logging.log_directory),
                log_format=log_data.get('log_format', config.logging.log_format),
                console_output=log_data.get('console_output', config.logging.console_output)
            )
        
        config.loaded_from = str(config_file)
        config.loaded_at = datetime.now()
        
        return config
    
    def _create_directories(self):
        """Create necessary directories"""
        directories = [
            self.config.output.backup_directory,
            self.config.output.output_directory,
            self.config.output.report_directory,
            self.config.logging.log_directory
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def save_config(self, config_path: Optional[str] = None) -> bool:
        """Save current configuration to YAML file"""
        if config_path:
            save_path = Path(config_path)
        else:
            save_path = Path("config/settings.yaml")
        
        try:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            
            config_dict = {
                'app': {
                    'name': self.config.app.name,
                    'version': self.config.app.version,
                    'log_level': self.config.app.log_level,
                    'debug_mode': self.config.app.debug_mode
                },
                'processing': {
                    'concurrent_requests': self.config.processing.concurrent_requests,
                    'request_timeout': self.config.processing.request_timeout,
                    'retry_attempts': self.config.processing.retry_attempts,
                    'retry_delay': self.config.processing.retry_delay,
                    'batch_size': self.config.processing.batch_size,
                    'total_packages': self.config.processing.total_packages,
                    'rate_limit_delay': self.config.processing.rate_limit_delay
                },
                'excel': {
                    'backup_original': self.config.excel.backup_original,
                    'preserve_formatting': self.config.excel.preserve_formatting,
                    'header_row': self.config.excel.header_row,
                    'total_columns': self.config.excel.total_columns,
                    'data_start_row': self.config.excel.data_start_row,
                    'timestamp_backups': self.config.excel.timestamp_backups,
                    'sheet_name': self.config.excel.sheet_name
                },
                'output': {
                    'generate_summary': self.config.output.generate_summary,
                    'create_reports': self.config.output.create_reports,
                    'timestamp_files': self.config.output.timestamp_files,
                    'export_formats': self.config.output.export_formats,
                    'backup_directory': self.config.output.backup_directory,
                    'output_directory': self.config.output.output_directory,
                    'report_directory': self.config.output.report_directory
                },
                'logging': {
                    'level': self.config.logging.level,
                    'file_rotation': self.config.logging.file_rotation,
                    'max_file_size': self.config.logging.max_file_size,
                    'backup_count': self.config.logging.backup_count,
                    'log_directory': self.config.logging.log_directory,
                    'log_format': self.config.logging.log_format,
                    'console_output': self.config.logging.console_output
                }
            }
            
            with open(save_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Configuration saved to: {save_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return False
    
    def get_config(self) -> Config:
        """Get current configuration"""
        return self.config
    
    def update_config(self, **kwargs):
        """Update configuration values"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
            else:
                self.logger.warning(f"Unknown configuration key: {key}")
    
    def validate_config(self) -> tuple[bool, list[str]]:
        """Validate configuration settings"""
        errors = []
        
        # Validate processing settings
        if self.config.processing.concurrent_requests < 1:
            errors.append("concurrent_requests must be at least 1")
        
        if self.config.processing.request_timeout < 1:
            errors.append("request_timeout must be at least 1")
        
        if self.config.processing.retry_attempts < 0:
            errors.append("retry_attempts must be non-negative")
        
        # Validate Excel settings
        if self.config.excel.header_row < 1:
            errors.append("header_row must be at least 1")
        
        if self.config.excel.data_start_row <= self.config.excel.header_row:
            errors.append("data_start_row must be greater than header_row")
        
        # Validate directories exist
        required_dirs = [
            self.config.output.backup_directory,
            self.config.output.output_directory,
            self.config.logging.log_directory
        ]
        
        for directory in required_dirs:
            if not Path(directory).exists():
                errors.append(f"Directory does not exist: {directory}")
        
        return len(errors) == 0, errors