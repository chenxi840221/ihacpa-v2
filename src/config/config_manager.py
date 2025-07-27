"""
Configuration Management for IHACPA v2.0

Handles loading and managing configuration settings from YAML files with
environment variable integration and validation.
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging
from dataclasses import dataclass, field
from datetime import datetime
from dotenv import load_dotenv


@dataclass
class AppConfig:
    """Application configuration"""
    name: str = "IHACPA v2.0 - AI-Enhanced Python Package Security Automation"
    version: str = "2.0.0"
    environment: str = "production"
    debug_mode: bool = False


@dataclass 
class ProcessingConfig:
    """Processing configuration"""
    max_concurrent_scans: int = 3
    request_timeout: int = 45
    retry_attempts: int = 3
    retry_delay: int = 2
    individual_package_processing: bool = True  # Compatible with AI sandboxes
    
    
@dataclass
class ExcelConfig:
    """Excel file configuration"""
    backup_original: bool = True
    preserve_formatting: bool = True
    header_row: int = 3  # Updated for IHACPA v2.0 structure - row 3 contains headers
    data_start_row: int = 4  # Data starts from row 4
    timestamp_backups: bool = True
    sheet_name: str = "Sheet1"
    enhanced_columns_enabled: bool = True  # Enable enhanced columns by default
    enhanced_columns: List[str] = field(default_factory=lambda: ["E", "F", "H", "K", "L", "M", "W"])
    
    # Column mapping for IHACPA v2.0 Excel structure
    column_mapping: Dict[str, int] = field(default_factory=lambda: {
        'index': 1,
        'package_name': 2, 
        'version': 3,
        'pypi_link': 4,
        'date_published': 5,
        'latest_version': 6,
        'latest_pypi_link': 7,
        'latest_date': 8,
        'requires': 9,
        'dev_status': 10,
        'github_url': 11,
        'github_security_url': 12,
        'github_security_result': 13,
        'notes': 14,
        'nvd_url': 15,
        'nvd_result': 16,
        'mitre_url': 17,
        'mitre_result': 18,
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
    export_formats: List[str] = field(default_factory=lambda: ["xlsx", "json"])
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
class AIConfig:
    """AI configuration for enhanced features"""
    enabled: bool = True
    provider: str = "azure"  # azure, openai, mock
    model: str = "gpt-4"
    temperature: float = 0.1
    timeout: int = 45
    max_tokens: int = 1000
    
    # Azure OpenAI specific
    azure_endpoint: Optional[str] = None
    azure_api_version: str = "2024-02-01"
    
    # Correlation analysis settings
    correlation_analysis_enabled: bool = True
    confidence_threshold: float = 0.7
    
    # Risk assessment settings
    risk_assessment_enabled: bool = True
    business_context: Dict[str, str] = field(default_factory=lambda: {
        "industry": "technology",
        "asset_criticality": "high",
        "data_sensitivity": "confidential"
    })


@dataclass
class Config:
    """Main configuration class"""
    app: AppConfig = field(default_factory=AppConfig)
    processing: ProcessingConfig = field(default_factory=ProcessingConfig)
    excel: ExcelConfig = field(default_factory=ExcelConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    
    def __post_init__(self):
        """Post-initialization setup"""
        self.loaded_from: Optional[str] = None
        self.loaded_at: Optional[datetime] = None
        
        # Load AI settings from environment
        self._load_ai_environment_variables()
    
    def _load_ai_environment_variables(self):
        """Load AI configuration from environment variables"""
        # Azure OpenAI settings
        if os.getenv('AZURE_OPENAI_ENDPOINT'):
            self.ai.azure_endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
            self.ai.provider = "azure"
            
        if os.getenv('AZURE_OPENAI_MODEL'):
            self.ai.model = os.getenv('AZURE_OPENAI_MODEL')
            
        if os.getenv('AZURE_OPENAI_API_VERSION'):
            self.ai.azure_api_version = os.getenv('AZURE_OPENAI_API_VERSION')
            
        # OpenAI settings
        if os.getenv('OPENAI_API_KEY') and not self.ai.azure_endpoint:
            self.ai.provider = "openai"
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        return getattr(self, key, default)


class ConfigManager:
    """Configuration manager for loading and managing settings"""
    
    DEFAULT_CONFIG_PATHS = [
        "config/settings.yaml",
        "config/settings.yml", 
        "settings.yaml",
        "settings.yml"
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager"""
        # Load .env file if it exists
        load_dotenv()
        
        self.config_path = config_path
        self.config = Config()
        self.logger = logging.getLogger(__name__)
        
    def load_config(self, config_path: Optional[str] = None) -> Config:
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Optional path to config file
            
        Returns:
            Loaded configuration object
        """
        if config_path:
            self.config_path = config_path
            
        # Try to find configuration file
        config_file = self._find_config_file()
        
        if config_file:
            try:
                self.config = self._load_from_file(config_file)
                print(f"✅ Configuration loaded from: {config_file}")
            except Exception as e:
                print(f"❌ Error loading configuration from {config_file}: {e}")
                print("Using default configuration")
        else:
            print("⚠️  No configuration file found, using defaults")
            
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
                print(f"⚠️  Specified config file not found: {config_path}")
        
        # Try default paths
        for path in self.DEFAULT_CONFIG_PATHS:
            config_path = Path(path)
            if config_path.exists():
                return config_path
                
        return None
    
    def _load_from_file(self, config_file: Path) -> Config:
        """Load configuration from YAML file"""
        with open(config_file, 'r', encoding='utf-8') as f:
            yaml_data = yaml.safe_load(f) or {}
        
        config = Config()
        
        # Load app settings
        if 'app' in yaml_data:
            app_data = yaml_data['app']
            config.app = AppConfig(
                name=app_data.get('name', config.app.name),
                version=app_data.get('version', config.app.version),
                environment=app_data.get('environment', config.app.environment),
                debug_mode=app_data.get('debug_mode', config.app.debug_mode)
            )
        
        # Load processing settings
        if 'processing' in yaml_data:
            proc_data = yaml_data['processing']
            config.processing = ProcessingConfig(
                max_concurrent_scans=proc_data.get('max_concurrent_scans', config.processing.max_concurrent_scans),
                request_timeout=proc_data.get('request_timeout', config.processing.request_timeout),
                retry_attempts=proc_data.get('retry_attempts', config.processing.retry_attempts),
                retry_delay=proc_data.get('retry_delay', config.processing.retry_delay),
                individual_package_processing=proc_data.get('individual_package_processing', config.processing.individual_package_processing)
            )
        
        # Load Excel settings
        if 'excel' in yaml_data:
            excel_data = yaml_data['excel']
            config.excel = ExcelConfig(
                backup_original=excel_data.get('backup_original', config.excel.backup_original),
                preserve_formatting=excel_data.get('preserve_formatting', config.excel.preserve_formatting),
                header_row=excel_data.get('header_row', config.excel.header_row),
                data_start_row=excel_data.get('data_start_row', config.excel.data_start_row),
                timestamp_backups=excel_data.get('timestamp_backups', config.excel.timestamp_backups),
                sheet_name=excel_data.get('sheet_name', config.excel.sheet_name),
                column_mapping=excel_data.get('column_mapping', config.excel.column_mapping)
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
        
        # Load AI settings
        if 'ai' in yaml_data:
            ai_data = yaml_data['ai']
            config.ai = AIConfig(
                enabled=ai_data.get('enabled', config.ai.enabled),
                provider=ai_data.get('provider', config.ai.provider),
                model=ai_data.get('model', config.ai.model),
                temperature=ai_data.get('temperature', config.ai.temperature),
                timeout=ai_data.get('timeout', config.ai.timeout),
                max_tokens=ai_data.get('max_tokens', config.ai.max_tokens),
                azure_endpoint=ai_data.get('azure_endpoint', config.ai.azure_endpoint),
                azure_api_version=ai_data.get('azure_api_version', config.ai.azure_api_version),
                correlation_analysis_enabled=ai_data.get('correlation_analysis_enabled', config.ai.correlation_analysis_enabled),
                confidence_threshold=ai_data.get('confidence_threshold', config.ai.confidence_threshold),
                risk_assessment_enabled=ai_data.get('risk_assessment_enabled', config.ai.risk_assessment_enabled),
                business_context=ai_data.get('business_context', config.ai.business_context)
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
        """
        Save current configuration to YAML file.
        
        Args:
            config_path: Optional path to save config file
            
        Returns:
            True if saved successfully, False otherwise
        """
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
                    'environment': self.config.app.environment,
                    'debug_mode': self.config.app.debug_mode
                },
                'processing': {
                    'max_concurrent_scans': self.config.processing.max_concurrent_scans,
                    'request_timeout': self.config.processing.request_timeout,
                    'retry_attempts': self.config.processing.retry_attempts,
                    'retry_delay': self.config.processing.retry_delay,
                    'individual_package_processing': self.config.processing.individual_package_processing
                },
                'excel': {
                    'backup_original': self.config.excel.backup_original,
                    'preserve_formatting': self.config.excel.preserve_formatting,
                    'header_row': self.config.excel.header_row,
                    'data_start_row': self.config.excel.data_start_row,
                    'timestamp_backups': self.config.excel.timestamp_backups,
                    'sheet_name': self.config.excel.sheet_name,
                    'column_mapping': self.config.excel.column_mapping
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
                },
                'ai': {
                    'enabled': self.config.ai.enabled,
                    'provider': self.config.ai.provider,
                    'model': self.config.ai.model,
                    'temperature': self.config.ai.temperature,
                    'timeout': self.config.ai.timeout,
                    'max_tokens': self.config.ai.max_tokens,
                    'azure_endpoint': self.config.ai.azure_endpoint,
                    'azure_api_version': self.config.ai.azure_api_version,
                    'correlation_analysis_enabled': self.config.ai.correlation_analysis_enabled,
                    'confidence_threshold': self.config.ai.confidence_threshold,
                    'risk_assessment_enabled': self.config.ai.risk_assessment_enabled,
                    'business_context': self.config.ai.business_context
                }
            }
            
            with open(save_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
            print(f"✅ Configuration saved to: {save_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving configuration: {e}")
            return False
    
    def get_config(self) -> Config:
        """Get current configuration"""
        return self.config
    
    def validate_config(self) -> tuple[bool, List[str]]:
        """
        Validate configuration settings.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Validate processing settings
        if self.config.processing.max_concurrent_scans < 1:
            errors.append("max_concurrent_scans must be at least 1")
        
        if self.config.processing.request_timeout < 1:
            errors.append("request_timeout must be at least 1")
        
        if self.config.processing.retry_attempts < 0:
            errors.append("retry_attempts must be non-negative")
        
        # Validate Excel settings
        if self.config.excel.header_row < 1:
            errors.append("header_row must be at least 1")
        
        if self.config.excel.data_start_row <= self.config.excel.header_row:
            errors.append("data_start_row must be greater than header_row")
        
        # Validate AI settings
        if self.config.ai.enabled:
            if self.config.ai.provider == "azure" and not self.config.ai.azure_endpoint:
                if not os.getenv('AZURE_OPENAI_ENDPOINT'):
                    errors.append("Azure OpenAI endpoint required when using Azure provider")
        
        return len(errors) == 0, errors