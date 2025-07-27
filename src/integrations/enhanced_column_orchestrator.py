"""
Enhanced Column Processing Orchestrator for IHACPA v2.0

Unified orchestrator that coordinates all column processors (A-W) with proper
integration to our AI-based sandbox infrastructure. Based on comprehensive 
analysis of the retired version's sophisticated approach.

Complete Column Mapping:
- A: Index (automatic)
- B: Package Name (from input)
- C: Current Version (from input)  
- D: PyPI Current Link (automatic)
- E: Date Published (current version)
- F: Latest Version
- G: PyPI Latest Link (automatic)
- H: Latest Version Release Date ✨ NEW
- I: Requirements/Dependencies
- J: Development Status
- K: GitHub URL
- L: GitHub Security URL
- M: GitHub Security Result
- N: Notes (manual)
- O: NIST NVD Lookup URL
- P: NIST NVD Lookup Result  
- Q: MITRE CVE Lookup URL
- R: MITRE CVE Lookup Result
- S: SNYK Lookup URL
- T: SNYK Lookup Result
- U: Exploit DB Lookup URL
- V: Exploit DB Lookup Result
- W: IHACPA Recommendation ✨ ENHANCED
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from .pypi_client import PyPIClient
from ..core.ai_analyzer import AIAnalyzer
from ..core.sandbox_manager import SandboxManager

# Import all specialized column processors
from .columns.pypi_data import (
    DatePublishedProcessor,
    LatestVersionProcessor,
    LatestReleaseDateProcessor,
    RequirementsProcessor,
    DevelopmentStatusProcessor
)

from .columns.github_data import (
    GitHubURLProcessor,
    GitHubSecurityURLProcessor,
    GitHubSecurityResultProcessor
)

from .columns.vulnerability_dbs import (
    NISTNVDProcessor,
    MITRECVEProcessor,
    SNYKProcessor,
    ExploitDBProcessor
)

from .columns.recommendations import RecommendationProcessor


class EnhancedColumnOrchestrator:
    """
    Unified orchestrator for all enhanced column processing.
    
    Coordinates PyPI data extraction, GitHub analysis, vulnerability scanning,
    and AI-powered recommendations using our sophisticated sandbox infrastructure.
    """
    
    def __init__(self, config: Any, ai_analyzer: Optional[AIAnalyzer] = None,
                 sandbox_manager: Optional[SandboxManager] = None):
        """
        Initialize orchestrator with all required components.
        
        Args:
            config: Application configuration (dict or config object)
            ai_analyzer: AI analyzer for enhanced processing
            sandbox_manager: Sandbox manager for vulnerability scanning
        """
        self.config = config
        self.ai_analyzer = ai_analyzer
        self.sandbox_manager = sandbox_manager
        self.logger = logging.getLogger(__name__)
        
        # Initialize PyPI client with robust configuration handling
        timeout = 30  # Default timeout
        max_retries = 3  # Default retries
        
        try:
            if isinstance(config, dict):
                # Handle dictionary configuration
                processing_config = config.get('processing', {})
                timeout = processing_config.get('request_timeout', 30)
                max_retries = processing_config.get('retry_attempts', 3)
            elif hasattr(config, 'processing') and config.processing:
                # Handle object configuration with processing attribute
                timeout = getattr(config.processing, 'request_timeout', 30)
                max_retries = getattr(config.processing, 'retry_attempts', 3)
            elif hasattr(config, '__dict__'):
                # Handle object configuration without processing - search in main config
                config_dict = config.__dict__
                if 'processing' in config_dict:
                    processing = config_dict['processing']
                    if isinstance(processing, dict):
                        timeout = processing.get('request_timeout', 30)
                        max_retries = processing.get('retry_attempts', 3)
                    else:
                        timeout = getattr(processing, 'request_timeout', 30)
                        max_retries = getattr(processing, 'retry_attempts', 3)
        except Exception as e:
            self.logger.warning(f"Error loading processing config, using defaults: {e}")
            timeout = 30
            max_retries = 3
        self.pypi_client = PyPIClient(timeout=timeout, max_retries=max_retries)
        
        # Initialize all column processors
        self._initialize_processors()
    
    def _initialize_processors(self):
        """Initialize all specialized column processors."""
        try:
            # PyPI Data Processors (E-J)
            self.date_published_processor = DatePublishedProcessor(self.pypi_client)
            self.latest_version_processor = LatestVersionProcessor(self.pypi_client)
            self.latest_release_date_processor = LatestReleaseDateProcessor(self.pypi_client)
            self.requirements_processor = RequirementsProcessor(self.pypi_client)
            self.development_status_processor = DevelopmentStatusProcessor(self.pypi_client)
            
            # GitHub Data Processors (K-M)
            self.github_url_processor = GitHubURLProcessor(self.pypi_client)
            self.github_security_url_processor = GitHubSecurityURLProcessor(self.pypi_client)
            self.github_security_result_processor = GitHubSecurityResultProcessor(self.pypi_client)
            
            # Vulnerability Database Processors (O-V) - requires sandbox manager
            if self.sandbox_manager:
                self.nist_nvd_processor = NISTNVDProcessor(self.sandbox_manager)
                self.mitre_cve_processor = MITRECVEProcessor(self.sandbox_manager)
                self.snyk_processor = SNYKProcessor(self.sandbox_manager)
                self.exploit_db_processor = ExploitDBProcessor(self.sandbox_manager)
            else:
                self.logger.warning("Sandbox manager not available - vulnerability scanning disabled")
                self.nist_nvd_processor = None
                self.mitre_cve_processor = None
                self.snyk_processor = None
                self.exploit_db_processor = None
            
            # Recommendation Processor (W)
            self.recommendation_processor = RecommendationProcessor(self.ai_analyzer)
            
            self.logger.info("Enhanced column processors initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing column processors: {e}")
            raise
    
    async def process_all_columns(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """
        Process all enhanced columns for a package.
        
        Orchestrates the complete analysis workflow following the retired version's
        sophisticated approach with our AI-enhanced infrastructure.
        
        Args:
            package_name: Name of the Python package
            current_version: Current installed version
            
        Returns:
            Dictionary with all column results
        """
        try:
            self.logger.info(f"Processing all enhanced columns for {package_name} v{current_version}")
            start_time = datetime.now()
            
            # Phase 1: PyPI Data Collection (Columns E-J)
            pypi_results = await self._process_pypi_columns(package_name, current_version)
            
            # Phase 2: GitHub Analysis (Columns K-M)  
            github_results = await self._process_github_columns(package_name, current_version, pypi_results)
            
            # Phase 3: Vulnerability Database Scanning (Columns O-V)
            vuln_results = await self._process_vulnerability_columns(package_name, current_version)
            
            # Phase 4: Generate Comprehensive Recommendation (Column W)
            recommendation_result = await self._process_recommendation_column(
                package_name, current_version, pypi_results, vuln_results
            )
            
            # Combine all results
            all_results = {
                **pypi_results,
                **github_results,
                **vuln_results,
                'W': recommendation_result
            }
            
            processing_time = (datetime.now() - start_time).total_seconds()
            self.logger.info(f"Completed all column processing for {package_name} in {processing_time:.2f}s")
            
            return all_results
            
        except Exception as e:
            self.logger.error(f"Error processing columns for {package_name}: {e}")
            raise
    
    async def _process_pypi_columns(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """Process PyPI-related columns (E-J) concurrently."""
        try:
            self.logger.debug(f"Processing PyPI columns for {package_name}")
            
            # Process all PyPI columns concurrently for efficiency
            tasks = [
                self.date_published_processor.process(package_name, current_version),           # Column E
                self.latest_version_processor.process(package_name, current_version),          # Column F  
                self.latest_release_date_processor.process(package_name, current_version),     # Column H
                self.requirements_processor.process(package_name, current_version),            # Column I
                self.development_status_processor.process(package_name, current_version)       # Column J
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Map results to column names
            column_results = {}
            columns = ['E', 'F', 'H', 'I', 'J']
            
            for i, (column, result) in enumerate(zip(columns, results)):
                if isinstance(result, Exception):
                    self.logger.error(f"Error processing column {column}: {result}")
                    column_results[column] = {
                        'value': 'Error',
                        'color': 'critical',
                        'font': 'critical',
                        'note': f'Error: {str(result)}'
                    }
                else:
                    column_results[column] = result
            
            # Generate automatic PyPI links (Columns D & G)
            column_results['D'] = self._generate_pypi_current_link(package_name, current_version)
            if 'F' in column_results and column_results['F'].get('value'):
                latest_version = column_results['F']['value']
                column_results['G'] = self._generate_pypi_latest_link(package_name, latest_version)
            
            self.logger.debug(f"Completed PyPI columns for {package_name}")
            return column_results
            
        except Exception as e:
            self.logger.error(f"Error processing PyPI columns for {package_name}: {e}")
            raise
    
    async def _process_github_columns(self, package_name: str, current_version: str, 
                                    pypi_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process GitHub-related columns (K-M)."""
        try:
            self.logger.debug(f"Processing GitHub columns for {package_name}")
            
            # Column K: GitHub URL
            github_url_result = await self.github_url_processor.process(package_name, current_version)
            
            # Column L: GitHub Security URL (depends on K)
            github_url = github_url_result.get('hyperlink') or github_url_result.get('value', '')
            security_url_result = await self.github_security_url_processor.process(package_name, github_url)
            
            # Column M: GitHub Security Result (depends on L)
            security_url = security_url_result.get('hyperlink') or security_url_result.get('value', '')
            security_result = await self.github_security_result_processor.process(
                package_name, current_version, github_url, security_url
            )
            
            return {
                'K': github_url_result,
                'L': security_url_result,
                'M': security_result
            }
            
        except Exception as e:
            self.logger.error(f"Error processing GitHub columns for {package_name}: {e}")
            return {
                'K': self._error_result(f'Error: {e}'),
                'L': self._error_result(f'Error: {e}'),
                'M': self._error_result(f'Error: {e}')
            }
    
    async def _process_vulnerability_columns(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """Process vulnerability database columns (O-V) using our AI sandboxes."""
        try:
            self.logger.debug(f"Processing vulnerability columns for {package_name}")
            
            if not self.sandbox_manager:
                self.logger.warning("Sandbox manager not available - skipping vulnerability scanning")
                return self._create_unavailable_vuln_results()
            
            # Process all vulnerability databases concurrently for efficiency
            tasks = []
            
            # NIST NVD (Columns O & P)
            if self.nist_nvd_processor:
                tasks.extend([
                    self.nist_nvd_processor.process_url(package_name, current_version),      # Column O
                    self.nist_nvd_processor.process_result(package_name, current_version)   # Column P
                ])
            
            # MITRE CVE (Columns Q & R) 
            if self.mitre_cve_processor:
                tasks.extend([
                    self.mitre_cve_processor.process_url(package_name, current_version),     # Column Q
                    self.mitre_cve_processor.process_result(package_name, current_version)  # Column R
                ])
            
            # SNYK (Columns S & T)
            if self.snyk_processor:
                tasks.extend([
                    self.snyk_processor.process_url(package_name, current_version),         # Column S
                    self.snyk_processor.process_result(package_name, current_version)      # Column T
                ])
            
            # Exploit DB (Columns U & V)
            if self.exploit_db_processor:
                tasks.extend([
                    self.exploit_db_processor.process_url(package_name, current_version),   # Column U
                    self.exploit_db_processor.process_result(package_name, current_version) # Column V
                ])
            
            # Execute all vulnerability scans concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Map results to columns
            vuln_results = {}
            columns = ['O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V']
            
            for i, (column, result) in enumerate(zip(columns, results)):
                if isinstance(result, Exception):
                    self.logger.error(f"Error processing vulnerability column {column}: {result}")
                    vuln_results[column] = self._error_result(f'Error: {result}')
                else:
                    vuln_results[column] = result
            
            self.logger.debug(f"Completed vulnerability columns for {package_name}")
            return vuln_results
            
        except Exception as e:
            self.logger.error(f"Error processing vulnerability columns for {package_name}: {e}")
            return self._create_unavailable_vuln_results()
    
    async def _process_recommendation_column(self, package_name: str, current_version: str,
                                           pypi_results: Dict[str, Any], vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process recommendation column (W) based on all scan results."""
        try:
            self.logger.debug(f"Processing recommendation column for {package_name}")
            
            # Get latest version from PyPI results
            latest_version = pypi_results.get('F', {}).get('value', current_version)
            
            # Combine vulnerability results for recommendation analysis
            vulnerability_results = {
                'M': pypi_results.get('M', {}),  # GitHub Security (if processed in GitHub phase)
                'P': vuln_results.get('P', {}),  # NIST NVD
                'R': vuln_results.get('R', {}),  # MITRE CVE
                'T': vuln_results.get('T', {}),  # SNYK
                'V': vuln_results.get('V', {})   # Exploit DB
            }
            
            # Generate comprehensive recommendation
            recommendation = await self.recommendation_processor.process(
                package_name, current_version, latest_version, vulnerability_results
            )
            
            self.logger.debug(f"Generated recommendation for {package_name}: {recommendation.get('value', 'N/A')}")
            return recommendation
            
        except Exception as e:
            self.logger.error(f"Error processing recommendation for {package_name}: {e}")
            return self._error_result(f'Error generating recommendation: {e}')
    
    def _generate_pypi_current_link(self, package_name: str, current_version: str) -> Dict[str, Any]:
        """Generate PyPI link for current version (Column D)."""
        url = f"https://pypi.org/project/{package_name}/{current_version}/"
        hyperlink_formula = f'=HYPERLINK("{url}", "PyPI {current_version}")'
        
        return {
            'value': hyperlink_formula,
            'color': 'updated',
            'font': 'updated',
            'note': f'PyPI link for current version {current_version}',
            'hyperlink': url
        }
    
    def _generate_pypi_latest_link(self, package_name: str, latest_version: str) -> Dict[str, Any]:
        """Generate PyPI link for latest version (Column G)."""
        url = f"https://pypi.org/project/{package_name}/{latest_version}/"
        hyperlink_formula = f'=HYPERLINK("{url}", "PyPI {latest_version}")'
        
        return {
            'value': hyperlink_formula,
            'color': 'new_data',
            'font': 'new_data',
            'note': f'PyPI link for latest version {latest_version}',
            'hyperlink': url
        }
    
    def _error_result(self, error_message: str) -> Dict[str, Any]:
        """Create standardized error result."""
        return {
            'value': 'Error',
            'color': 'critical',
            'font': 'critical',
            'note': error_message
        }
    
    def _create_unavailable_vuln_results(self) -> Dict[str, Any]:
        """Create results for when vulnerability scanning is unavailable."""
        unavailable_result = {
            'value': 'Scanner unavailable',
            'color': 'version_update',
            'font': 'version_update',
            'note': 'Vulnerability scanner not available'
        }
        
        return {
            'O': unavailable_result.copy(),
            'P': unavailable_result.copy(),
            'Q': unavailable_result.copy(),
            'R': unavailable_result.copy(),
            'S': unavailable_result.copy(),
            'T': unavailable_result.copy(),
            'U': unavailable_result.copy(),
            'V': unavailable_result.copy()
        }
    
    async def cleanup(self):
        """Cleanup resources."""
        try:
            if hasattr(self.pypi_client, 'cleanup'):
                await self.pypi_client.cleanup()
        except Exception as e:
            self.logger.warning(f"Error during cleanup: {e}")