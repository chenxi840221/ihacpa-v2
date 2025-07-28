"""
Report Generator for IHACPA v2.0

Generates comprehensive reports from scan results including summary statistics,
detailed findings, and formatted output.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from ..config import Config


class ReportGenerator:
    """Generates various types of reports from scan results"""
    
    def __init__(self, config: Config):
        """
        Initialize report generator.
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
    def generate_summary_report(self, 
                              scan_results: Dict[str, Any],
                              output_path: Optional[Path] = None) -> Path:
        """
        Generate a comprehensive summary report.
        
        Args:
            scan_results: Dictionary containing scan results and statistics
            output_path: Optional custom output path
            
        Returns:
            Path to generated report
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(self.config.output.report_directory) / f"ihacpa_summary_{timestamp}.txt"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                self._write_summary_header(f, scan_results)
                self._write_execution_summary(f, scan_results)
                self._write_security_summary(f, scan_results)
                self._write_ai_analysis_summary(f, scan_results)
                self._write_package_statistics(f, scan_results)
                self._write_recommendations(f, scan_results)
                self._write_detailed_findings(f, scan_results)
            
            self.logger.info(f"Summary report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating summary report: {e}")
            raise
    
    def generate_changes_report(self,
                              changes_data: Dict[str, Any],
                              output_path: Optional[Path] = None) -> Path:
        """
        Generate a report of changes made to the Excel file.
        
        Args:
            changes_data: Dictionary containing change information
            output_path: Optional custom output path
            
        Returns:
            Path to generated report
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(self.config.output.report_directory) / f"ihacpa_changes_{timestamp}.txt"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                self._write_changes_header(f, changes_data)
                self._write_changes_summary(f, changes_data)
                self._write_detailed_changes(f, changes_data)
            
            self.logger.info(f"Changes report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating changes report: {e}")
            raise
    
    def generate_json_report(self,
                           scan_results: Dict[str, Any],
                           output_path: Optional[Path] = None) -> Path:
        """
        Generate a detailed JSON report.
        
        Args:
            scan_results: Dictionary containing scan results
            output_path: Optional custom output path
            
        Returns:
            Path to generated report
        """
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(self.config.output.report_directory) / f"ihacpa_detailed_{timestamp}.json"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Create comprehensive JSON structure
            json_data = {
                'metadata': {
                    'report_generated': datetime.now().isoformat(),
                    'ihacpa_version': self.config.app.version,
                    'configuration': {
                        'ai_enabled': self.config.ai.enabled,
                        'ai_provider': self.config.ai.provider,
                        'correlation_analysis': self.config.ai.correlation_analysis_enabled,
                        'risk_assessment': self.config.ai.risk_assessment_enabled
                    }
                },
                'summary': scan_results.get('summary', {}),
                'detailed_results': scan_results.get('detailed_results', []),
                'statistics': scan_results.get('statistics', {}),
                'ai_analysis': scan_results.get('ai_analysis', {}),
                'errors': scan_results.get('errors', [])
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, default=str)
            
            self.logger.info(f"JSON report generated: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")
            raise
    
    def _write_summary_header(self, f, scan_results: Dict[str, Any]):
        """Write report header"""
        f.write("IHACPA v2.0 - AI-Enhanced Python Package Security Analysis Report\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"IHACPA Version: {self.config.app.version}\n")
        
        if 'metadata' in scan_results:
            metadata = scan_results['metadata']
            f.write(f"Excel File: {metadata.get('excel_file', 'N/A')}\n")
            f.write(f"Total Packages: {metadata.get('total_packages', 0)}\n")
        
        f.write("\n")
    
    def _write_execution_summary(self, f, scan_results: Dict[str, Any]):
        """Write execution summary"""
        f.write("Execution Summary\n")
        f.write("-" * 40 + "\n")
        
        summary = scan_results.get('summary', {})
        f.write(f"Packages Processed: {summary.get('packages_processed', 0)}\n")
        f.write(f"Successful Scans: {summary.get('successful_scans', 0)}\n")
        f.write(f"Failed Scans: {summary.get('failed_scans', 0)}\n")
        f.write(f"Success Rate: {summary.get('success_rate', 0):.1f}%\n")
        
        if 'total_time' in summary:
            f.write(f"Total Processing Time: {summary['total_time']:.2f} seconds\n")
            f.write(f"Average Time per Package: {summary.get('avg_time_per_package', 0):.2f} seconds\n")
        
        f.write("\n")
    
    def _write_security_summary(self, f, scan_results: Dict[str, Any]):
        """Write security findings summary"""
        f.write("Security Findings Summary\n")
        f.write("-" * 40 + "\n")
        
        security = scan_results.get('security_summary', {})
        f.write(f"Total Vulnerabilities Found: {security.get('total_vulnerabilities', 0)}\n")
        f.write(f"Unique Vulnerabilities: {security.get('unique_vulnerabilities', 0)}\n")
        f.write(f"Critical Vulnerabilities: {security.get('critical_vulnerabilities', 0)}\n")
        f.write(f"High Risk Vulnerabilities: {security.get('high_risk_vulnerabilities', 0)}\n")
        f.write(f"Medium Risk Vulnerabilities: {security.get('medium_risk_vulnerabilities', 0)}\n")
        f.write(f"Low Risk Vulnerabilities: {security.get('low_risk_vulnerabilities', 0)}\n")
        
        if 'deduplication_rate' in security:
            f.write(f"Deduplication Rate: {security['deduplication_rate']:.1f}%\n")
        
        f.write("\n")
    
    def _write_ai_analysis_summary(self, f, scan_results: Dict[str, Any]):
        """Write AI analysis summary"""
        f.write("AI Analysis Summary\n")
        f.write("-" * 40 + "\n")
        
        ai_summary = scan_results.get('ai_summary', {})
        f.write(f"AI Enhancement Enabled: {'Yes' if self.config.ai.enabled else 'No'}\n")
        
        if self.config.ai.enabled:
            f.write(f"AI Provider: {self.config.ai.provider}\n")
            f.write(f"AI Model: {self.config.ai.model}\n")
            f.write(f"Enhanced Scans: {ai_summary.get('ai_enhanced_scans', 0)}\n")
            f.write(f"Average AI Confidence: {ai_summary.get('avg_confidence', 0):.1%}\n")
            f.write(f"Correlation Analysis: {'Enabled' if self.config.ai.correlation_analysis_enabled else 'Disabled'}\n")
            f.write(f"Risk Assessment: {'Enabled' if self.config.ai.risk_assessment_enabled else 'Disabled'}\n")
        
        f.write("\n")
    
    def _write_package_statistics(self, f, scan_results: Dict[str, Any]):
        """Write package statistics"""
        f.write("Package Statistics\n")
        f.write("-" * 40 + "\n")
        
        stats = scan_results.get('statistics', {})
        
        # Sandbox performance
        sandbox_stats = stats.get('sandbox_performance', {})
        if sandbox_stats:
            f.write("Sandbox Performance:\n")
            for sandbox, perf in sandbox_stats.items():
                f.write(f"  {sandbox}: {perf.get('success_rate', 0):.1f}% success, ")
                f.write(f"{perf.get('avg_time', 0):.2f}s avg\n")
        
        # Version analysis
        version_stats = stats.get('version_analysis', {})
        if version_stats:
            f.write(f"\nVersion Analysis:\n")
            f.write(f"  Packages with updates available: {version_stats.get('updates_available', 0)}\n")
            f.write(f"  Average age of packages: {version_stats.get('avg_age_days', 0)} days\n")
        
        f.write("\n")
    
    def _write_recommendations(self, f, scan_results: Dict[str, Any]):
        """Write recommendations"""
        f.write("Recommendations\n")
        f.write("-" * 40 + "\n")
        
        recommendations = scan_results.get('recommendations', [])
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                f.write(f"{i}. {rec}\n")
        else:
            f.write("No specific recommendations generated.\n")
        
        f.write("\n")
    
    def _write_detailed_findings(self, f, scan_results: Dict[str, Any]):
        """Write detailed findings"""
        f.write("Detailed Findings\n")
        f.write("-" * 40 + "\n")
        
        detailed_results = scan_results.get('detailed_results', [])
        
        # Group by risk level
        critical_packages = []
        high_risk_packages = []
        medium_risk_packages = []
        
        for result in detailed_results:
            risk_score = result.get('overall_risk_score', 0)
            if risk_score >= 0.9:
                critical_packages.append(result)
            elif risk_score >= 0.7:
                high_risk_packages.append(result)
            elif risk_score >= 0.4:
                medium_risk_packages.append(result)
        
        # Write critical packages
        if critical_packages:
            f.write(f"🚨 CRITICAL RISK PACKAGES ({len(critical_packages)}):\n")
            for pkg in critical_packages:
                self._write_package_detail(f, pkg)
            f.write("\n")
        
        # Write high risk packages
        if high_risk_packages:
            f.write(f"⚠️  HIGH RISK PACKAGES ({len(high_risk_packages)}):\n")
            for pkg in high_risk_packages[:10]:  # Limit to top 10
                self._write_package_detail(f, pkg)
            f.write("\n")
        
        # Write summary for medium risk
        if medium_risk_packages:
            f.write(f"📋 MEDIUM RISK PACKAGES ({len(medium_risk_packages)}):\n")
            for pkg in medium_risk_packages[:5]:  # Limit to top 5
                self._write_package_detail(f, pkg, brief=True)
            f.write("\n")
    
    def _write_package_detail(self, f, package_result: Dict[str, Any], brief: bool = False):
        """Write detailed package information"""
        name = package_result.get('package', 'Unknown')
        version = package_result.get('current_version', 'Unknown')
        risk_score = package_result.get('overall_risk_score', 0)
        critical_vulns = package_result.get('critical_vulnerabilities', 0)
        total_vulns = package_result.get('total_vulnerabilities', 0)
        
        f.write(f"  📦 {name} v{version}\n")
        f.write(f"     Risk Score: {risk_score:.2f} | Vulnerabilities: {total_vulns} ({critical_vulns} critical)\n")
        
        if not brief:
            # Add AI recommendation if available
            recommendation = package_result.get('ihacpa_recommendation', '')
            if recommendation:
                f.write(f"     Recommendation: {recommendation}\n")
            
            # Add top vulnerabilities
            if 'top_vulnerabilities' in package_result:
                f.write(f"     Top Issues:\n")
                for vuln in package_result['top_vulnerabilities'][:3]:
                    f.write(f"       • {vuln.get('title', 'Unknown vulnerability')}\n")
        
        f.write("\n")
    
    def _write_changes_header(self, f, changes_data: Dict[str, Any]):
        """Write changes report header"""
        f.write("IHACPA v2.0 - Changes Made Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Source File: {changes_data.get('source_file', 'N/A')}\n")
        f.write("\n")
    
    def _write_changes_summary(self, f, changes_data: Dict[str, Any]):
        """Write changes summary"""
        f.write("Changes Summary\n")
        f.write("-" * 30 + "\n")
        
        summary = changes_data.get('summary', {})
        f.write(f"Total Changes: {summary.get('total_changes', 0)}\n")
        f.write(f"Rows Modified: {summary.get('rows_modified', 0)}\n")
        
        most_changed = summary.get('most_changed_fields', [])
        if most_changed:
            f.write(f"Most Changed Fields:\n")
            for field, count in most_changed:
                f.write(f"  {field}: {count} changes\n")
        
        f.write("\n")
    
    def _write_detailed_changes(self, f, changes_data: Dict[str, Any]):
        """Write detailed changes"""
        f.write("Detailed Changes\n")
        f.write("-" * 30 + "\n")
        
        changes = changes_data.get('changes', [])
        
        # Group changes by row
        changes_by_row = {}
        for change in changes:
            row = change['row']
            if row not in changes_by_row:
                changes_by_row[row] = []
            changes_by_row[row].append(change)
        
        for row, row_changes in sorted(changes_by_row.items()):
            f.write(f"Row {row}:\n")
            for change in row_changes:
                f.write(f"  {change['field']}: {change['old_value']} → {change['new_value']}\n")
            f.write("\n")