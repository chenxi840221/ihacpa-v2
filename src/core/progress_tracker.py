"""
Progress Tracker for IHACPA v2.0

Provides comprehensive progress tracking with statistics, ETA calculations,
and performance monitoring.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from dataclasses import dataclass, field


@dataclass
class PackageResult:
    """Result of processing a single package"""
    package_name: str
    success: bool
    processing_time: float
    vulnerabilities_found: int = 0
    ai_enhanced: bool = False
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)


class ProgressTracker:
    """Advanced progress tracking with statistics and performance monitoring"""
    
    def __init__(self, total_packages: int, logger: logging.Logger):
        """
        Initialize progress tracker.
        
        Args:
            total_packages: Total number of packages to process
            logger: Logger instance
        """
        self.total_packages = total_packages
        self.logger = logger
        
        # Progress tracking
        self.processed_packages = 0
        self.successful_packages = 0
        self.failed_packages = 0
        self.start_time = datetime.now()
        self.last_update_time = datetime.now()
        
        # Detailed results
        self.package_results: List[PackageResult] = []
        self.errors: List[Dict[str, Any]] = []
        
        # Performance tracking
        self.processing_times: List[float] = []
        self.vulnerability_counts: List[int] = []
        self.ai_enhanced_count = 0
        
        # Progress reporting intervals
        self.report_interval = max(1, total_packages // 20)  # Report every 5%
        
    def start_package(self, package_name: str, package_index: int):
        """
        Log start of package processing.
        
        Args:
            package_name: Name of package being processed
            package_index: Index of package (1-based)
        """
        self.current_package = package_name
        self.current_start_time = time.time()
        
        # Log progress periodically
        if package_index % self.report_interval == 0 or package_index == 1:
            progress_percent = (package_index / self.total_packages) * 100
            elapsed = datetime.now() - self.start_time
            
            progress_msg = f"📊 Progress: {package_index}/{self.total_packages} ({progress_percent:.1f}%) - {package_name}"
            self.logger.info(progress_msg)
            print(progress_msg)  # Also print to console
            
            if package_index > 1:
                self._log_current_statistics(elapsed)
    
    def complete_package(self, 
                        package_name: str,
                        success: bool,
                        vulnerabilities_found: int = 0,
                        ai_enhanced: bool = False,
                        error_message: Optional[str] = None):
        """
        Mark package processing as complete.
        
        Args:
            package_name: Name of processed package
            success: Whether processing was successful
            vulnerabilities_found: Number of vulnerabilities found
            ai_enhanced: Whether AI enhancement was used
            error_message: Error message if failed
        """
        processing_time = time.time() - self.current_start_time
        
        # Create result record
        result = PackageResult(
            package_name=package_name,
            success=success,
            processing_time=processing_time,
            vulnerabilities_found=vulnerabilities_found,
            ai_enhanced=ai_enhanced,
            error_message=error_message
        )
        
        self.package_results.append(result)
        
        # Update counters
        self.processed_packages += 1
        if success:
            self.successful_packages += 1
            self.processing_times.append(processing_time)
            self.vulnerability_counts.append(vulnerabilities_found)
            if ai_enhanced:
                self.ai_enhanced_count += 1
        else:
            self.failed_packages += 1
            if error_message:
                self.errors.append({
                    'package': package_name,
                    'error': error_message,
                    'timestamp': datetime.now()
                })
        
        # Log individual completion
        if success:
            status_emoji = "✅"
            if vulnerabilities_found > 0:
                vuln_info = f", {vulnerabilities_found} vulnerabilities"
                if vulnerabilities_found >= 5:
                    status_emoji = "🚨"
                elif vulnerabilities_found >= 2:
                    status_emoji = "⚠️"
            else:
                vuln_info = ""
            
            ai_indicator = " (AI)" if ai_enhanced else ""
            self.logger.info(
                f"{status_emoji} Completed {package_name} in {processing_time:.2f}s{vuln_info}{ai_indicator}"
            )
        else:
            self.logger.error(f"❌ Failed to process {package_name}: {error_message}")
        
        self.last_update_time = datetime.now()
    
    def log_vulnerability_found(self, package_name: str, database: str, count: int):
        """
        Log vulnerability finding.
        
        Args:
            package_name: Package name
            database: Database that found the vulnerability
            count: Number of vulnerabilities found
        """
        if count > 0:
            self.logger.warning(f"🔍 {package_name}: Found {count} vulnerabilities in {database}")
    
    def log_package_update_available(self, package_name: str, current_version: str, latest_version: str):
        """
        Log package update availability.
        
        Args:
            package_name: Package name
            current_version: Current version
            latest_version: Latest available version
        """
        self.logger.info(f"📦 {package_name}: Update available {current_version} → {latest_version}")
    
    def _log_current_statistics(self, elapsed_time: timedelta):
        """Log current processing statistics"""
        if self.processed_packages > 0:
            avg_time = sum(self.processing_times) / len(self.processing_times) if self.processing_times else 0
            remaining_packages = self.total_packages - self.processed_packages
            eta_seconds = avg_time * remaining_packages
            eta = datetime.now() + timedelta(seconds=eta_seconds)
            
            success_rate = (self.successful_packages / self.processed_packages) * 100
            
            stats_msg = (f"📈 Stats: {self.processed_packages}/{self.total_packages} "
                         f"| ✅ {self.successful_packages} | ❌ {self.failed_packages} "
                         f"| Success: {success_rate:.1f}%")
            self.logger.info(stats_msg)
            print(stats_msg)  # Also print to console
            
            if eta_seconds > 0:
                eta_msg = f"⏰ ETA: {eta.strftime('%H:%M:%S')}"
                self.logger.info(eta_msg)
                print(eta_msg)  # Also print to console
    
    def get_current_statistics(self) -> Dict[str, Any]:
        """
        Get current processing statistics.
        
        Returns:
            Dictionary with current statistics
        """
        elapsed_time = (datetime.now() - self.start_time).total_seconds()
        
        stats = {
            'total_packages': self.total_packages,
            'processed_packages': self.processed_packages,
            'successful_packages': self.successful_packages,
            'failed_packages': self.failed_packages,
            'success_rate': (self.successful_packages / max(1, self.processed_packages)) * 100,
            'elapsed_time': elapsed_time,
            'packages_per_second': self.processed_packages / max(1, elapsed_time),
        }
        
        if self.processing_times:
            stats.update({
                'avg_processing_time': sum(self.processing_times) / len(self.processing_times),
                'min_processing_time': min(self.processing_times),
                'max_processing_time': max(self.processing_times),
            })
        
        if self.vulnerability_counts:
            stats.update({
                'total_vulnerabilities': sum(self.vulnerability_counts),
                'avg_vulnerabilities_per_package': sum(self.vulnerability_counts) / len(self.vulnerability_counts),
                'max_vulnerabilities': max(self.vulnerability_counts),
            })
        
        stats['ai_enhanced_packages'] = self.ai_enhanced_count
        stats['ai_enhancement_rate'] = (self.ai_enhanced_count / max(1, self.successful_packages)) * 100
        
        return stats
    
    def log_final_summary(self):
        """Log comprehensive final summary"""
        total_time = (datetime.now() - self.start_time).total_seconds()
        
        self.logger.info("=" * 80)
        self.logger.info("PROCESSING SUMMARY")
        self.logger.info("=" * 80)
        
        # Basic statistics
        self.logger.info(f"Total packages: {self.total_packages}")
        self.logger.info(f"Successfully processed: {self.successful_packages}")
        self.logger.info(f"Failed: {self.failed_packages}")
        self.logger.info(f"Success rate: {(self.successful_packages/self.total_packages)*100:.1f}%")
        self.logger.info(f"Total time: {total_time/60:.1f} minutes")
        
        if self.processing_times:
            avg_time = sum(self.processing_times) / len(self.processing_times)
            self.logger.info(f"Average time per package: {avg_time:.2f} seconds")
        
        # Performance statistics
        if self.processed_packages > 0:
            self.logger.info(f"Processing rate: {self.processed_packages/total_time:.2f} packages/second")
        
        # Vulnerability statistics
        if self.vulnerability_counts:
            total_vulns = sum(self.vulnerability_counts)
            packages_with_vulns = len([v for v in self.vulnerability_counts if v > 0])
            
            self.logger.info(f"Total vulnerabilities found: {total_vulns}")
            self.logger.info(f"Packages with vulnerabilities: {packages_with_vulns}")
            if packages_with_vulns > 0:
                self.logger.info(f"Average vulnerabilities per affected package: {total_vulns/packages_with_vulns:.1f}")
        
        # AI enhancement statistics
        if self.ai_enhanced_count > 0:
            ai_rate = (self.ai_enhanced_count / self.successful_packages) * 100
            self.logger.info(f"AI-enhanced packages: {self.ai_enhanced_count} ({ai_rate:.1f}%)")
        
        # Error summary
        if self.errors:
            self.logger.info(f"Errors encountered: {len(self.errors)}")
            
            # Group errors by type
            error_types = {}
            for error in self.errors:
                error_msg = error['error']
                # Simple error categorization
                if 'timeout' in error_msg.lower():
                    error_type = 'Timeout'
                elif 'not found' in error_msg.lower():
                    error_type = 'Not Found'
                elif 'connection' in error_msg.lower():
                    error_type = 'Connection'
                else:
                    error_type = 'Other'
                
                error_types[error_type] = error_types.get(error_type, 0) + 1
            
            self.logger.info("Error breakdown:")
            for error_type, count in error_types.items():
                self.logger.info(f"  {error_type}: {count}")
        
        self.logger.info("=" * 80)
    
    def get_detailed_results(self) -> List[PackageResult]:
        """
        Get detailed results for all processed packages.
        
        Returns:
            List of PackageResult objects
        """
        return self.package_results.copy()
    
    def get_error_summary(self) -> List[Dict[str, Any]]:
        """
        Get summary of all errors encountered.
        
        Returns:
            List of error dictionaries
        """
        return self.errors.copy()
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get detailed performance metrics.
        
        Returns:
            Dictionary with performance metrics
        """
        metrics = self.get_current_statistics()
        
        # Add additional performance details
        if len(self.processing_times) >= 10:  # Only if we have enough data
            # Calculate percentiles
            sorted_times = sorted(self.processing_times)
            n = len(sorted_times)
            
            metrics.update({
                'processing_time_p50': sorted_times[n//2],
                'processing_time_p90': sorted_times[int(n*0.9)],
                'processing_time_p95': sorted_times[int(n*0.95)],
            })
        
        return metrics