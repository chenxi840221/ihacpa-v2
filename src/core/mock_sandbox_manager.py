"""
Mock Sandbox Manager for IHACPA v2.0 Demo

Provides mock vulnerability scanning functionality for demonstration purposes
when Redis/actual sandboxes are not available.
"""

import asyncio
import random
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class MockVulnerabilityResult:
    """Mock vulnerability scan result"""
    success: bool = True
    vulnerabilities: List[Dict[str, Any]] = None
    error_message: Optional[str] = None
    ai_enhanced: bool = False
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []


class MockSandboxManager:
    """Mock sandbox manager for demonstration purposes"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.is_initialized = False
        
        # Mock vulnerability databases with realistic-looking results
        self.mock_vulnerability_data = {
            'nvd': [
                'CVE-2023-12345: SQL injection vulnerability in package authentication',
                'CVE-2023-67890: Cross-site scripting vulnerability in web interface',
                'CVE-2024-11111: Remote code execution in file processing',
                'CVE-2024-22222: Privilege escalation in configuration module',
            ],
            'mitre': [
                'CWE-89: SQL Injection vulnerability detected',
                'CWE-79: Cross-site Scripting (XSS) vulnerability found',
                'CWE-94: Code Injection vulnerability in parsing logic',
                'CWE-287: Authentication bypass vulnerability',
            ],
            'snyk': [
                'SNYK-001: High severity dependency vulnerability',
                'SNYK-002: Medium severity prototype pollution',
                'SNYK-003: Low severity information disclosure',
                'SNYK-004: Critical remote code execution',
            ],
            'exploit_db': [
                'EDB-50001: Public exploit available for authentication bypass',
                'EDB-50002: Proof of concept for privilege escalation',
                'EDB-50003: Remote shell exploit for file upload vulnerability',
            ]
        }
    
    async def initialize(self):
        """Initialize mock sandbox manager"""
        print("🔧 Initializing Mock Sandbox Manager for demo...")
        await asyncio.sleep(0.1)  # Simulate initialization delay
        self.is_initialized = True
        print("✅ Mock Sandbox Manager initialized successfully")
    
    async def health_check_all(self) -> Dict[str, bool]:
        """Mock health check for all sandboxes"""
        return {
            'nvd_sandbox': True,
            'mitre_sandbox': True,
            'snyk_sandbox': True,
            'exploit_db_sandbox': True,
            'mock_sandbox': True
        }
    
    async def scan_package(self, package_name: str, current_version: Optional[str] = None) -> Dict[str, MockVulnerabilityResult]:
        """
        Mock basic package scanning without AI enhancement.
        
        Args:
            package_name: Name of package to scan
            current_version: Current version of package
            
        Returns:
            Dictionary with mock scan results from different sources
        """
        await asyncio.sleep(random.uniform(0.1, 0.5))  # Simulate scan time
        
        results = {}
        
        # Generate mock results for each database
        for db_name in ['nvd', 'mitre', 'snyk', 'exploit_db']:
            vuln_count = random.randint(0, 3)  # Random number of vulnerabilities
            vulnerabilities = []
            
            if vuln_count > 0:
                # Pick random vulnerabilities from our mock data
                available_vulns = self.mock_vulnerability_data.get(db_name, [])
                selected_vulns = random.sample(available_vulns, min(vuln_count, len(available_vulns)))
                
                for vuln in selected_vulns:
                    vulnerabilities.append({
                        'id': f"{db_name.upper()}-{random.randint(1000, 9999)}",
                        'description': vuln,
                        'severity': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                        'package': package_name,
                        'version_affected': current_version or 'unknown',
                        'discovered_date': datetime.now().strftime('%Y-%m-%d')
                    })
            
            results[db_name] = MockVulnerabilityResult(
                success=True,
                vulnerabilities=vulnerabilities,
                ai_enhanced=False
            )
        
        return results
    
    async def scan_package_with_ai_analysis(self, 
                                          package_name: str,
                                          current_version: Optional[str] = None,
                                          include_correlation_analysis: bool = True,
                                          include_risk_assessment: bool = True) -> Dict[str, Any]:
        """
        Mock AI-enhanced package scanning.
        
        Args:
            package_name: Name of package to scan
            current_version: Current version of package
            include_correlation_analysis: Whether to include correlation analysis
            include_risk_assessment: Whether to include risk assessment
            
        Returns:
            Dictionary with mock AI-enhanced scan results
        """
        # First get basic scan results
        scan_results = await self.scan_package(package_name, current_version)
        
        # Mark some results as AI-enhanced
        for db_name, result in scan_results.items():
            if random.choice([True, False]):  # 50% chance of AI enhancement
                result.ai_enhanced = True
                # Add some AI-enhanced vulnerability details
                for vuln in result.vulnerabilities:
                    vuln['ai_confidence'] = random.uniform(0.7, 0.95)
                    vuln['ai_severity_adjustment'] = random.choice(['confirmed', 'elevated', 'reduced'])
        
        # Mock correlation analysis
        correlation_analysis = None
        if include_correlation_analysis:
            all_vulnerabilities = []
            for result in scan_results.values():
                all_vulnerabilities.extend(result.vulnerabilities)
            
            # Mock deduplication and correlation
            unique_vulns = all_vulnerabilities[:len(all_vulnerabilities)//2] if all_vulnerabilities else []
            
            class MockCorrelationAnalysis:
                def __init__(self, all_vulns, unique_vulns):
                    self.total_vulnerabilities_found = len(all_vulns)
                    self.unique_vulnerabilities = unique_vulns
                    self.duplicates_removed = len(all_vulns) - len(unique_vulns)
                    self.correlation_confidence = random.uniform(0.8, 0.95)
                    self.cross_database_matches = random.randint(0, 2)
            
            correlation_analysis = MockCorrelationAnalysis(all_vulnerabilities, unique_vulns)
        
        # Mock risk assessment
        risk_assessment = None
        if include_risk_assessment:
            total_vulns = sum(len(r.vulnerabilities) for r in scan_results.values())
            critical_vulns = sum(1 for r in scan_results.values() 
                               for v in r.vulnerabilities 
                               if v.get('severity') == 'CRITICAL')
            high_risk_vulns = sum(1 for r in scan_results.values() 
                                for v in r.vulnerabilities 
                                if v.get('severity') == 'HIGH')
            
            # Calculate mock risk score
            risk_score = min(1.0, (critical_vulns * 0.4 + high_risk_vulns * 0.3 + total_vulns * 0.1))
            
            # Create a simple object to hold risk assessment data
            class MockRiskAssessment:
                def __init__(self, risk_score, critical_vulns, high_risk_vulns, total_vulns, current_version, parent):
                    self.overall_package_risk = risk_score
                    self.critical_vulnerabilities = critical_vulns
                    self.high_risk_vulnerabilities = high_risk_vulns
                    self.risk_factors = [
                        f"Package has {total_vulns} known vulnerabilities",
                        f"Found {critical_vulns} critical severity issues",
                        f"Version {current_version or 'unknown'} may be outdated"
                    ] if total_vulns > 0 else ["No significant security risks detected"]
                    self.recommended_actions = parent._generate_mock_recommendations(total_vulns, critical_vulns, high_risk_vulns)
            
            risk_assessment = MockRiskAssessment(risk_score, critical_vulns, high_risk_vulns, total_vulns, current_version, self)
        
        return {
            'scan_results': scan_results,
            'correlation_analysis': correlation_analysis,
            'risk_assessment': risk_assessment,
            'ai_processing_time': random.uniform(0.5, 2.0),
            'mock_data': True  # Indicate this is mock data
        }
    
    def _generate_mock_recommendations(self, total_vulns: int, critical_vulns: int, high_risk_vulns: int) -> List[str]:
        """Generate mock AI recommendations based on vulnerability counts"""
        recommendations = []
        
        if critical_vulns > 0:
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED: Critical vulnerabilities detected",
                "Update package to latest version immediately",
                "Consider alternative packages if updates unavailable"
            ])
        elif high_risk_vulns > 0:
            recommendations.extend([
                "HIGH PRIORITY: Schedule security update within 48 hours",
                "Review package dependencies for additional risks",
                "Monitor security advisories for this package"
            ])
        elif total_vulns > 0:
            recommendations.extend([
                "MODERATE RISK: Plan security update in next maintenance window",
                "Verify package usage in production environments",
                "Consider implementing additional security controls"
            ])
        else:
            recommendations.extend([
                "PROCEED: No significant security risks detected",
                "Continue monitoring for new security advisories",
                "Keep package updated with regular maintenance"
            ])
        
        return recommendations
    
    async def cleanup(self):
        """Cleanup mock sandbox manager"""
        print("🧹 Cleaning up Mock Sandbox Manager...")
        await asyncio.sleep(0.1)
        self.is_initialized = False
        print("✅ Mock Sandbox Manager cleanup completed")