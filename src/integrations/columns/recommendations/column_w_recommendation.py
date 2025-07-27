"""
Column W: Recommendation Processor

Generates comprehensive IHACPA recommendations based on all vulnerability scan results.
Implements retired version's sophisticated 4-tier recommendation system with enhanced classification.
"""

import logging
from typing import Dict, Any, List, Optional
from ....core.ai_analyzer import AIAnalyzer


class RecommendationProcessor:
    """
    Processor for Column W - IHACPA Recommendations
    
    Based on retired version's sophisticated multi-tier recommendation logic:
    - Tier 1: Security Issues (Highest Priority) 
    - Tier 2: Manual Review Required
    - Tier 3: Version Updates
    - Tier 4: Additional Information (SAFE findings)
    """
    
    def __init__(self, ai_analyzer: Optional[AIAnalyzer] = None):
        """
        Initialize processor.
        
        Args:
            ai_analyzer: Optional AI analyzer for enhanced recommendations
        """
        self.ai_analyzer = ai_analyzer
        self.logger = logging.getLogger(__name__)
    
    async def process(self, package_name: str, current_version: str, latest_version: str,
                     vulnerability_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process Column W: IHACPA Recommendation
        
        Generates comprehensive recommendations based on all vulnerability scan results.
        Implements retired version's enhanced multi-tier classification system.
        
        Args:
            package_name: Name of the Python package
            current_version: Current installed version
            latest_version: Latest available version
            vulnerability_results: Combined results from all vulnerability scans (columns M, P, R, T, V)
            
        Returns:
            Dictionary with recommendation and cell formatting
        """
        try:
            self.logger.debug(f"Processing Column W (recommendation) for {package_name}")
            
            # Check for maintenance mode packages first
            maintenance_check = self._check_maintenance_mode(package_name)
            if maintenance_check:
                return {
                    'value': maintenance_check['recommendation'],
                    'color': 'maintenance',
                    'font': 'warning',
                    'note': maintenance_check['note'],
                    'maintenance_warning': True
                }
            
            # Extract scan results from all vulnerability databases
            scan_results = self._extract_scan_results(vulnerability_results)
            
            # Phase 1: Enhanced classification with proper SAFE vs VULNERABLE distinction
            classifications = self._classify_all_database_results(scan_results)
            
            # Phase 2: Multi-tier recommendation logic (following retired version)
            recommendation = self._generate_multi_tier_recommendation(
                package_name, current_version, latest_version, classifications
            )
            
            # Phase 3: AI enhancement if available
            if self.ai_analyzer:
                try:
                    ai_recommendation = await self.ai_analyzer.generate_recommendation(
                        package_name, vulnerability_results
                    )
                    if ai_recommendation:
                        recommendation = self._enhance_with_ai(recommendation, ai_recommendation)
                except Exception as e:
                    self.logger.warning(f"AI recommendation failed for {package_name}: {e}")
            
            # Determine color and formatting based on recommendation severity
            color_info = self._determine_recommendation_formatting(recommendation, classifications)
            
            return {
                'value': recommendation,
                'color': color_info['color'],
                'font': color_info['font'],
                'note': color_info['note'],
                'classification_summary': classifications,
                'recommendation_tier': color_info['tier'],
                'ai_enhanced': self.ai_analyzer is not None
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Column W for {package_name}: {e}")
            return {
                'value': 'Error generating recommendation',
                'color': 'critical',
                'font': 'critical',
                'note': f'Error generating recommendation: {str(e)}'
            }
    
    def _extract_scan_results(self, vulnerability_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract scan results from all vulnerability databases.
        
        Maps results from columns M, P, R, T, V to database names.
        """
        scan_results = {}
        
        # Map column results to database names (following retired version's mapping)
        column_db_mapping = {
            'M': 'github_advisory',  # GitHub Security Advisory Result
            'P': 'nist_nvd',         # NIST NVD Lookup Result
            'R': 'mitre_cve',        # MITRE CVE Lookup Result  
            'T': 'snyk',             # SNYK Vulnerability Lookup Result
            'V': 'exploit_db'        # Exploit Database Lookup Result
        }
        
        for column, db_name in column_db_mapping.items():
            if column in vulnerability_results:
                result = vulnerability_results[column]
                
                # Normalize result format for classification
                scan_results[db_name] = {
                    'summary': result.get('value', ''),
                    'vulnerability_count': result.get('vulnerability_count', 0),
                    'found_vulnerabilities': result.get('found_vulnerabilities', False),
                    'classification_status': result.get('classification_status', 'none_found'),
                    'severity': result.get('severity', 'NONE'),
                    'ai_analysis': result.get('ai_analysis', ''),
                    'database': db_name
                }
        
        return scan_results
    
    def _classify_all_database_results(self, scan_results: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Classify all database results using retired version's enhanced classification logic.
        
        Returns classification into 4 categories:
        - vulnerable: Confirmed security risks requiring action
        - safe: CVEs found but current version not affected
        - manual_review: Requires human assessment  
        - none_found: No relevant vulnerabilities
        """
        classifications = {
            'vulnerable': [],
            'safe': [],
            'manual_review': [],
            'none_found': []
        }
        
        # Database display names (from retired version)
        db_names = {
            'github_advisory': 'GitHub Advisory',
            'nist_nvd': 'NIST NVD',
            'mitre_cve': 'MITRE CVE', 
            'snyk': 'SNYK',
            'exploit_db': 'Exploit Database'
        }
        
        # Classify each database result using retired version's enhanced logic
        for db_name, result in scan_results.items():
            if db_name in db_names:
                classification = self._classify_database_result_enhanced(result, db_name)
                
                classifications[classification['status']].append({
                    'database': db_names[db_name],
                    'db_key': db_name,
                    'count': classification['count'],
                    'severity': classification.get('severity', 'UNKNOWN'),
                    'note': classification.get('note', '')
                })
        
        return classifications
    
    def _classify_database_result_enhanced(self, result: Dict[str, Any], db_name: str) -> Dict[str, Any]:
        """
        Enhanced classification with proper SAFE vs VULNERABLE distinction.
        
        Based on retired version's _classify_database_result_enhanced method.
        """
        summary = result.get('summary', '').lower()
        ai_analysis = result.get('ai_analysis', '').lower()
        vulnerability_count = result.get('vulnerability_count', 0)
        classification_status = result.get('classification_status', 'none_found')
        
        # Priority 1: Check for explicit SAFE indication
        if ('safe -' in summary and 'not affected' in summary) or \
           ('safe -' in summary and 'but v' in summary) or \
           classification_status == 'safe':
            return {
                'status': 'safe',
                'count': vulnerability_count,
                'severity': self._extract_severity_robust(result),
                'note': f'{vulnerability_count} CVEs found but current version not affected'
            }
        
        # Priority 2: Check for explicit VULNERABLE indication
        if ('vulnerable -' in summary and 'affect' in summary) or \
           ('vulnerable -' in summary and 'cves affect' in summary) or \
           classification_status == 'vulnerable':
            return {
                'status': 'vulnerable',
                'count': vulnerability_count,
                'severity': self._extract_severity_robust(result),
                'note': f'{vulnerability_count} CVEs affect current version'
            }
        
        # Priority 3: Apply < 10 CVE threshold logic (from retired version)
        if 'manual review required' in summary or classification_status == 'manual_review':
            if vulnerability_count < 10:
                # Convert to SAFE per threshold logic
                return {
                    'status': 'safe',
                    'count': 0,
                    'severity': 'NONE',
                    'note': f'{vulnerability_count} CVEs found but < 10 threshold - treated as SAFE'
                }
            else:
                # Keep as manual review for ≥ 10 CVEs
                return {
                    'status': 'manual_review',
                    'count': 0,
                    'severity': 'UNKNOWN',
                    'note': f'{vulnerability_count} CVEs require manual assessment'
                }
        
        # Priority 4: Check for explicit "none found"
        if 'none found' in summary or 'no published' in summary or classification_status == 'none_found':
            return {
                'status': 'none_found',
                'count': 0,
                'severity': 'NONE',
                'note': 'No relevant vulnerabilities found'
            }
        
        # Priority 5: Check AI analysis for Exploit Database
        if db_name == 'exploit_db' and ai_analysis:
            if 'not_found' in ai_analysis or 'no exploits found' in ai_analysis:
                return {
                    'status': 'none_found',
                    'count': 0,
                    'severity': 'NONE', 
                    'note': 'No exploits found'
                }
            elif ': found' in ai_analysis and 'not_found' not in ai_analysis:
                return {
                    'status': 'vulnerable',
                    'count': max(vulnerability_count, 1),
                    'severity': self._extract_severity_robust(result),
                    'note': 'Exploits found via AI analysis'
                }
        
        # Priority 6: Legacy logic for edge cases
        if result.get('found_vulnerabilities', False) and vulnerability_count > 0:
            # Determine if SAFE or VULNERABLE based on summary context
            if 'but v' in summary and 'not affected' in summary:
                return {
                    'status': 'safe',
                    'count': vulnerability_count,
                    'severity': self._extract_severity_robust(result),
                    'note': f'{vulnerability_count} CVEs found but version not affected'
                }
            else:
                return {
                    'status': 'vulnerable',
                    'count': vulnerability_count,
                    'severity': self._extract_severity_robust(result),
                    'note': f'{vulnerability_count} vulnerabilities detected'
                }
        
        # Default: No vulnerabilities found
        return {
            'status': 'none_found',
            'count': 0,
            'severity': 'NONE',
            'note': 'No vulnerabilities detected'
        }
    
    def _generate_multi_tier_recommendation(self, package_name: str, current_version: str, 
                                          latest_version: str, classifications: Dict[str, List[Dict[str, Any]]]) -> str:
        """
        Generate multi-tier recommendation using retired version's sophisticated logic.
        
        Implements the 4-tier system:
        1. Security Issues (Highest Priority)
        2. Manual Review Required  
        3. Version Updates
        4. Additional Information
        """
        recommendations = []
        action_prefix = ""
        
        # Tier 1: Security Issues (Highest Priority)
        if classifications['vulnerable']:
            total_vulns = sum(item['count'] for item in classifications['vulnerable'])
            highest_severity = self._get_highest_severity_enhanced([item['severity'] for item in classifications['vulnerable']])
            
            action_prefix = "🚨 SECURITY RISK"
            recommendations.append(f"{total_vulns} confirmed vulnerabilities found")
            
            if highest_severity in ['CRITICAL', 'HIGH']:
                recommendations.append(f"⚡ HIGH PRIORITY: {highest_severity} severity detected")
            
            # Show vulnerable sources
            vuln_sources = []
            for item in classifications['vulnerable']:
                count_text = f"{item['count']} ({item['severity']})" if item['severity'] != 'UNKNOWN' else str(item['count'])
                vuln_sources.append(f"{item['database']}: {count_text}")
            recommendations.append(f"Sources: {', '.join(vuln_sources)}")
            recommendations.append("⚠️ Review security advisories before deployment")
            
            # Version update for vulnerable packages
            if current_version != latest_version:
                recommendations.insert(1, f"📦 UPDATE REQUIRED: {current_version} → {latest_version}")
        
        # Tier 2: Manual Review Required (when no confirmed vulnerabilities)
        elif classifications['manual_review']:
            manual_sources = [item['database'] for item in classifications['manual_review']]
            action_prefix = "🔍 MANUAL REVIEW"
            recommendations.append(f"{', '.join(manual_sources)} require human assessment")
            
            # Show details for manual review
            for item in classifications['manual_review']:
                if item['note']:
                    recommendations.append(f"• {item['database']}: {item['note']}")
            
            recommendations.append("📋 Human review needed for indeterminate cases")
        
        # Tier 3: Version Updates (when no security risks or manual review)
        else:
            version_update_needed = current_version != latest_version
            if version_update_needed:
                action_prefix = "✅ PROCEED WITH UPDATE"
                recommendations.append(f"📦 UPDATE AVAILABLE: {current_version} → {latest_version}")
                recommendations.append("✅ No security risks detected - safe to update")
            else:
                action_prefix = "✅ PROCEED"
        
        # Tier 4: Additional Information (SAFE findings)
        if classifications['safe']:
            safe_count = sum(item['count'] for item in classifications['safe'])
            safe_sources = [item['database'] for item in classifications['safe']]
            info_text = f"ℹ️ INFO: {safe_count} CVEs found but current version not affected"
            if len(safe_sources) <= 2:
                info_text += f" ({', '.join(safe_sources)})"
            recommendations.append(info_text)
        
        # Return final recommendation
        if recommendations:
            return f"{action_prefix} | {' | '.join(recommendations)}"
        else:
            return action_prefix or "✅ PROCEED"
    
    def _enhance_with_ai(self, base_recommendation: str, ai_recommendation: str) -> str:
        """Enhance base recommendation with AI insights."""
        try:
            # If AI provides a clear recommendation, use it as the primary
            if ai_recommendation and len(ai_recommendation.strip()) > 10:
                return f"AI: {ai_recommendation.strip()}"
            else:
                return base_recommendation
        except Exception:
            return base_recommendation
    
    def _determine_recommendation_formatting(self, recommendation: str, classifications: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Determine color and formatting based on recommendation content."""
        rec_lower = recommendation.lower()
        
        # Critical security risks
        if '🚨' in recommendation or 'security risk' in rec_lower:
            return {
                'color': 'security_risk',
                'font': 'security_risk',
                'note': 'Critical security issues detected - immediate action required',
                'tier': 1
            }
        
        # Manual review required
        elif '🔍' in recommendation or 'manual review' in rec_lower:
            return {
                'color': 'version_update',
                'font': 'version_update',
                'note': 'Manual review required for security assessment',
                'tier': 2
            }
        
        # Version updates available
        elif 'update available' in rec_lower or 'proceed with update' in rec_lower:
            return {
                'color': 'updated',
                'font': 'updated',
                'note': 'Version update available - no security risks detected',
                'tier': 3
            }
        
        # All clear
        else:
            return {
                'color': 'new_data',
                'font': 'new_data',
                'note': 'No security issues detected - package is safe to use',
                'tier': 4
            }
    
    def _extract_severity_robust(self, result: Dict[str, Any]) -> str:
        """Extract severity from result with robust fallback logic."""
        severity = result.get('severity', 'NONE')
        if severity and severity != 'NONE':
            return severity.upper()
        
        # Fallback based on vulnerability count
        count = result.get('vulnerability_count', 0)
        if count >= 5:
            return 'HIGH'
        elif count >= 2:
            return 'MEDIUM'
        elif count >= 1:
            return 'LOW'
        else:
            return 'NONE'
    
    def _get_highest_severity_enhanced(self, severities: List[str]) -> str:
        """Get highest severity from list with enhanced priority."""
        severity_priority = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'NONE': 1,
            'UNKNOWN': 0
        }
        
        if not severities:
            return 'NONE'
        
        highest = max(severities, key=lambda s: severity_priority.get(s.upper(), 0))
        return highest.upper()
    
    def _check_maintenance_mode(self, package_name: str) -> Optional[Dict[str, str]]:
        """
        Check if package is in maintenance mode or deprecated.
        
        Args:
            package_name: Name of the package to check
            
        Returns:
            Dictionary with maintenance warning if applicable
        """
        package_lower = package_name.lower()
        
        # Known maintenance mode packages based on stakeholder feedback
        maintenance_packages = {
            'py': {
                'recommendation': '⚠️ MAINTENANCE MODE | Package "py" has been in maintenance mode since 2021 and should not be used for new code',
                'note': 'Package is no longer actively maintained - use alternatives for new projects'
            }
        }
        
        if package_lower in maintenance_packages:
            return maintenance_packages[package_lower]
        
        return None