"""
Cross-Database Correlation Analyzer

AI-powered analysis engine for correlating vulnerabilities across multiple
security databases and providing unified threat intelligence.
"""

import asyncio
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from collections import defaultdict

from langchain.prompts import PromptTemplate
from langchain.schema import BaseOutputParser

from ...core.base_scanner import ScanResult, VulnerabilityInfo, SeverityLevel
from ..chain_factory import get_ai_factory


@dataclass
class VulnerabilityCorrelation:
    """
    Correlation between vulnerabilities from different sources.
    """
    primary_vuln: VulnerabilityInfo
    correlated_vulns: List[VulnerabilityInfo]
    correlation_confidence: float  # 0.0 to 1.0
    correlation_reasoning: str
    unified_severity: SeverityLevel
    ai_risk_score: float  # 0.0 to 1.0
    cross_database_insights: str
    
    def get_all_cve_ids(self) -> List[str]:
        """Get all CVE IDs from correlated vulnerabilities"""
        cve_ids = []
        if self.primary_vuln.cve_id:
            cve_ids.append(self.primary_vuln.cve_id)
        
        for vuln in self.correlated_vulns:
            if vuln.cve_id and vuln.cve_id not in cve_ids:
                cve_ids.append(vuln.cve_id)
        
        return cve_ids
    
    def get_source_distribution(self) -> Dict[str, int]:
        """Get distribution of sources in correlation"""
        sources = defaultdict(int)
        
        # Count primary vulnerability source
        # Note: This would need to be tracked in VulnerabilityInfo
        
        for vuln in self.correlated_vulns:
            # This would need source information in VulnerabilityInfo
            pass
        
        return dict(sources)


@dataclass
class CrossDatabaseAnalysis:
    """
    Comprehensive analysis result across multiple vulnerability databases.
    """
    package_name: str
    analysis_timestamp: datetime
    
    # Individual scan results
    scan_results: Dict[str, ScanResult]  # source -> result
    
    # Correlation analysis
    correlations: List[VulnerabilityCorrelation]
    unique_vulnerabilities: List[VulnerabilityInfo]
    duplicate_count: int
    
    # AI-powered insights
    ai_overall_risk_assessment: str
    ai_priority_vulnerabilities: List[str]  # CVE IDs or titles
    ai_threat_landscape_summary: str
    ai_remediation_strategy: str
    ai_confidence_score: float
    
    # Cross-database statistics
    database_coverage: Dict[str, float]  # source -> coverage score
    data_quality_scores: Dict[str, float]  # source -> quality score
    consensus_confidence: float  # How much databases agree
    
    def get_high_priority_vulnerabilities(self) -> List[VulnerabilityInfo]:
        """Get vulnerabilities marked as high priority"""
        high_priority = []
        
        for vuln in self.unique_vulnerabilities:
            if (vuln.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] or
                any(vuln.cve_id in self.ai_priority_vulnerabilities or 
                    vuln.title in self.ai_priority_vulnerabilities 
                    for _ in [1])):  # Simplified check
                high_priority.append(vuln)
        
        return high_priority
    
    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get summary of correlation analysis"""
        return {
            "total_vulnerabilities_found": sum(len(result.vulnerabilities) for result in self.scan_results.values()),
            "unique_vulnerabilities": len(self.unique_vulnerabilities),
            "correlations_found": len(self.correlations),
            "duplicate_count": self.duplicate_count,
            "database_coverage": self.database_coverage,
            "consensus_confidence": self.consensus_confidence,
            "high_priority_count": len(self.get_high_priority_vulnerabilities()),
            "ai_confidence": self.ai_confidence_score
        }


class CorrelationOutputParser(BaseOutputParser):
    """Parser for AI correlation analysis output"""
    
    def parse(self, text: str) -> Dict[str, Any]:
        """Parse correlation analysis output"""
        try:
            # Try to parse as JSON first
            return json.loads(text)
        except json.JSONDecodeError:
            # Fallback to pattern matching
            result = {
                "overall_risk": "medium",
                "priority_vulnerabilities": [],
                "threat_summary": "Cross-database analysis completed",
                "remediation_strategy": "Review identified vulnerabilities and apply patches",
                "confidence_score": 0.7
            }
            
            # Extract information using patterns
            import re
            
            # Extract risk level
            risk_match = re.search(r"(?:risk|threat).*?level.*?:.*?(critical|high|medium|low)", text, re.IGNORECASE)
            if risk_match:
                result["overall_risk"] = risk_match.group(1).lower()
            
            # Extract CVE IDs mentioned
            cve_matches = re.findall(r"CVE-\d{4}-\d{4,}", text)
            result["priority_vulnerabilities"] = list(set(cve_matches))
            
            # Extract confidence score
            conf_match = re.search(r"confidence.*?:.*?(\d+(?:\.\d+)?)", text, re.IGNORECASE)
            if conf_match:
                result["confidence_score"] = float(conf_match.group(1))
                if result["confidence_score"] > 1.0:
                    result["confidence_score"] = result["confidence_score"] / 100.0
            
            return result


class CrossDatabaseCorrelationAnalyzer:
    """
    AI-powered analyzer for correlating vulnerabilities across multiple databases.
    """
    
    def __init__(self, ai_factory=None):
        self.ai_factory = ai_factory or get_ai_factory()
        self.output_parser = CorrelationOutputParser()
        
        # Create correlation analysis prompt
        self.correlation_prompt = PromptTemplate(
            input_variables=[
                "package_name", "scan_results_summary", "vulnerability_details",
                "cve_overlaps", "severity_distribution", "source_reliability"
            ],
            template="""
            You are a cybersecurity expert analyzing vulnerability data from multiple security databases.
            
            Package: {package_name}
            
            Scan Results Summary:
            {scan_results_summary}
            
            Vulnerability Details:
            {vulnerability_details}
            
            CVE Overlaps:
            {cve_overlaps}
            
            Severity Distribution:
            {severity_distribution}
            
            Source Reliability:
            {source_reliability}
            
            Perform cross-database correlation analysis and provide:
            
            1. OVERALL_RISK: Overall risk assessment (critical/high/medium/low)
            2. PRIORITY_VULNERABILITIES: List of CVE IDs or vulnerability titles that need immediate attention
            3. THREAT_SUMMARY: Comprehensive threat landscape summary
            4. REMEDIATION_STRATEGY: Prioritized remediation approach
            5. CONFIDENCE_SCORE: Analysis confidence (0.0-1.0)
            6. CORRELATIONS: Key correlations found between databases
            7. DATA_QUALITY: Assessment of data quality and consistency
            
            Focus on:
            - Identifying true positives vs false positives
            - Resolving conflicting severity assessments
            - Finding gaps in coverage
            - Prioritizing based on exploit availability and threat intelligence
            - Providing actionable recommendations
            
            Format as JSON with keys: overall_risk, priority_vulnerabilities, threat_summary, 
            remediation_strategy, confidence_score, correlations, data_quality
            """.strip()
        )
    
    async def analyze_cross_database_results(
        self,
        package_name: str,
        scan_results: Dict[str, ScanResult]
    ) -> CrossDatabaseAnalysis:
        """
        Perform comprehensive cross-database correlation analysis.
        
        Args:
            package_name: Name of the scanned package
            scan_results: Dictionary of scan results from different sources
            
        Returns:
            CrossDatabaseAnalysis with correlations and insights
        """
        analysis_start = datetime.utcnow()
        
        try:
            # Step 1: Find correlations and deduplicate
            correlations = await self._find_correlations(scan_results)
            unique_vulnerabilities = self._deduplicate_vulnerabilities(scan_results)
            
            # Step 2: Calculate database metrics
            database_coverage = self._calculate_database_coverage(scan_results)
            data_quality_scores = self._calculate_data_quality(scan_results)
            consensus_confidence = self._calculate_consensus_confidence(correlations)
            
            # Step 3: Get AI analysis
            ai_analysis = await self._get_ai_correlation_analysis(
                package_name, scan_results, correlations, unique_vulnerabilities
            )
            
            # Step 4: Create comprehensive analysis
            analysis = CrossDatabaseAnalysis(
                package_name=package_name,
                analysis_timestamp=analysis_start,
                scan_results=scan_results,
                correlations=correlations,
                unique_vulnerabilities=unique_vulnerabilities,
                duplicate_count=self._count_duplicates(scan_results),
                ai_overall_risk_assessment=ai_analysis.get("overall_risk", "medium"),
                ai_priority_vulnerabilities=ai_analysis.get("priority_vulnerabilities", []),
                ai_threat_landscape_summary=ai_analysis.get("threat_summary", ""),
                ai_remediation_strategy=ai_analysis.get("remediation_strategy", ""),
                ai_confidence_score=ai_analysis.get("confidence_score", 0.7),
                database_coverage=database_coverage,
                data_quality_scores=data_quality_scores,
                consensus_confidence=consensus_confidence
            )
            
            return analysis
            
        except Exception as e:
            # Return fallback analysis
            return self._create_fallback_analysis(package_name, scan_results, str(e))
    
    async def _find_correlations(
        self,
        scan_results: Dict[str, ScanResult]
    ) -> List[VulnerabilityCorrelation]:
        """Find correlations between vulnerabilities from different sources"""
        correlations = []
        
        # Group vulnerabilities by CVE ID
        cve_groups = defaultdict(list)
        title_groups = defaultdict(list)
        
        for source, result in scan_results.items():
            if not result.success:
                continue
                
            for vuln in result.vulnerabilities:
                # Group by CVE ID
                if vuln.cve_id:
                    cve_groups[vuln.cve_id].append((source, vuln))
                
                # Group by normalized title for non-CVE vulnerabilities
                normalized_title = self._normalize_title(vuln.title)
                title_groups[normalized_title].append((source, vuln))
        
        # Create correlations for CVE groups
        for cve_id, source_vulns in cve_groups.items():
            if len(source_vulns) > 1:
                correlation = await self._create_correlation_from_group(cve_id, source_vulns, "CVE")
                if correlation:
                    correlations.append(correlation)
        
        # Create correlations for title groups (more uncertain)
        for title, source_vulns in title_groups.items():
            if len(source_vulns) > 1:
                # Skip if already correlated by CVE
                cve_ids = [vuln.cve_id for _, vuln in source_vulns if vuln.cve_id]
                if not any(cve_id in cve_groups for cve_id in cve_ids):
                    correlation = await self._create_correlation_from_group(title, source_vulns, "title")
                    if correlation:
                        correlations.append(correlation)
        
        return correlations
    
    async def _create_correlation_from_group(
        self,
        identifier: str,
        source_vulns: List[Tuple[str, VulnerabilityInfo]],
        correlation_type: str
    ) -> Optional[VulnerabilityCorrelation]:
        """Create a correlation from a group of related vulnerabilities"""
        try:
            # Select primary vulnerability (highest confidence or most detailed)
            primary_source, primary_vuln = max(
                source_vulns,
                key=lambda x: (
                    x[1].confidence.value if hasattr(x[1].confidence, 'value') else 0.5,
                    len(x[1].description),
                    x[1].cvss_score or 0
                )
            )
            
            # Get correlated vulnerabilities
            correlated_vulns = [vuln for source, vuln in source_vulns if source != primary_source]
            
            # Calculate correlation confidence
            confidence = 1.0 if correlation_type == "CVE" else 0.7
            
            # Determine unified severity using AI
            unified_severity = await self._determine_unified_severity(primary_vuln, correlated_vulns)
            
            # Calculate AI risk score
            risk_score = await self._calculate_ai_risk_score(primary_vuln, correlated_vulns)
            
            # Generate cross-database insights
            insights = await self._generate_cross_database_insights(
                identifier, source_vulns, correlation_type
            )
            
            return VulnerabilityCorrelation(
                primary_vuln=primary_vuln,
                correlated_vulns=correlated_vulns,
                correlation_confidence=confidence,
                correlation_reasoning=f"Correlated by {correlation_type}: {identifier}",
                unified_severity=unified_severity,
                ai_risk_score=risk_score,
                cross_database_insights=insights
            )
            
        except Exception as e:
            print(f"Failed to create correlation for {identifier}: {e}")
            return None
    
    def _normalize_title(self, title: str) -> str:
        """Normalize vulnerability title for comparison"""
        import re
        
        # Remove common prefixes and normalize
        title = re.sub(r'^(CVE|GHSA|SNYK)-\S+\s*:?\s*', '', title, flags=re.IGNORECASE)
        title = re.sub(r'\s+', ' ', title.strip().lower())
        
        # Remove version numbers for better matching
        title = re.sub(r'\b\d+\.\d+(\.\d+)*\b', '', title)
        
        return title.strip()
    
    def _deduplicate_vulnerabilities(
        self,
        scan_results: Dict[str, ScanResult]
    ) -> List[VulnerabilityInfo]:
        """Deduplicate vulnerabilities across all sources"""
        seen_cves = set()
        seen_titles = set()
        unique_vulns = []
        
        # First pass: collect by CVE ID
        for source, result in scan_results.items():
            if not result.success:
                continue
                
            for vuln in result.vulnerabilities:
                if vuln.cve_id and vuln.cve_id not in seen_cves:
                    seen_cves.add(vuln.cve_id)
                    unique_vulns.append(vuln)
        
        # Second pass: collect by normalized title (for non-CVE vulnerabilities)
        for source, result in scan_results.items():
            if not result.success:
                continue
                
            for vuln in result.vulnerabilities:
                if not vuln.cve_id:
                    normalized_title = self._normalize_title(vuln.title)
                    if normalized_title not in seen_titles:
                        seen_titles.add(normalized_title)
                        unique_vulns.append(vuln)
        
        return unique_vulns
    
    def _count_duplicates(self, scan_results: Dict[str, ScanResult]) -> int:
        """Count total duplicates found"""
        total_vulns = sum(len(result.vulnerabilities) for result in scan_results.values() if result.success)
        unique_count = len(self._deduplicate_vulnerabilities(scan_results))
        return max(0, total_vulns - unique_count)
    
    def _calculate_database_coverage(self, scan_results: Dict[str, ScanResult]) -> Dict[str, float]:
        """Calculate coverage score for each database"""
        coverage = {}
        
        for source, result in scan_results.items():
            if result.success:
                # Simple coverage based on number of vulnerabilities found
                vuln_count = len(result.vulnerabilities)
                coverage[source] = min(1.0, vuln_count / 10.0)  # Normalize to 0-1
            else:
                coverage[source] = 0.0
        
        return coverage
    
    def _calculate_data_quality(self, scan_results: Dict[str, ScanResult]) -> Dict[str, float]:
        """Calculate data quality score for each database"""
        quality_scores = {}
        
        for source, result in scan_results.items():
            if not result.success:
                quality_scores[source] = 0.0
                continue
            
            score = 0.0
            total_vulns = len(result.vulnerabilities)
            
            if total_vulns == 0:
                quality_scores[source] = 0.5  # Neutral score for no vulnerabilities
                continue
            
            # Quality metrics
            cve_coverage = sum(1 for v in result.vulnerabilities if v.cve_id) / total_vulns
            desc_quality = sum(1 for v in result.vulnerabilities if len(v.description) > 50) / total_vulns
            ref_quality = sum(1 for v in result.vulnerabilities if v.references) / total_vulns
            date_quality = sum(1 for v in result.vulnerabilities if v.published_date) / total_vulns
            
            # Weighted quality score
            score = (cve_coverage * 0.3 + desc_quality * 0.3 + 
                    ref_quality * 0.2 + date_quality * 0.2)
            
            quality_scores[source] = score
        
        return quality_scores
    
    def _calculate_consensus_confidence(self, correlations: List[VulnerabilityCorrelation]) -> float:
        """Calculate how much the databases agree"""
        if not correlations:
            return 0.5  # Neutral when no correlations
        
        # Average correlation confidence
        avg_confidence = sum(c.correlation_confidence for c in correlations) / len(correlations)
        return avg_confidence
    
    async def _determine_unified_severity(
        self,
        primary_vuln: VulnerabilityInfo,
        correlated_vulns: List[VulnerabilityInfo]
    ) -> SeverityLevel:
        """Determine unified severity using AI analysis"""
        try:
            # Collect all severities
            severities = [primary_vuln.severity]
            severities.extend([v.severity for v in correlated_vulns])
            
            # Use highest severity as baseline
            max_severity = max(severities, key=lambda s: self._severity_to_numeric(s))
            
            # Use AI to refine if there's disagreement
            if len(set(severities)) > 1:
                # AI analysis would go here
                return max_severity
            
            return max_severity
            
        except Exception:
            return SeverityLevel.MEDIUM  # Fallback
    
    def _severity_to_numeric(self, severity: SeverityLevel) -> int:
        """Convert severity to numeric for comparison"""
        severity_map = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
            SeverityLevel.UNKNOWN: 0
        }
        return severity_map.get(severity, 0)
    
    async def _calculate_ai_risk_score(
        self,
        primary_vuln: VulnerabilityInfo,
        correlated_vulns: List[VulnerabilityInfo]
    ) -> float:
        """Calculate AI-powered risk score"""
        try:
            # Base score from severity
            base_score = self._severity_to_numeric(primary_vuln.severity) / 5.0
            
            # Adjust for correlation confidence
            if correlated_vulns:
                # More sources confirming = higher confidence
                correlation_bonus = min(0.2, len(correlated_vulns) * 0.05)
                base_score += correlation_bonus
            
            # Adjust for CVSS score
            if primary_vuln.cvss_score:
                cvss_factor = primary_vuln.cvss_score / 10.0
                base_score = (base_score + cvss_factor) / 2.0
            
            return min(1.0, base_score)
            
        except Exception:
            return 0.5  # Fallback
    
    async def _generate_cross_database_insights(
        self,
        identifier: str,
        source_vulns: List[Tuple[str, VulnerabilityInfo]],
        correlation_type: str
    ) -> str:
        """Generate insights about cross-database correlation"""
        sources = [source for source, _ in source_vulns]
        
        if correlation_type == "CVE":
            return f"CVE {identifier} confirmed across {len(sources)} databases: {', '.join(sources)}. High confidence correlation."
        else:
            return f"Potential vulnerability correlation across {len(sources)} databases: {', '.join(sources)}. Medium confidence based on title similarity."
    
    async def _get_ai_correlation_analysis(
        self,
        package_name: str,
        scan_results: Dict[str, ScanResult],
        correlations: List[VulnerabilityCorrelation],
        unique_vulnerabilities: List[VulnerabilityInfo]
    ) -> Dict[str, Any]:
        """Get AI analysis of correlations and overall assessment"""
        try:
            # Prepare data for AI analysis
            scan_summary = self._create_scan_summary(scan_results)
            vuln_details = self._create_vulnerability_details(unique_vulnerabilities)
            cve_overlaps = self._analyze_cve_overlaps(correlations)
            severity_dist = self._analyze_severity_distribution(unique_vulnerabilities)
            source_reliability = self._assess_source_reliability(scan_results)
            
            # Create prompt
            prompt_vars = {
                "package_name": package_name,
                "scan_results_summary": scan_summary,
                "vulnerability_details": vuln_details,
                "cve_overlaps": cve_overlaps,
                "severity_distribution": severity_dist,
                "source_reliability": source_reliability
            }
            
            # Run AI analysis
            llm = self.ai_factory.get_chat_llm()
            chain = self.correlation_prompt | llm | self.output_parser
            
            result = await self._run_chain_async(chain, prompt_vars)
            return result
            
        except Exception as e:
            print(f"AI correlation analysis failed: {e}")
            return {
                "overall_risk": "medium",
                "priority_vulnerabilities": [],
                "threat_summary": "Cross-database analysis completed with limited AI insights",
                "remediation_strategy": "Review identified vulnerabilities and apply patches",
                "confidence_score": 0.5
            }
    
    def _create_scan_summary(self, scan_results: Dict[str, ScanResult]) -> str:
        """Create summary of scan results"""
        summary_lines = []
        
        for source, result in scan_results.items():
            if result.success:
                vuln_count = len(result.vulnerabilities)
                ai_enhanced = " (AI-enhanced)" if result.ai_enhanced else ""
                summary_lines.append(f"- {source}: {vuln_count} vulnerabilities{ai_enhanced}")
            else:
                summary_lines.append(f"- {source}: Failed - {result.error_message}")
        
        return "\n".join(summary_lines)
    
    def _create_vulnerability_details(self, vulnerabilities: List[VulnerabilityInfo]) -> str:
        """Create detailed vulnerability summary"""
        if not vulnerabilities:
            return "No vulnerabilities found"
        
        details = []
        for vuln in vulnerabilities[:10]:  # Limit to top 10
            cve_info = f" (CVE: {vuln.cve_id})" if vuln.cve_id else ""
            cvss_info = f" [CVSS: {vuln.cvss_score}]" if vuln.cvss_score else ""
            details.append(f"- {vuln.severity.value.upper()}: {vuln.title}{cve_info}{cvss_info}")
        
        if len(vulnerabilities) > 10:
            details.append(f"... and {len(vulnerabilities) - 10} more")
        
        return "\n".join(details)
    
    def _analyze_cve_overlaps(self, correlations: List[VulnerabilityCorrelation]) -> str:
        """Analyze CVE overlaps between databases"""
        if not correlations:
            return "No CVE overlaps found"
        
        overlaps = []
        for correlation in correlations:
            cve_ids = correlation.get_all_cve_ids()
            if cve_ids:
                overlaps.append(f"- {', '.join(cve_ids)}: {len(correlation.correlated_vulns) + 1} sources")
        
        return "\n".join(overlaps) if overlaps else "No significant CVE overlaps"
    
    def _analyze_severity_distribution(self, vulnerabilities: List[VulnerabilityInfo]) -> str:
        """Analyze severity distribution"""
        if not vulnerabilities:
            return "No vulnerabilities to analyze"
        
        severity_counts = defaultdict(int)
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        distribution = []
        for severity, count in severity_counts.items():
            percentage = (count / len(vulnerabilities)) * 100
            distribution.append(f"- {severity.value.upper()}: {count} ({percentage:.1f}%)")
        
        return "\n".join(distribution)
    
    def _assess_source_reliability(self, scan_results: Dict[str, ScanResult]) -> str:
        """Assess reliability of different sources"""
        reliability = []
        
        for source, result in scan_results.items():
            if result.success:
                ai_status = "AI-enhanced" if result.ai_enhanced else "Standard"
                vuln_count = len(result.vulnerabilities)
                reliability.append(f"- {source}: {ai_status}, {vuln_count} findings")
            else:
                reliability.append(f"- {source}: Failed")
        
        return "\n".join(reliability)
    
    async def _run_chain_async(self, chain, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Run the chain asynchronously"""
        try:
            result = chain.invoke(inputs)
            return result
        except Exception as e:
            print(f"Chain execution failed: {e}")
            return {
                "overall_risk": "medium",
                "priority_vulnerabilities": [],
                "threat_summary": "Analysis completed with errors",
                "remediation_strategy": "Manual review recommended",
                "confidence_score": 0.3
            }
    
    def _create_fallback_analysis(
        self,
        package_name: str,
        scan_results: Dict[str, ScanResult],
        error_message: str
    ) -> CrossDatabaseAnalysis:
        """Create fallback analysis when main analysis fails"""
        unique_vulns = self._deduplicate_vulnerabilities(scan_results)
        
        return CrossDatabaseAnalysis(
            package_name=package_name,
            analysis_timestamp=datetime.utcnow(),
            scan_results=scan_results,
            correlations=[],
            unique_vulnerabilities=unique_vulns,
            duplicate_count=0,
            ai_overall_risk_assessment="medium",
            ai_priority_vulnerabilities=[],
            ai_threat_landscape_summary=f"Analysis completed with errors: {error_message}",
            ai_remediation_strategy="Manual review of vulnerabilities recommended",
            ai_confidence_score=0.3,
            database_coverage={source: 0.5 for source in scan_results.keys()},
            data_quality_scores={source: 0.5 for source in scan_results.keys()},
            consensus_confidence=0.5
        )