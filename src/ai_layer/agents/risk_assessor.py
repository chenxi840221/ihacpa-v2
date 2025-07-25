"""
AI-Powered Risk Assessment Engine

Advanced risk assessment and severity scoring using AI analysis
across multiple vulnerability databases and threat intelligence sources.
"""

import asyncio
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from langchain.prompts import PromptTemplate
from langchain.schema import BaseOutputParser

from ...core.base_scanner import VulnerabilityInfo, SeverityLevel, ConfidenceLevel
from ..chain_factory import get_ai_factory


class RiskCategory(Enum):
    """Risk categories for comprehensive assessment"""
    EXPLOITATION = "exploitation"
    BUSINESS_IMPACT = "business_impact"
    DATA_EXPOSURE = "data_exposure"
    AVAILABILITY = "availability"
    COMPLIANCE = "compliance"
    REPUTATIONAL = "reputational"


class ThreatContext(Enum):
    """Threat context for risk assessment"""
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"
    INTERNAL = "internal"
    PUBLIC_FACING = "public_facing"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"


@dataclass
class RiskFactor:
    """Individual risk factor assessment"""
    category: RiskCategory
    score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    reasoning: str
    evidence: List[str]
    mitigation_difficulty: float  # 0.0 to 1.0 (higher = harder to mitigate)


@dataclass
class ComprehensiveRiskAssessment:
    """
    Comprehensive AI-powered risk assessment for a vulnerability.
    """
    vulnerability: VulnerabilityInfo
    package_name: str
    context: ThreatContext
    
    # Risk analysis
    overall_risk_score: float  # 0.0 to 1.0
    ai_severity_assessment: SeverityLevel
    risk_factors: List[RiskFactor]
    
    # Threat intelligence
    exploit_availability: bool
    exploit_maturity: str  # "proof-of-concept", "functional", "mature"
    active_exploitation: bool
    threat_actor_interest: str  # "low", "medium", "high"
    
    # Business context
    business_impact_score: float  # 0.0 to 1.0
    compliance_risk_score: float  # 0.0 to 1.0
    reputational_risk_score: float  # 0.0 to 1.0
    
    # Mitigation analysis
    mitigation_complexity: str  # "trivial", "moderate", "complex", "very_complex"
    mitigation_cost_estimate: str  # "low", "medium", "high"
    alternative_solutions: List[str]
    
    # Temporal factors
    urgency_level: str  # "immediate", "urgent", "moderate", "low"
    time_to_exploit: str  # "minutes", "hours", "days", "weeks"
    patch_availability: bool
    patch_maturity: str  # "beta", "stable", "well_tested"
    
    # AI insights
    ai_confidence: float  # 0.0 to 1.0
    ai_reasoning: str
    ai_recommendation: str
    similar_vulnerabilities: List[str]  # CVE IDs of similar vulns
    
    def get_priority_score(self) -> float:
        """Calculate priority score for vulnerability triage"""
        # Weighted combination of factors
        priority = (
            self.overall_risk_score * 0.4 +
            self.business_impact_score * 0.2 +
            self.exploit_availability * 0.2 +
            (1.0 if self.active_exploitation else 0.0) * 0.2
        )
        
        # Adjust for urgency
        urgency_multiplier = {
            "immediate": 1.0,
            "urgent": 0.9,
            "moderate": 0.7,
            "low": 0.5
        }.get(self.urgency_level, 0.7)
        
        return min(1.0, priority * urgency_multiplier)
    
    def get_risk_category_scores(self) -> Dict[str, float]:
        """Get risk scores by category"""
        category_scores = {}
        
        for factor in self.risk_factors:
            category = factor.category.value
            if category not in category_scores:
                category_scores[category] = []
            category_scores[category].append(factor.score)
        
        # Average scores by category
        return {
            category: sum(scores) / len(scores)
            for category, scores in category_scores.items()
        }


@dataclass
class PackageRiskProfile:
    """
    Overall risk profile for a package based on all vulnerabilities.
    """
    package_name: str
    assessment_timestamp: datetime
    
    # Individual assessments
    vulnerability_assessments: List[ComprehensiveRiskAssessment]
    
    # Aggregate scores
    overall_package_risk: float  # 0.0 to 1.0
    highest_individual_risk: float
    average_risk_score: float
    
    # Risk distribution
    critical_vulnerabilities: int
    high_risk_vulnerabilities: int
    medium_risk_vulnerabilities: int
    low_risk_vulnerabilities: int
    
    # Business impact
    aggregate_business_impact: float
    aggregate_compliance_risk: float
    aggregate_reputational_risk: float
    
    # Recommendations
    immediate_actions: List[str]
    short_term_actions: List[str]
    long_term_actions: List[str]
    
    # AI insights
    ai_package_assessment: str
    ai_risk_trends: str
    ai_strategic_recommendations: str
    
    def get_top_priority_vulnerabilities(self, limit: int = 5) -> List[ComprehensiveRiskAssessment]:
        """Get top priority vulnerabilities for immediate attention"""
        return sorted(
            self.vulnerability_assessments,
            key=lambda x: x.get_priority_score(),
            reverse=True
        )[:limit]


class RiskAssessmentOutputParser(BaseOutputParser):
    """Parser for AI risk assessment output"""
    
    def parse(self, text: str) -> Dict[str, Any]:
        """Parse risk assessment output"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Fallback parsing
            import re
            
            result = {
                "overall_risk_score": 0.5,
                "severity_assessment": "medium",
                "exploit_availability": False,
                "business_impact": 0.5,
                "urgency_level": "moderate",
                "ai_confidence": 0.5,
                "reasoning": "Risk assessment completed with limited analysis",
                "recommendation": "Review vulnerability and apply appropriate mitigations"
            }
            
            # Extract risk score
            risk_match = re.search(r"risk.*?score.*?:.*?(\d+(?:\.\d+)?)", text, re.IGNORECASE)
            if risk_match:
                score = float(risk_match.group(1))
                result["overall_risk_score"] = score if score <= 1.0 else score / 100.0
            
            # Extract severity
            severity_match = re.search(r"severity.*?:.*?(critical|high|medium|low)", text, re.IGNORECASE)
            if severity_match:
                result["severity_assessment"] = severity_match.group(1).lower()
            
            # Check for exploit mentions
            if any(term in text.lower() for term in ["exploit", "poc", "proof of concept"]):
                result["exploit_availability"] = True
            
            return result


class AIRiskAssessor:
    """
    AI-powered risk assessment engine for comprehensive vulnerability analysis.
    """
    
    def __init__(self, ai_factory=None):
        self.ai_factory = ai_factory or get_ai_factory()
        self.output_parser = RiskAssessmentOutputParser()
        
        # Risk assessment prompt template
        self.risk_assessment_prompt = PromptTemplate(
            input_variables=[
                "vulnerability_details", "package_context", "threat_context",
                "exploit_intelligence", "business_context", "historical_data"
            ],
            template="""
            You are a senior cybersecurity risk analyst performing comprehensive vulnerability risk assessment.
            
            Vulnerability Details:
            {vulnerability_details}
            
            Package Context:
            {package_context}
            
            Threat Context:
            {threat_context}
            
            Exploit Intelligence:
            {exploit_intelligence}
            
            Business Context:
            {business_context}
            
            Historical Data:
            {historical_data}
            
            Provide a comprehensive risk assessment including:
            
            1. OVERALL_RISK_SCORE (0.0-1.0): Comprehensive risk score
            2. SEVERITY_ASSESSMENT: AI-refined severity (critical/high/medium/low)
            3. RISK_FACTORS: Key risk factors by category
            4. EXPLOIT_AVAILABILITY: Is there a known exploit? (true/false)
            5. EXPLOIT_MATURITY: Exploit sophistication level
            6. ACTIVE_EXPLOITATION: Evidence of active exploitation (true/false)
            7. BUSINESS_IMPACT: Business impact score (0.0-1.0)
            8. COMPLIANCE_RISK: Compliance/regulatory risk (0.0-1.0)
            9. REPUTATIONAL_RISK: Reputational damage risk (0.0-1.0)
            10. MITIGATION_COMPLEXITY: Difficulty to fix (trivial/moderate/complex/very_complex)
            11. URGENCY_LEVEL: Response urgency (immediate/urgent/moderate/low)
            12. TIME_TO_EXPLOIT: Expected time for exploitation
            13. AI_CONFIDENCE: Assessment confidence (0.0-1.0)
            14. REASONING: Detailed risk analysis reasoning
            15. RECOMMENDATION: Specific actionable recommendations
            
            Consider:
            - Technical exploitability and attack vectors
            - Business context and asset criticality
            - Threat landscape and actor capabilities
            - Regulatory and compliance implications
            - Historical exploitation patterns
            - Mitigation complexity and cost
            - Time sensitivity and urgency factors
            
            Format as JSON with the specified keys.
            """.strip()
        )
    
    async def assess_vulnerability_risk(
        self,
        vulnerability: VulnerabilityInfo,
        package_name: str,
        context: ThreatContext = ThreatContext.PRODUCTION,
        business_context: Optional[Dict[str, Any]] = None
    ) -> ComprehensiveRiskAssessment:
        """
        Perform comprehensive risk assessment for a single vulnerability.
        
        Args:
            vulnerability: Vulnerability to assess
            package_name: Name of the affected package
            context: Deployment/threat context
            business_context: Business context information
            
        Returns:
            Comprehensive risk assessment
        """
        try:
            # Prepare context for AI analysis
            vuln_details = self._prepare_vulnerability_details(vulnerability)
            package_ctx = self._prepare_package_context(package_name, context)
            threat_ctx = self._prepare_threat_context(context, business_context)
            exploit_intel = await self._gather_exploit_intelligence(vulnerability)
            business_ctx = self._prepare_business_context(business_context or {})
            historical_data = await self._gather_historical_data(vulnerability)
            
            # Get AI assessment
            ai_assessment = await self._get_ai_risk_assessment({
                "vulnerability_details": vuln_details,
                "package_context": package_ctx,
                "threat_context": threat_ctx,
                "exploit_intelligence": exploit_intel,
                "business_context": business_ctx,
                "historical_data": historical_data
            })
            
            # Parse risk factors
            risk_factors = self._parse_risk_factors(ai_assessment)
            
            # Create comprehensive assessment
            assessment = ComprehensiveRiskAssessment(
                vulnerability=vulnerability,
                package_name=package_name,
                context=context,
                overall_risk_score=ai_assessment.get("overall_risk_score", 0.5),
                ai_severity_assessment=self._parse_severity(ai_assessment.get("severity_assessment", "medium")),
                risk_factors=risk_factors,
                exploit_availability=ai_assessment.get("exploit_availability", False),
                exploit_maturity=ai_assessment.get("exploit_maturity", "unknown"),
                active_exploitation=ai_assessment.get("active_exploitation", False),
                threat_actor_interest=ai_assessment.get("threat_actor_interest", "low"),
                business_impact_score=ai_assessment.get("business_impact", 0.5),
                compliance_risk_score=ai_assessment.get("compliance_risk", 0.3),
                reputational_risk_score=ai_assessment.get("reputational_risk", 0.3),
                mitigation_complexity=ai_assessment.get("mitigation_complexity", "moderate"),
                mitigation_cost_estimate=self._estimate_mitigation_cost(ai_assessment),
                alternative_solutions=ai_assessment.get("alternative_solutions", []),
                urgency_level=ai_assessment.get("urgency_level", "moderate"),
                time_to_exploit=ai_assessment.get("time_to_exploit", "days"),
                patch_availability=ai_assessment.get("patch_availability", False),
                patch_maturity=ai_assessment.get("patch_maturity", "unknown"),
                ai_confidence=ai_assessment.get("ai_confidence", 0.5),
                ai_reasoning=ai_assessment.get("reasoning", ""),
                ai_recommendation=ai_assessment.get("recommendation", ""),
                similar_vulnerabilities=ai_assessment.get("similar_vulnerabilities", [])
            )
            
            return assessment
            
        except Exception as e:
            print(f"Risk assessment failed for {vulnerability.cve_id or vulnerability.title}: {e}")
            return self._create_fallback_assessment(vulnerability, package_name, context)
    
    async def assess_package_risk_profile(
        self,
        vulnerabilities: List[VulnerabilityInfo],
        package_name: str,
        context: ThreatContext = ThreatContext.PRODUCTION,
        business_context: Optional[Dict[str, Any]] = None
    ) -> PackageRiskProfile:
        """
        Assess overall risk profile for a package with multiple vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerabilities in the package
            package_name: Name of the package
            context: Deployment/threat context
            business_context: Business context information
            
        Returns:
            Package risk profile
        """
        try:
            # Assess individual vulnerabilities
            individual_assessments = []
            for vuln in vulnerabilities:
                assessment = await self.assess_vulnerability_risk(
                    vuln, package_name, context, business_context
                )
                individual_assessments.append(assessment)
            
            # Calculate aggregate metrics
            risk_scores = [a.overall_risk_score for a in individual_assessments]
            overall_risk = max(risk_scores) if risk_scores else 0.0
            avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
            
            # Categorize vulnerabilities
            critical_count = sum(1 for a in individual_assessments if a.overall_risk_score >= 0.9)
            high_count = sum(1 for a in individual_assessments if 0.7 <= a.overall_risk_score < 0.9)
            medium_count = sum(1 for a in individual_assessments if 0.4 <= a.overall_risk_score < 0.7)
            low_count = sum(1 for a in individual_assessments if a.overall_risk_score < 0.4)
            
            # Calculate business impact aggregates
            business_impacts = [a.business_impact_score for a in individual_assessments]
            compliance_risks = [a.compliance_risk_score for a in individual_assessments]
            reputational_risks = [a.reputational_risk_score for a in individual_assessments]
            
            # Generate recommendations
            recommendations = await self._generate_package_recommendations(individual_assessments)
            
            # Get AI package assessment
            ai_insights = await self._get_ai_package_insights(individual_assessments, package_name)
            
            profile = PackageRiskProfile(
                package_name=package_name,
                assessment_timestamp=datetime.utcnow(),
                vulnerability_assessments=individual_assessments,
                overall_package_risk=overall_risk,
                highest_individual_risk=max(risk_scores) if risk_scores else 0.0,
                average_risk_score=avg_risk,
                critical_vulnerabilities=critical_count,
                high_risk_vulnerabilities=high_count,
                medium_risk_vulnerabilities=medium_count,
                low_risk_vulnerabilities=low_count,
                aggregate_business_impact=max(business_impacts) if business_impacts else 0.0,
                aggregate_compliance_risk=max(compliance_risks) if compliance_risks else 0.0,
                aggregate_reputational_risk=max(reputational_risks) if reputational_risks else 0.0,
                immediate_actions=recommendations.get("immediate", []),
                short_term_actions=recommendations.get("short_term", []),
                long_term_actions=recommendations.get("long_term", []),
                ai_package_assessment=ai_insights.get("package_assessment", ""),
                ai_risk_trends=ai_insights.get("risk_trends", ""),
                ai_strategic_recommendations=ai_insights.get("strategic_recommendations", "")
            )
            
            return profile
            
        except Exception as e:
            print(f"Package risk assessment failed for {package_name}: {e}")
            return self._create_fallback_package_profile(vulnerabilities, package_name)
    
    def _prepare_vulnerability_details(self, vulnerability: VulnerabilityInfo) -> str:
        """Prepare vulnerability details for AI analysis"""
        details = [
            f"Title: {vulnerability.title}",
            f"CVE ID: {vulnerability.cve_id or 'N/A'}",
            f"Severity: {vulnerability.severity.value}",
            f"Confidence: {vulnerability.confidence.value if hasattr(vulnerability.confidence, 'value') else 'N/A'}",
            f"CVSS Score: {vulnerability.cvss_score or 'N/A'}",
            f"Description: {vulnerability.description[:500]}..." if len(vulnerability.description) > 500 else f"Description: {vulnerability.description}"
        ]
        
        if vulnerability.affected_versions:
            details.append(f"Affected Versions: {', '.join(vulnerability.affected_versions)}")
        
        if vulnerability.fixed_versions:
            details.append(f"Fixed Versions: {', '.join(vulnerability.fixed_versions)}")
        
        if vulnerability.published_date:
            details.append(f"Published: {vulnerability.published_date.isoformat()}")
        
        if vulnerability.references:
            details.append(f"References: {len(vulnerability.references)} URLs available")
        
        return "\n".join(details)
    
    def _prepare_package_context(self, package_name: str, context: ThreatContext) -> str:
        """Prepare package context information"""
        return f"""
        Package Name: {package_name}
        Deployment Context: {context.value}
        Package Type: Python library/framework
        Ecosystem: PyPI
        """
    
    def _prepare_threat_context(self, context: ThreatContext, business_context: Optional[Dict[str, Any]]) -> str:
        """Prepare threat context information"""
        lines = [f"Deployment Context: {context.value}"]
        
        if business_context:
            if "industry" in business_context:
                lines.append(f"Industry: {business_context['industry']}")
            if "asset_criticality" in business_context:
                lines.append(f"Asset Criticality: {business_context['asset_criticality']}")
            if "data_sensitivity" in business_context:
                lines.append(f"Data Sensitivity: {business_context['data_sensitivity']}")
            if "regulatory_requirements" in business_context:
                lines.append(f"Regulatory Requirements: {', '.join(business_context['regulatory_requirements'])}")
        
        return "\n".join(lines)
    
    async def _gather_exploit_intelligence(self, vulnerability: VulnerabilityInfo) -> str:
        """Gather exploit intelligence for the vulnerability"""
        intel_lines = []
        
        # Check for exploit indicators in description
        description_lower = vulnerability.description.lower()
        
        if any(term in description_lower for term in ["exploit", "poc", "proof of concept"]):
            intel_lines.append("- Exploit mentions found in vulnerability description")
        
        if any(term in description_lower for term in ["remote", "unauthenticated"]):
            intel_lines.append("- Remote/unauthenticated exploitation possible")
        
        if any(term in description_lower for term in ["code execution", "rce", "command injection"]):
            intel_lines.append("- Code execution capabilities indicated")
        
        # Check references for exploit repositories
        for ref in vulnerability.references:
            if any(domain in ref for domain in ["exploit-db.com", "github.com", "gitlab.com"]):
                intel_lines.append(f"- Potential exploit reference: {ref}")
        
        if not intel_lines:
            intel_lines.append("- No explicit exploit intelligence available")
        
        return "\n".join(intel_lines)
    
    def _prepare_business_context(self, business_context: Dict[str, Any]) -> str:
        """Prepare business context for analysis"""
        if not business_context:
            return "Standard business context - no specific requirements provided"
        
        lines = []
        for key, value in business_context.items():
            if isinstance(value, list):
                lines.append(f"{key.replace('_', ' ').title()}: {', '.join(value)}")
            else:
                lines.append(f"{key.replace('_', ' ').title()}: {value}")
        
        return "\n".join(lines)
    
    async def _gather_historical_data(self, vulnerability: VulnerabilityInfo) -> str:
        """Gather historical exploitation data"""
        historical = []
        
        # Check vulnerability age
        if vulnerability.published_date:
            age_days = (datetime.utcnow() - vulnerability.published_date).days
            if age_days > 365:
                historical.append("- Vulnerability is over 1 year old")
            elif age_days > 90:
                historical.append("- Vulnerability is 3+ months old")
            else:
                historical.append("- Recently disclosed vulnerability")
        
        # Check CVSS score trends
        if vulnerability.cvss_score:
            if vulnerability.cvss_score >= 9.0:
                historical.append("- Critical CVSS score indicates high severity")
            elif vulnerability.cvss_score >= 7.0:
                historical.append("- High CVSS score indicates significant risk")
        
        if not historical:
            historical.append("- Limited historical data available")
        
        return "\n".join(historical)
    
    async def _get_ai_risk_assessment(self, prompt_vars: Dict[str, str]) -> Dict[str, Any]:
        """Get AI risk assessment"""
        try:
            llm = self.ai_factory.get_chat_llm()
            chain = self.risk_assessment_prompt | llm | self.output_parser
            
            result = await self._run_chain_async(chain, prompt_vars)
            return result
            
        except Exception as e:
            print(f"AI risk assessment failed: {e}")
            return {
                "overall_risk_score": 0.5,
                "severity_assessment": "medium",
                "reasoning": f"Risk assessment failed: {str(e)}",
                "recommendation": "Manual assessment required"
            }
    
    def _parse_risk_factors(self, ai_assessment: Dict[str, Any]) -> List[RiskFactor]:
        """Parse risk factors from AI assessment"""
        factors = []
        
        # Create risk factors based on AI assessment
        if "risk_factors" in ai_assessment:
            for category, data in ai_assessment["risk_factors"].items():
                if isinstance(data, dict):
                    factor = RiskFactor(
                        category=RiskCategory(category.lower()),
                        score=data.get("score", 0.5),
                        confidence=data.get("confidence", 0.5),
                        reasoning=data.get("reasoning", ""),
                        evidence=data.get("evidence", []),
                        mitigation_difficulty=data.get("mitigation_difficulty", 0.5)
                    )
                    factors.append(factor)
        
        # Create default factors if none provided
        if not factors:
            factors.append(RiskFactor(
                category=RiskCategory.EXPLOITATION,
                score=ai_assessment.get("overall_risk_score", 0.5),
                confidence=ai_assessment.get("ai_confidence", 0.5),
                reasoning=ai_assessment.get("reasoning", "Default risk assessment"),
                evidence=[],
                mitigation_difficulty=0.5
            ))
        
        return factors
    
    def _parse_severity(self, severity_str: str) -> SeverityLevel:
        """Parse severity string to SeverityLevel"""
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO
        }
        return severity_map.get(severity_str.lower(), SeverityLevel.MEDIUM)
    
    def _estimate_mitigation_cost(self, ai_assessment: Dict[str, Any]) -> str:
        """Estimate mitigation cost based on complexity"""
        complexity = ai_assessment.get("mitigation_complexity", "moderate")
        
        cost_map = {
            "trivial": "low",
            "moderate": "medium",
            "complex": "high",
            "very_complex": "high"
        }
        
        return cost_map.get(complexity, "medium")
    
    async def _generate_package_recommendations(
        self,
        assessments: List[ComprehensiveRiskAssessment]
    ) -> Dict[str, List[str]]:
        """Generate package-level recommendations"""
        immediate = []
        short_term = []
        long_term = []
        
        # Analyze high-priority vulnerabilities
        critical_vulns = [a for a in assessments if a.overall_risk_score >= 0.9]
        high_vulns = [a for a in assessments if 0.7 <= a.overall_risk_score < 0.9]
        
        if critical_vulns:
            immediate.append("Address critical vulnerabilities immediately")
            for vuln in critical_vulns[:3]:  # Top 3
                if vuln.patch_availability:
                    immediate.append(f"Update package to fix {vuln.vulnerability.cve_id or vuln.vulnerability.title}")
                else:
                    immediate.append(f"Implement workarounds for {vuln.vulnerability.cve_id or vuln.vulnerability.title}")
        
        if high_vulns:
            short_term.append("Plan updates for high-risk vulnerabilities")
            short_term.append("Implement additional monitoring for high-risk components")
        
        long_term.append("Establish regular vulnerability scanning schedule")
        long_term.append("Review and update security policies")
        
        return {
            "immediate": immediate,
            "short_term": short_term,
            "long_term": long_term
        }
    
    async def _get_ai_package_insights(
        self,
        assessments: List[ComprehensiveRiskAssessment],
        package_name: str
    ) -> Dict[str, str]:
        """Get AI insights for package-level assessment"""
        try:
            # Simplified package insights
            risk_scores = [a.overall_risk_score for a in assessments]
            avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
            
            package_assessment = f"Package {package_name} has an average risk score of {avg_risk:.2f}"
            
            if avg_risk >= 0.8:
                package_assessment += " indicating high overall risk requiring immediate attention."
            elif avg_risk >= 0.6:
                package_assessment += " indicating moderate risk requiring planned remediation."
            else:
                package_assessment += " indicating manageable risk levels."
            
            return {
                "package_assessment": package_assessment,
                "risk_trends": "Risk assessment based on current vulnerability data",
                "strategic_recommendations": "Implement systematic vulnerability management processes"
            }
            
        except Exception:
            return {
                "package_assessment": f"Risk assessment completed for {package_name}",
                "risk_trends": "Monitor for new vulnerabilities",
                "strategic_recommendations": "Maintain regular security updates"
            }
    
    def _create_fallback_assessment(
        self,
        vulnerability: VulnerabilityInfo,
        package_name: str,
        context: ThreatContext
    ) -> ComprehensiveRiskAssessment:
        """Create fallback assessment when AI analysis fails"""
        # Map base severity to risk score
        severity_scores = {
            SeverityLevel.CRITICAL: 0.95,
            SeverityLevel.HIGH: 0.8,
            SeverityLevel.MEDIUM: 0.5,
            SeverityLevel.LOW: 0.2,
            SeverityLevel.INFO: 0.1,
            SeverityLevel.UNKNOWN: 0.4
        }
        
        risk_score = severity_scores.get(vulnerability.severity, 0.5)
        
        return ComprehensiveRiskAssessment(
            vulnerability=vulnerability,
            package_name=package_name,
            context=context,
            overall_risk_score=risk_score,
            ai_severity_assessment=vulnerability.severity,
            risk_factors=[],
            exploit_availability=False,
            exploit_maturity="unknown",
            active_exploitation=False,
            threat_actor_interest="low",
            business_impact_score=risk_score * 0.8,
            compliance_risk_score=0.3,
            reputational_risk_score=0.3,
            mitigation_complexity="moderate",
            mitigation_cost_estimate="medium",
            alternative_solutions=[],
            urgency_level="moderate",
            time_to_exploit="days",
            patch_availability=bool(vulnerability.fixed_versions),
            patch_maturity="unknown",
            ai_confidence=0.3,
            ai_reasoning="Fallback assessment due to AI analysis failure",
            ai_recommendation="Manual review recommended",
            similar_vulnerabilities=[]
        )
    
    def _create_fallback_package_profile(
        self,
        vulnerabilities: List[VulnerabilityInfo],
        package_name: str
    ) -> PackageRiskProfile:
        """Create fallback package profile"""
        # Create basic assessments
        assessments = []
        for vuln in vulnerabilities:
            assessment = self._create_fallback_assessment(vuln, package_name, ThreatContext.PRODUCTION)
            assessments.append(assessment)
        
        risk_scores = [a.overall_risk_score for a in assessments]
        
        return PackageRiskProfile(
            package_name=package_name,
            assessment_timestamp=datetime.utcnow(),
            vulnerability_assessments=assessments,
            overall_package_risk=max(risk_scores) if risk_scores else 0.0,
            highest_individual_risk=max(risk_scores) if risk_scores else 0.0,
            average_risk_score=sum(risk_scores) / len(risk_scores) if risk_scores else 0.0,
            critical_vulnerabilities=sum(1 for a in assessments if a.overall_risk_score >= 0.9),
            high_risk_vulnerabilities=sum(1 for a in assessments if 0.7 <= a.overall_risk_score < 0.9),
            medium_risk_vulnerabilities=sum(1 for a in assessments if 0.4 <= a.overall_risk_score < 0.7),
            low_risk_vulnerabilities=sum(1 for a in assessments if a.overall_risk_score < 0.4),
            aggregate_business_impact=0.5,
            aggregate_compliance_risk=0.3,
            aggregate_reputational_risk=0.3,
            immediate_actions=["Review vulnerability findings"],
            short_term_actions=["Plan remediation activities"],
            long_term_actions=["Implement security monitoring"],
            ai_package_assessment="Basic risk assessment completed",
            ai_risk_trends="Monitor for updates",
            ai_strategic_recommendations="Implement systematic vulnerability management"
        )
    
    async def _run_chain_async(self, chain, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Run chain asynchronously"""
        try:
            result = chain.invoke(inputs)
            return result
        except Exception as e:
            print(f"Chain execution failed: {e}")
            return {
                "overall_risk_score": 0.5,
                "severity_assessment": "medium",
                "reasoning": f"Analysis failed: {str(e)}",
                "recommendation": "Manual assessment required"
            }