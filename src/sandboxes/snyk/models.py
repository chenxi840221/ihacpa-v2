"""
SNYK Data Models

Models for SNYK vulnerability database responses and AI analysis.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

from ...core.base_scanner import SeverityLevel


class SNYKSeverity(Enum):
    """SNYK-specific severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SNYKLicense(Enum):
    """SNYK license types"""
    COPYLEFT = "copyleft"
    PERMISSIVE = "permissive"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


@dataclass
class SNYKVulnerability:
    """
    SNYK vulnerability information with AI enhancement capabilities.
    """
    snyk_id: str
    title: str
    description: str
    severity: SNYKSeverity
    cvss_score: Optional[float] = None
    cve_ids: List[str] = None
    cwe_ids: List[str] = None
    affected_versions: List[str] = None
    patched_versions: List[str] = None
    disclosed_date: Optional[datetime] = None
    published_date: Optional[datetime] = None
    modification_date: Optional[datetime] = None
    credit: List[str] = None
    references: List[str] = None
    exploit_maturity: Optional[str] = None
    functions: List[str] = None
    package_manager: str = "pip"
    package_name: str = ""
    
    # AI Enhancement fields
    ai_risk_assessment: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_recommendation: Optional[str] = None
    ai_reasoning: Optional[str] = None
    ai_exploitability: Optional[str] = None
    ai_business_impact: Optional[str] = None
    
    def __post_init__(self):
        if self.cve_ids is None:
            self.cve_ids = []
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.affected_versions is None:
            self.affected_versions = []
        if self.patched_versions is None:
            self.patched_versions = []
        if self.credit is None:
            self.credit = []
        if self.references is None:
            self.references = []
        if self.functions is None:
            self.functions = []
    
    def to_base_vulnerability(self):
        """Convert to base VulnerabilityInfo format"""
        from ...core.base_scanner import VulnerabilityInfo, ConfidenceLevel
        
        # Map SNYK severity to base severity
        severity_map = {
            SNYKSeverity.CRITICAL: SeverityLevel.CRITICAL,
            SNYKSeverity.HIGH: SeverityLevel.HIGH,
            SNYKSeverity.MEDIUM: SeverityLevel.MEDIUM,
            SNYKSeverity.LOW: SeverityLevel.LOW
        }
        
        # Determine confidence level from AI assessment
        confidence = ConfidenceLevel.MEDIUM
        if self.ai_confidence:
            if self.ai_confidence >= 0.9:
                confidence = ConfidenceLevel.VERY_HIGH
            elif self.ai_confidence >= 0.75:
                confidence = ConfidenceLevel.HIGH
            elif self.ai_confidence >= 0.5:
                confidence = ConfidenceLevel.MEDIUM
            elif self.ai_confidence >= 0.25:
                confidence = ConfidenceLevel.LOW
            else:
                confidence = ConfidenceLevel.VERY_LOW
        
        # Create description with AI insights
        description = self.description
        if self.ai_reasoning:
            description += f"\n\nAI Analysis: {self.ai_reasoning}"
        if self.ai_recommendation:
            description += f"\n\nRecommendation: {self.ai_recommendation}"
        
        return VulnerabilityInfo(
            cve_id=self.cve_ids[0] if self.cve_ids else None,
            title=self.title,
            description=description,
            severity=severity_map.get(self.severity, SeverityLevel.UNKNOWN),
            confidence=confidence,
            cvss_score=self.cvss_score,
            affected_versions=self.affected_versions,
            fixed_versions=self.patched_versions,
            published_date=self.published_date,
            references=self.references,
            source_url=f"https://security.snyk.io/vuln/{self.snyk_id}"
        )


@dataclass
class SNYKPackageInfo:
    """
    SNYK package information including license and dependency analysis.
    """
    package_name: str
    package_manager: str = "pip"
    latest_version: Optional[str] = None
    license_type: Optional[SNYKLicense] = None
    license_issues: List[str] = None
    deprecated: bool = False
    malicious: bool = False
    vulnerabilities_count: int = 0
    dependencies_count: int = 0
    
    # AI Enhancement fields
    ai_trust_score: Optional[float] = None
    ai_maintenance_assessment: Optional[str] = None
    ai_security_posture: Optional[str] = None
    ai_recommendation: Optional[str] = None
    
    def __post_init__(self):
        if self.license_issues is None:
            self.license_issues = []


@dataclass
class SNYKAnalysisContext:
    """
    Context for AI analysis of SNYK vulnerabilities.
    """
    package_name: str
    current_version: Optional[str] = None
    vulnerability: Optional[SNYKVulnerability] = None
    package_info: Optional[SNYKPackageInfo] = None
    similar_vulnerabilities: List[SNYKVulnerability] = None
    industry_context: Optional[str] = None
    deployment_context: Optional[str] = None
    
    def __post_init__(self):
        if self.similar_vulnerabilities is None:
            self.similar_vulnerabilities = []
    
    def to_prompt_context(self) -> Dict[str, Any]:
        """Convert to context suitable for AI prompts"""
        context = {
            "package_name": self.package_name,
            "current_version": self.current_version or "Unknown",
            "industry_context": self.industry_context or "General software development",
            "deployment_context": self.deployment_context or "Standard deployment"
        }
        
        if self.vulnerability:
            context.update({
                "vulnerability_title": self.vulnerability.title,
                "vulnerability_description": self.vulnerability.description,
                "snyk_severity": self.vulnerability.severity.value,
                "cvss_score": self.vulnerability.cvss_score,
                "cve_ids": ", ".join(self.vulnerability.cve_ids) if self.vulnerability.cve_ids else "None",
                "exploit_maturity": self.vulnerability.exploit_maturity or "Unknown",
                "affected_versions": ", ".join(self.vulnerability.affected_versions) if self.vulnerability.affected_versions else "Unknown",
                "patched_versions": ", ".join(self.vulnerability.patched_versions) if self.vulnerability.patched_versions else "None available"
            })
        
        if self.package_info:
            context.update({
                "package_license": self.package_info.license_type.value if self.package_info.license_type else "Unknown",
                "package_deprecated": self.package_info.deprecated,
                "package_malicious": self.package_info.malicious,
                "total_vulnerabilities": self.package_info.vulnerabilities_count
            })
        
        if self.similar_vulnerabilities:
            similar_info = []
            for vuln in self.similar_vulnerabilities[:3]:  # Top 3 similar
                similar_info.append({
                    "title": vuln.title,
                    "severity": vuln.severity.value,
                    "cvss": vuln.cvss_score
                })
            context["similar_vulnerabilities"] = similar_info
        
        return context


@dataclass 
class SNYKScanResult:
    """
    Result of SNYK vulnerability scan with AI enhancement.
    """
    package_name: str
    scan_timestamp: datetime
    success: bool
    vulnerabilities: List[SNYKVulnerability] = None
    package_info: Optional[SNYKPackageInfo] = None
    error_message: Optional[str] = None
    ai_enhanced: bool = False
    cache_hit: bool = False
    scan_duration: Optional[float] = None
    
    # AI Enhancement summary
    ai_overall_risk: Optional[str] = None
    ai_priority_recommendations: List[str] = None
    ai_false_positive_likelihood: Optional[float] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.ai_priority_recommendations is None:
            self.ai_priority_recommendations = []
    
    def get_high_priority_vulnerabilities(self) -> List[SNYKVulnerability]:
        """Get vulnerabilities marked as high priority by AI analysis"""
        return [
            vuln for vuln in self.vulnerabilities 
            if vuln.severity in [SNYKSeverity.CRITICAL, SNYKSeverity.HIGH]
            and (vuln.ai_confidence is None or vuln.ai_confidence >= 0.7)
        ]
    
    def get_ai_summary(self) -> Dict[str, Any]:
        """Get AI analysis summary"""
        high_priority = self.get_high_priority_vulnerabilities()
        
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "high_priority_count": len(high_priority),
            "ai_enhanced": self.ai_enhanced,
            "overall_risk": self.ai_overall_risk,
            "priority_recommendations": self.ai_priority_recommendations,
            "false_positive_likelihood": self.ai_false_positive_likelihood,
            "package_trust_score": self.package_info.ai_trust_score if self.package_info else None
        }