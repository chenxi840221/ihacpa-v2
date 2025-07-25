"""
MITRE CVE Database Models

Models for MITRE CVE database responses and AI-enhanced analysis.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

from ...core.base_scanner import SeverityLevel


class MITREStatus(Enum):
    """MITRE CVE status values"""
    PUBLISHED = "Published"
    RESERVED = "Reserved"
    REJECTED = "Rejected"
    DISPUTED = "Disputed"


class MITREAssignerType(Enum):
    """MITRE CVE assigner types"""
    CNA = "CNA"  # CVE Numbering Authority
    ADP = "ADP"  # Authorized Data Publisher
    MITRE = "MITRE"


@dataclass
class MITREReference:
    """MITRE CVE reference information"""
    url: str
    name: Optional[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class MITREMetrics:
    """MITRE CVE metrics (CVSS etc.)"""
    cvss_version: Optional[str] = None
    cvss_vector: Optional[str] = None
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None


@dataclass
class MITREWeakness:
    """MITRE CWE (Common Weakness Enumeration) information"""
    cwe_id: str
    description: str
    type: Optional[str] = None


@dataclass
class MITREConfiguration:
    """MITRE CVE configuration/affected products"""
    operator: str = "OR"  # OR, AND
    nodes: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.nodes is None:
            self.nodes = []


@dataclass
class MITREVulnerability:
    """
    MITRE CVE vulnerability with AI enhancement capabilities.
    """
    cve_id: str
    description: str
    status: MITREStatus = MITREStatus.PUBLISHED
    assigner: Optional[str] = None
    assigner_type: Optional[MITREAssignerType] = None
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    
    # Technical details
    references: List[MITREReference] = None
    metrics: Optional[MITREMetrics] = None
    weaknesses: List[MITREWeakness] = None
    configurations: List[MITREConfiguration] = None
    
    # Vendor/product information
    affected_vendors: List[str] = None
    affected_products: List[str] = None
    affected_versions: List[str] = None
    
    # AI Enhancement fields
    ai_severity_assessment: Optional[SeverityLevel] = None
    ai_confidence: Optional[float] = None
    ai_exploitability: Optional[str] = None
    ai_relevance_score: Optional[float] = None
    ai_recommendation: Optional[str] = None
    ai_reasoning: Optional[str] = None
    ai_related_cves: List[str] = None
    ai_attack_vectors: List[str] = None
    ai_business_impact: Optional[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.weaknesses is None:
            self.weaknesses = []
        if self.configurations is None:
            self.configurations = []
        if self.affected_vendors is None:
            self.affected_vendors = []
        if self.affected_products is None:
            self.affected_products = []
        if self.affected_versions is None:
            self.affected_versions = []
        if self.ai_related_cves is None:
            self.ai_related_cves = []
        if self.ai_attack_vectors is None:
            self.ai_attack_vectors = []
    
    def to_base_vulnerability(self):
        """Convert to base VulnerabilityInfo format"""
        from ...core.base_scanner import VulnerabilityInfo, ConfidenceLevel
        
        # Determine severity from AI assessment or CVSS
        severity = self.ai_severity_assessment or SeverityLevel.UNKNOWN
        if not self.ai_severity_assessment and self.metrics and self.metrics.base_score:
            if self.metrics.base_score >= 9.0:
                severity = SeverityLevel.CRITICAL
            elif self.metrics.base_score >= 7.0:
                severity = SeverityLevel.HIGH
            elif self.metrics.base_score >= 4.0:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW
        
        # Determine confidence level
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
        
        # Create enhanced description
        description = self.description
        if self.ai_reasoning:
            description += f"\n\nAI Analysis: {self.ai_reasoning}"
        if self.ai_recommendation:
            description += f"\n\nRecommendation: {self.ai_recommendation}"
        if self.weaknesses:
            cwe_list = ", ".join([w.cwe_id for w in self.weaknesses])
            description += f"\n\nRelated Weaknesses: {cwe_list}"
        
        # Extract reference URLs
        ref_urls = [ref.url for ref in self.references]
        
        return VulnerabilityInfo(
            cve_id=self.cve_id,
            title=f"MITRE CVE: {self.cve_id}",
            description=description,
            severity=severity,
            confidence=confidence,
            cvss_score=self.metrics.base_score if self.metrics else None,
            affected_versions=self.affected_versions,
            fixed_versions=[],  # MITRE doesn't typically have fix info
            published_date=self.published_date,
            references=ref_urls,
            source_url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={self.cve_id}"
        )


@dataclass
class MITRECVEInfo:
    """
    Comprehensive MITRE CVE information with search context.
    """
    search_query: str
    total_results: int
    page_number: int = 1
    results_per_page: int = 20
    vulnerabilities: List[MITREVulnerability] = None
    
    # AI Enhancement for search results
    ai_search_relevance: Optional[float] = None
    ai_priority_ranking: List[str] = None  # CVE IDs ranked by AI
    ai_search_summary: Optional[str] = None
    ai_recommended_actions: List[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.ai_priority_ranking is None:
            self.ai_priority_ranking = []
        if self.ai_recommended_actions is None:
            self.ai_recommended_actions = []
    
    def get_high_priority_cves(self) -> List[MITREVulnerability]:
        """Get CVEs marked as high priority by AI analysis"""
        high_priority = []
        
        for vuln in self.vulnerabilities:
            # Check AI assessment
            if vuln.ai_severity_assessment in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                high_priority.append(vuln)
                continue
            
            # Check CVSS score
            if vuln.metrics and vuln.metrics.base_score and vuln.metrics.base_score >= 7.0:
                high_priority.append(vuln)
                continue
            
            # Check AI relevance score
            if vuln.ai_relevance_score and vuln.ai_relevance_score >= 0.8:
                high_priority.append(vuln)
        
        return high_priority
    
    def get_ai_insights(self) -> Dict[str, Any]:
        """Get comprehensive AI insights for the search results"""
        return {
            "total_cves": len(self.vulnerabilities),
            "high_priority_count": len(self.get_high_priority_cves()),
            "search_relevance": self.ai_search_relevance,
            "priority_ranking": self.ai_priority_ranking,
            "search_summary": self.ai_search_summary,
            "recommended_actions": self.ai_recommended_actions,
            "avg_confidence": sum(v.ai_confidence for v in self.vulnerabilities if v.ai_confidence) / max(1, len([v for v in self.vulnerabilities if v.ai_confidence])),
            "cwe_distribution": self._get_cwe_distribution(),
            "vendor_distribution": self._get_vendor_distribution()
        }
    
    def _get_cwe_distribution(self) -> Dict[str, int]:
        """Get distribution of CWE types"""
        cwe_counts = {}
        for vuln in self.vulnerabilities:
            for weakness in vuln.weaknesses:
                cwe_counts[weakness.cwe_id] = cwe_counts.get(weakness.cwe_id, 0) + 1
        return cwe_counts
    
    def _get_vendor_distribution(self) -> Dict[str, int]:
        """Get distribution of affected vendors"""
        vendor_counts = {}
        for vuln in self.vulnerabilities:
            for vendor in vuln.affected_vendors:
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
        return vendor_counts


@dataclass
class MITRESearchContext:
    """
    Context for AI-enhanced MITRE CVE searches.
    """
    package_name: str
    search_terms: List[str] = None
    date_range: Optional[tuple] = None  # (start_date, end_date)
    severity_filter: Optional[SeverityLevel] = None
    max_results: int = 100
    
    # AI search enhancement
    ai_query_expansion: bool = True
    ai_relevance_filtering: bool = True
    ai_priority_scoring: bool = True
    
    def __post_init__(self):
        if self.search_terms is None:
            self.search_terms = []
    
    def get_search_query(self) -> str:
        """Generate search query string"""
        terms = [self.package_name] + self.search_terms
        return " OR ".join(f'"{term}"' for term in terms if term)
    
    def to_prompt_context(self) -> Dict[str, Any]:
        """Convert to context suitable for AI prompts"""
        return {
            "package_name": self.package_name,
            "search_terms": self.search_terms,
            "date_range": f"{self.date_range[0]} to {self.date_range[1]}" if self.date_range else "All time",
            "severity_filter": self.severity_filter.value if self.severity_filter else "All severities",
            "max_results": self.max_results,
            "query_expansion_enabled": self.ai_query_expansion,
            "relevance_filtering_enabled": self.ai_relevance_filtering
        }