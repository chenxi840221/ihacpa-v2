"""
GitHub Security Advisory Database Models

Models for GitHub Security Advisory database responses and AI analysis.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

from ...core.base_scanner import SeverityLevel


class GitHubSeverity(Enum):
    """GitHub Advisory severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GitHubAdvisoryType(Enum):
    """GitHub Advisory types"""
    REVIEWED = "reviewed"
    MALWARE = "malware"
    UNREVIEWED = "unreviewed"


class GitHubEcosystem(Enum):
    """GitHub supported ecosystems"""
    PYPI = "pip"
    NPM = "npm"
    MAVEN = "maven"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"
    GO = "go"
    RUST = "rust"
    COMPOSER = "composer"


@dataclass
class GitHubAdvisoryIdentifier:
    """GitHub Advisory identifier information"""
    type: str  # GHSA, CVE, etc.
    value: str


@dataclass
class GitHubAdvisoryReference:
    """GitHub Advisory reference information"""
    url: str
    type: Optional[str] = None  # ADVISORY, ARTICLE, REPORT, etc.


@dataclass
class GitHubVulnerableVersionRange:
    """GitHub vulnerable version range"""
    events: List[Dict[str, str]] = None  # introduced, fixed, last_affected, etc.
    
    def __post_init__(self):
        if self.events is None:
            self.events = []
    
    def get_introduced_version(self) -> Optional[str]:
        """Get the version where vulnerability was introduced"""
        for event in self.events:
            if event.get("type") == "introduced":
                return event.get("version")
        return None
    
    def get_fixed_version(self) -> Optional[str]:
        """Get the version where vulnerability was fixed"""
        for event in self.events:
            if event.get("type") == "fixed":
                return event.get("version")
        return None
    
    def get_last_affected_version(self) -> Optional[str]:
        """Get the last affected version"""
        for event in self.events:
            if event.get("type") == "last_affected":
                return event.get("version")
        return None


@dataclass
class GitHubVulnerablePackage:
    """GitHub vulnerable package information"""
    ecosystem: GitHubEcosystem
    name: str
    vulnerable_version_range: GitHubVulnerableVersionRange
    patched_versions: List[str] = None
    unaffected_versions: List[str] = None
    database_specific: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.patched_versions is None:
            self.patched_versions = []
        if self.unaffected_versions is None:
            self.unaffected_versions = []
        if self.database_specific is None:
            self.database_specific = {}


@dataclass
class GitHubAdvisory:
    """
    GitHub Security Advisory with AI enhancement capabilities.
    """
    ghsa_id: str
    summary: str
    description: str
    severity: GitHubSeverity
    type: GitHubAdvisoryType = GitHubAdvisoryType.REVIEWED
    
    # Metadata
    published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    withdrawn_at: Optional[datetime] = None
    
    # Identifiers and references
    identifiers: List[GitHubAdvisoryIdentifier] = None
    references: List[GitHubAdvisoryReference] = None
    
    # Vulnerability details
    aliases: List[str] = None  # CVE IDs, etc.
    related: List[str] = None  # Related advisories
    
    # Package information
    affected_packages: List[GitHubVulnerablePackage] = None
    
    # Credits
    credits: List[Dict[str, str]] = None
    
    # AI Enhancement fields
    ai_risk_assessment: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_exploitability: Optional[str] = None
    ai_relevance_score: Optional[float] = None
    ai_recommendation: Optional[str] = None
    ai_reasoning: Optional[str] = None
    ai_impact_analysis: Optional[str] = None
    ai_remediation_priority: Optional[str] = None
    
    def __post_init__(self):
        if self.identifiers is None:
            self.identifiers = []
        if self.references is None:
            self.references = []
        if self.aliases is None:
            self.aliases = []
        if self.related is None:
            self.related = []
        if self.affected_packages is None:
            self.affected_packages = []
        if self.credits is None:
            self.credits = []
    
    def get_cve_ids(self) -> List[str]:
        """Get associated CVE IDs"""
        cve_ids = []
        
        # From identifiers
        for identifier in self.identifiers:
            if identifier.type == "CVE":
                cve_ids.append(identifier.value)
        
        # From aliases
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                cve_ids.append(alias)
        
        return list(set(cve_ids))
    
    def get_affected_package_names(self) -> List[str]:
        """Get names of affected packages"""
        return [pkg.name for pkg in self.affected_packages]
    
    def is_package_affected(self, package_name: str, version: Optional[str] = None) -> bool:
        """Check if a specific package and version is affected"""
        for pkg in self.affected_packages:
            if pkg.name.lower() == package_name.lower():
                if not version:
                    return True
                
                # Check version ranges (simplified)
                if pkg.vulnerable_version_range:
                    introduced = pkg.vulnerable_version_range.get_introduced_version()
                    fixed = pkg.vulnerable_version_range.get_fixed_version()
                    
                    # If no specific version constraints, assume affected
                    if not introduced and not fixed:
                        return True
                    
                    # Simple version comparison (would need proper semver in production)
                    if introduced and version and version >= introduced:
                        if not fixed or version < fixed:
                            return True
                
                return True
        
        return False
    
    def get_fixed_versions(self, package_name: str) -> List[str]:
        """Get fixed versions for a specific package"""
        for pkg in self.affected_packages:
            if pkg.name.lower() == package_name.lower():
                fixed_versions = []
                
                # From patched versions
                fixed_versions.extend(pkg.patched_versions)
                
                # From version range
                if pkg.vulnerable_version_range:
                    fixed = pkg.vulnerable_version_range.get_fixed_version()
                    if fixed:
                        fixed_versions.append(fixed)
                
                return list(set(fixed_versions))
        
        return []
    
    def to_base_vulnerability(self):
        """Convert to base VulnerabilityInfo format"""
        from ...core.base_scanner import VulnerabilityInfo, ConfidenceLevel
        
        # Map GitHub severity to base severity
        severity_map = {
            GitHubSeverity.CRITICAL: SeverityLevel.CRITICAL,
            GitHubSeverity.HIGH: SeverityLevel.HIGH,
            GitHubSeverity.MEDIUM: SeverityLevel.MEDIUM,
            GitHubSeverity.LOW: SeverityLevel.LOW
        }
        
        # Determine confidence level
        confidence = ConfidenceLevel.HIGH  # GitHub advisories are generally high quality
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
        description = f"{self.summary}\n\n{self.description}"
        if self.ai_reasoning:
            description += f"\n\nAI Analysis: {self.ai_reasoning}"
        if self.ai_recommendation:
            description += f"\n\nRecommendation: {self.ai_recommendation}"
        
        # Extract affected versions
        affected_versions = []
        fixed_versions = []
        for pkg in self.affected_packages:
            if pkg.vulnerable_version_range:
                introduced = pkg.vulnerable_version_range.get_introduced_version()
                if introduced:
                    affected_versions.append(f">= {introduced}")
                
                fixed = pkg.vulnerable_version_range.get_fixed_version()
                if fixed:
                    fixed_versions.append(fixed)
            
            fixed_versions.extend(pkg.patched_versions)
        
        # Extract reference URLs
        ref_urls = [ref.url for ref in self.references]
        
        return VulnerabilityInfo(
            cve_id=self.get_cve_ids()[0] if self.get_cve_ids() else None,
            title=self.summary,
            description=description,
            severity=severity_map.get(self.severity, SeverityLevel.UNKNOWN),
            confidence=confidence,
            affected_versions=list(set(affected_versions)),
            fixed_versions=list(set(fixed_versions)),
            published_date=self.published_at,
            references=ref_urls,
            source_url=f"https://github.com/advisories/{self.ghsa_id}"
        )


@dataclass
class GitHubVulnerability:
    """
    Processed GitHub vulnerability with AI enhancements.
    """
    advisory: GitHubAdvisory
    target_package: str
    target_version: Optional[str] = None
    is_affected: bool = False
    
    # AI Enhancement summary
    ai_priority_score: Optional[float] = None
    ai_exploitability_assessment: Optional[str] = None
    ai_remediation_effort: Optional[str] = None
    ai_business_risk: Optional[str] = None
    
    def get_ai_summary(self) -> Dict[str, Any]:
        """Get comprehensive AI analysis summary"""
        return {
            "advisory_id": self.advisory.ghsa_id,
            "target_package": self.target_package,
            "is_affected": self.is_affected,
            "ai_priority_score": self.ai_priority_score,
            "ai_exploitability": self.ai_exploitability_assessment,
            "ai_remediation_effort": self.ai_remediation_effort,
            "ai_business_risk": self.ai_business_risk,
            "cve_ids": self.advisory.get_cve_ids(),
            "severity": self.advisory.severity.value,
            "fixed_versions": self.advisory.get_fixed_versions(self.target_package)
        }


@dataclass
class GitHubAdvisorySearchResult:
    """
    Result of GitHub Advisory search with AI enhancement.
    """
    query: str
    total_count: int
    advisories: List[GitHubAdvisory] = None
    
    # AI Enhancement for search results
    ai_search_quality: Optional[float] = None
    ai_relevance_ranking: List[str] = None  # GHSA IDs ranked by relevance
    ai_search_summary: Optional[str] = None
    ai_key_findings: List[str] = None
    ai_recommended_focus: List[str] = None  # Top advisories to focus on
    
    def __post_init__(self):
        if self.advisories is None:
            self.advisories = []
        if self.ai_relevance_ranking is None:
            self.ai_relevance_ranking = []
        if self.ai_key_findings is None:
            self.ai_key_findings = []
        if self.ai_recommended_focus is None:
            self.ai_recommended_focus = []
    
    def get_high_severity_advisories(self) -> List[GitHubAdvisory]:
        """Get high severity advisories"""
        return [
            advisory for advisory in self.advisories
            if advisory.severity in [GitHubSeverity.CRITICAL, GitHubSeverity.HIGH]
        ]
    
    def get_recent_advisories(self, days: int = 30) -> List[GitHubAdvisory]:
        """Get recently published advisories"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        return [
            advisory for advisory in self.advisories
            if advisory.published_at and advisory.published_at > cutoff_date
        ]
    
    def get_ai_insights(self) -> Dict[str, Any]:
        """Get comprehensive AI insights"""
        high_severity = self.get_high_severity_advisories()
        recent = self.get_recent_advisories()
        
        return {
            "total_advisories": len(self.advisories),
            "high_severity_count": len(high_severity),
            "recent_advisories_count": len(recent),
            "search_quality": self.ai_search_quality,
            "relevance_ranking": self.ai_relevance_ranking,
            "search_summary": self.ai_search_summary,
            "key_findings": self.ai_key_findings,
            "recommended_focus": self.ai_recommended_focus,
            "severity_distribution": self._get_severity_distribution(),
            "ecosystem_distribution": self._get_ecosystem_distribution()
        }
    
    def _get_severity_distribution(self) -> Dict[str, int]:
        """Get distribution of severity levels"""
        severity_counts = {}
        for advisory in self.advisories:
            severity = advisory.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
    
    def _get_ecosystem_distribution(self) -> Dict[str, int]:
        """Get distribution of affected ecosystems"""
        ecosystem_counts = {}
        for advisory in self.advisories:
            for pkg in advisory.affected_packages:
                ecosystem = pkg.ecosystem.value
                ecosystem_counts[ecosystem] = ecosystem_counts.get(ecosystem, 0) + 1
        return ecosystem_counts