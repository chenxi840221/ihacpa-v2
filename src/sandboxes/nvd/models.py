"""
NVD Data Models

Pydantic models for NIST NVD API responses and CVE information.
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum

from ...core.base_scanner import SeverityLevel


class CVSSVersion(Enum):
    """CVSS Version"""
    V2 = "2.0"
    V3_0 = "3.0" 
    V3_1 = "3.1"
    V4_0 = "4.0"


class AttackVector(Enum):
    """CVSS Attack Vector"""
    NETWORK = "NETWORK"
    ADJACENT_NETWORK = "ADJACENT_NETWORK"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class AttackComplexity(Enum):
    """CVSS Attack Complexity"""
    LOW = "LOW"
    HIGH = "HIGH"


class CVSSMetrics(BaseModel):
    """CVSS metrics information"""
    version: CVSSVersion
    vector_string: str
    base_score: float
    base_severity: str
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    
    # CVSS v3+ specific
    attack_vector: Optional[AttackVector] = None
    attack_complexity: Optional[AttackComplexity] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None


class CPEMatch(BaseModel):
    """Common Platform Enumeration match"""
    vulnerable: bool
    criteria: str
    match_criteria_id: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_start_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_end_including: Optional[str] = None


class CPEConfiguration(BaseModel):
    """CPE configuration node"""
    operator: str  # "OR", "AND"
    negate: bool = False
    cpe_match: List[CPEMatch] = Field(default_factory=list)


class VendorData(BaseModel):
    """Vendor information"""
    vendor_name: str
    product: Dict[str, Any] = Field(default_factory=dict)


class CVEReference(BaseModel):
    """CVE reference link"""
    url: HttpUrl
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class CVEDescription(BaseModel):
    """CVE description"""
    lang: str
    value: str


class CVEData(BaseModel):
    """Core CVE data"""
    cve_id: str = Field(alias="CVE_data_meta")
    description: List[CVEDescription] = Field(default_factory=list)
    references: List[CVEReference] = Field(default_factory=list)
    problemtype: Dict[str, Any] = Field(default_factory=dict)
    
    @classmethod
    def __get_validators__(cls):
        yield cls.validate_cve_data
    
    @classmethod
    def validate_cve_data(cls, v):
        if isinstance(v, dict) and "CVE_data_meta" in v:
            cve_id = v["CVE_data_meta"].get("ID", "")
            
            # Parse descriptions
            descriptions = []
            description_data = v.get("description", {}).get("description_data", [])
            for desc in description_data:
                descriptions.append(CVEDescription(
                    lang=desc.get("lang", "en"),
                    value=desc.get("value", "")
                ))
            
            # Parse references
            references = []
            reference_data = v.get("references", {}).get("reference_data", [])
            for ref in reference_data:
                if ref.get("url"):
                    try:
                        references.append(CVEReference(
                            url=ref["url"],
                            source=ref.get("source"),
                            tags=ref.get("tags", [])
                        ))
                    except Exception:
                        pass  # Skip invalid URLs
            
            return cls(
                cve_id=cve_id,
                description=descriptions,
                references=references,
                problemtype=v.get("problemtype", {})
            )
        return v


class NVDVulnerability(BaseModel):
    """Complete NVD vulnerability information"""
    cve_id: str
    source_identifier: Optional[str] = None
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    
    # Vulnerability details
    descriptions: List[CVEDescription] = Field(default_factory=list)
    references: List[CVEReference] = Field(default_factory=list)
    
    # CVSS metrics
    cvss_v2: Optional[CVSSMetrics] = None
    cvss_v3_0: Optional[CVSSMetrics] = None
    cvss_v3_1: Optional[CVSSMetrics] = None
    
    # Configuration and affected products
    configurations: List[CPEConfiguration] = Field(default_factory=list)
    vendor_data: List[VendorData] = Field(default_factory=list)
    
    # Analysis flags
    cisaExploitAdd: Optional[datetime] = None
    cisaActionDue: Optional[datetime] = None
    cisaRequiredAction: Optional[str] = None
    cisaVulnerabilityName: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    @classmethod
    def from_nvd_response(cls, cve_item: Dict[str, Any]) -> "NVDVulnerability":
        """
        Create NVDVulnerability from NVD API response.
        
        Args:
            cve_item: Individual CVE item from NVD API
            
        Returns:
            Parsed NVDVulnerability object
        """
        cve_data = cve_item.get("cve", {})
        
        # Parse basic information
        cve_id = cve_data.get("id", "")
        source_identifier = cve_data.get("sourceIdentifier", "")
        
        # Parse timestamps
        published = None
        last_modified = None
        
        if cve_data.get("published"):
            try:
                published = datetime.fromisoformat(cve_data["published"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        if cve_data.get("lastModified"):
            try:
                last_modified = datetime.fromisoformat(cve_data["lastModified"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        
        # Parse descriptions
        descriptions = []
        for desc in cve_data.get("descriptions", []):
            descriptions.append(CVEDescription(
                lang=desc.get("lang", "en"),
                value=desc.get("value", "")
            ))
        
        # Parse references
        references = []
        for ref in cve_data.get("references", []):
            if ref.get("url"):
                try:
                    references.append(CVEReference(
                        url=ref["url"],
                        source=ref.get("source"),
                        tags=ref.get("tags", [])
                    ))
                except Exception:
                    pass  # Skip invalid URLs
        
        # Parse CVSS metrics
        cvss_v2 = None
        cvss_v3_0 = None
        cvss_v3_1 = None
        
        metrics = cve_data.get("metrics", {})
        
        # CVSS v2
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            v2_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_v2 = CVSSMetrics(
                version=CVSSVersion.V2,
                vector_string=v2_data.get("vectorString", ""),
                base_score=v2_data.get("baseScore", 0.0),
                base_severity=v2_data.get("baseSeverity", "UNKNOWN")
            )
        
        # CVSS v3.0
        if "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            v30_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_v3_0 = CVSSMetrics(
                version=CVSSVersion.V3_0,
                vector_string=v30_data.get("vectorString", ""),
                base_score=v30_data.get("baseScore", 0.0),
                base_severity=v30_data.get("baseSeverity", "UNKNOWN"),
                attack_vector=AttackVector(v30_data.get("attackVector", "NETWORK")),
                attack_complexity=AttackComplexity(v30_data.get("attackComplexity", "LOW"))
            )
        
        # CVSS v3.1
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            v31_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_v3_1 = CVSSMetrics(
                version=CVSSVersion.V3_1,
                vector_string=v31_data.get("vectorString", ""),
                base_score=v31_data.get("baseScore", 0.0),
                base_severity=v31_data.get("baseSeverity", "UNKNOWN"),
                attack_vector=AttackVector(v31_data.get("attackVector", "NETWORK")),
                attack_complexity=AttackComplexity(v31_data.get("attackComplexity", "LOW"))
            )
        
        # Parse configurations
        configurations = []
        for config in cve_data.get("configurations", []):
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = []
                for match in node.get("cpeMatch", []):
                    cpe_matches.append(CPEMatch(
                        vulnerable=match.get("vulnerable", False),
                        criteria=match.get("criteria", ""),
                        match_criteria_id=match.get("matchCriteriaId"),
                        version_start_excluding=match.get("versionStartExcluding"),
                        version_start_including=match.get("versionStartIncluding"),
                        version_end_excluding=match.get("versionEndExcluding"),
                        version_end_including=match.get("versionEndIncluding")
                    ))
                
                configurations.append(CPEConfiguration(
                    operator=node.get("operator", "OR"),
                    negate=node.get("negate", False),
                    cpe_match=cpe_matches
                ))
        
        return cls(
            cve_id=cve_id,
            source_identifier=source_identifier,
            published=published,
            last_modified=last_modified,
            descriptions=descriptions,
            references=references,
            cvss_v2=cvss_v2,
            cvss_v3_0=cvss_v3_0,
            cvss_v3_1=cvss_v3_1,
            configurations=configurations
        )
    
    def get_primary_description(self, lang: str = "en") -> str:
        """Get primary description in specified language"""
        for desc in self.descriptions:
            if desc.lang == lang:
                return desc.value
        
        # Fallback to first available description
        if self.descriptions:
            return self.descriptions[0].value
        
        return ""
    
    def get_best_cvss_score(self) -> Optional[float]:
        """Get the best available CVSS score (preferring v3.1 > v3.0 > v2)"""
        if self.cvss_v3_1:
            return self.cvss_v3_1.base_score
        elif self.cvss_v3_0:
            return self.cvss_v3_0.base_score
        elif self.cvss_v2:
            return self.cvss_v2.base_score
        return None
    
    def get_severity_level(self) -> SeverityLevel:
        """Convert CVSS score to standardized severity level"""
        score = self.get_best_cvss_score()
        if score is None:
            return SeverityLevel.UNKNOWN
        
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score > 0.0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def affects_package(self, package_name: str, version: Optional[str] = None) -> bool:
        """
        Check if this vulnerability affects a specific package.
        
        Args:
            package_name: Name of the package to check
            version: Specific version to check (optional)
            
        Returns:
            True if the package is potentially affected
        """
        package_lower = package_name.lower()
        
        # Check descriptions for package mentions
        primary_desc = self.get_primary_description().lower()
        if package_lower in primary_desc:
            return True
        
        # Check CPE configurations
        for config in self.configurations:
            for cpe_match in config.cpe_match:
                if cpe_match.vulnerable and package_lower in cpe_match.criteria.lower():
                    # If no version specified, assume it's affected
                    if not version:
                        return True
                    
                    # TODO: Implement version range checking
                    # This would require parsing version constraints and comparing
                    return True
        
        return False


class CVEItem(BaseModel):
    """Individual CVE item from NVD API response"""
    cve: NVDVulnerability
    
    @classmethod
    def from_api_response(cls, item: Dict[str, Any]) -> "CVEItem":
        """Create CVEItem from API response"""
        return cls(cve=NVDVulnerability.from_nvd_response(item))