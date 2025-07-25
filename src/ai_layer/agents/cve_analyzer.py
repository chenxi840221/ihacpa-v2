"""
CVE Analyzer Agent

AI-powered analysis of CVE vulnerabilities for package-specific impact assessment.
"""

import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime

from langchain.prompts import PromptTemplate
from langchain.schema import BaseOutputParser

from ...core.base_scanner import VulnerabilityInfo, SeverityLevel, ConfidenceLevel
from ..chain_factory import get_ai_factory


@dataclass 
class CVEAnalysisResult:
    """Result of CVE analysis"""
    cve_id: str
    package_name: str
    current_version: Optional[str]
    is_affected: bool
    confidence: float  # 0.0 to 1.0
    severity: SeverityLevel
    recommendation: str
    reasoning: str
    fixed_versions: List[str]
    workarounds: List[str]
    
    def to_vulnerability_info(self) -> VulnerabilityInfo:
        """Convert to standard VulnerabilityInfo format"""
        confidence_level = ConfidenceLevel.VERY_LOW
        if self.confidence >= 0.9:
            confidence_level = ConfidenceLevel.VERY_HIGH
        elif self.confidence >= 0.75:
            confidence_level = ConfidenceLevel.HIGH
        elif self.confidence >= 0.5:
            confidence_level = ConfidenceLevel.MEDIUM
        elif self.confidence >= 0.25:
            confidence_level = ConfidenceLevel.LOW
        
        return VulnerabilityInfo(
            cve_id=self.cve_id,
            title=f"CVE Analysis: {self.cve_id}",
            description=f"{self.reasoning}\n\nRecommendation: {self.recommendation}",
            severity=self.severity,
            confidence=confidence_level,
            affected_versions=[self.current_version] if self.current_version and self.is_affected else [],
            fixed_versions=self.fixed_versions,
            references=[f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"]
        )


class CVEAnalysisOutputParser(BaseOutputParser):
    """Parse structured output from CVE analysis prompt"""
    
    def parse(self, text: str) -> CVEAnalysisResult:
        """Parse the LLM output into structured result"""
        
        # Default values
        result_data = {
            "cve_id": "",
            "package_name": "",
            "current_version": None,
            "is_affected": False,
            "confidence": 0.5,
            "severity": SeverityLevel.UNKNOWN,
            "recommendation": "Unable to determine recommendation",
            "reasoning": "Analysis could not be completed",
            "fixed_versions": [],
            "workarounds": []
        }
        
        # Extract structured information using regex patterns
        patterns = {
            "is_affected": r"(?:AFFECTED|IS_AFFECTED):\s*(YES|NO|TRUE|FALSE)",
            "confidence": r"(?:CONFIDENCE|CONFIDENCE_SCORE):\s*(\d+(?:\.\d+)?)",
            "severity": r"(?:SEVERITY|RISK_LEVEL):\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)",
            "recommendation": r"(?:RECOMMENDATION|RECOMMEND):\s*(.+?)(?:\n|$)",
            "reasoning": r"(?:REASONING|ANALYSIS|EXPLANATION):\s*(.+?)(?:\n\n|\n[A-Z]+:)",
            "fixed_versions": r"(?:FIXED_IN|FIXED_VERSIONS):\s*(.+?)(?:\n|$)",
            "workarounds": r"(?:WORKAROUNDS|MITIGATIONS):\s*(.+?)(?:\n|$)"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                value = match.group(1).strip()
                
                if key == "is_affected":
                    result_data[key] = value.upper() in ["YES", "TRUE"]
                elif key == "confidence":
                    try:
                        conf = float(value)
                        # If confidence is given as percentage, convert to 0-1 range
                        if conf > 1.0:
                            conf = conf / 100.0
                        result_data[key] = max(0.0, min(1.0, conf))
                    except ValueError:
                        pass
                elif key == "severity":
                    severity_map = {
                        "CRITICAL": SeverityLevel.CRITICAL,
                        "HIGH": SeverityLevel.HIGH,
                        "MEDIUM": SeverityLevel.MEDIUM,
                        "LOW": SeverityLevel.LOW,
                        "INFO": SeverityLevel.INFO
                    }
                    result_data[key] = severity_map.get(value.upper(), SeverityLevel.UNKNOWN)
                elif key in ["fixed_versions", "workarounds"]:
                    # Parse comma-separated lists
                    items = [item.strip() for item in value.split(",") if item.strip()]
                    result_data[key] = items
                else:
                    result_data[key] = value
        
        return CVEAnalysisResult(**result_data)


class CVEAnalyzer:
    """
    AI-powered CVE analyzer that provides intelligent vulnerability assessment.
    """
    
    def __init__(self, ai_factory=None):
        self.ai_factory = ai_factory or get_ai_factory()
        self.output_parser = CVEAnalysisOutputParser()
        
        # Create analysis prompt template
        self.analysis_prompt = PromptTemplate(
            input_variables=[
                "cve_id", "cve_description", "package_name", "current_version",
                "cvss_score", "published_date", "affected_products"
            ],
            template="""
You are a cybersecurity expert analyzing CVE vulnerabilities for specific packages.

CVE Information:
- CVE ID: {cve_id}
- Description: {cve_description}
- CVSS Score: {cvss_score}
- Published: {published_date}
- Affected Products: {affected_products}

Package Context:
- Package Name: {package_name}
- Current Version: {current_version}

Please analyze if this CVE affects the specified package version and provide:

IS_AFFECTED: [YES/NO] - Does this CVE affect the specified package version?
CONFIDENCE: [0-100] - How confident are you in this assessment?
SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW/INFO] - Severity level for this specific context
RECOMMENDATION: [Brief action recommendation]
REASONING: [Detailed explanation of your analysis]
FIXED_VERSIONS: [Comma-separated list of versions that fix this issue, if known]
WORKAROUNDS: [Comma-separated list of potential workarounds, if any]

Focus on:
1. Whether the package name matches affected products
2. Version-specific impact analysis
3. Practical remediation steps
4. Real-world exploitability context

Be precise and conservative in your assessment.
            """.strip()
        )
    
    async def analyze_cve(
        self,
        cve_id: str,
        cve_description: str,
        package_name: str,
        current_version: Optional[str] = None,
        cvss_score: Optional[float] = None,
        published_date: Optional[datetime] = None,
        affected_products: Optional[str] = None,
        **kwargs
    ) -> CVEAnalysisResult:
        """
        Analyze a CVE for package-specific impact.
        
        Args:
            cve_id: CVE identifier
            cve_description: CVE description text
            package_name: Target package name
            current_version: Current package version
            cvss_score: CVSS score if available
            published_date: CVE publication date
            affected_products: Known affected products/versions
            **kwargs: Additional context
            
        Returns:
            CVE analysis result
        """
        try:
            # Prepare input variables
            prompt_vars = {
                "cve_id": cve_id or "Unknown",
                "cve_description": cve_description or "No description available",
                "package_name": package_name,
                "current_version": current_version or "Unknown",
                "cvss_score": f"{cvss_score:.1f}" if cvss_score else "Not available",
                "published_date": published_date.strftime("%Y-%m-%d") if published_date else "Unknown",
                "affected_products": affected_products or "Not specified"
            }
            
            # Create the chain
            llm = self.ai_factory.get_chat_llm()
            chain = self.analysis_prompt | llm | self.output_parser
            
            # Run analysis
            result = await self._run_chain_async(chain, prompt_vars)
            
            # Set the input parameters in result
            result.cve_id = cve_id
            result.package_name = package_name
            result.current_version = current_version
            
            return result
            
        except Exception as e:
            print(f"CVE analysis failed for {cve_id}: {e}")
            
            # Return conservative fallback result
            return CVEAnalysisResult(
                cve_id=cve_id,
                package_name=package_name,
                current_version=current_version,
                is_affected=True,  # Conservative assumption
                confidence=0.3,    # Low confidence
                severity=SeverityLevel.MEDIUM,  # Conservative severity
                recommendation="Review this CVE manually and update if necessary",
                reasoning=f"Automated analysis failed: {str(e)}",
                fixed_versions=[],
                workarounds=[]
            )
    
    async def _run_chain_async(self, chain, inputs: Dict[str, Any]) -> CVEAnalysisResult:
        """Run the chain asynchronously with proper error handling"""
        try:
            # For now, run synchronously since LangChain async support varies
            result = chain.invoke(inputs)
            return result
        except Exception as e:
            # If chain execution fails, parse the error and create a basic result
            print(f"Chain execution failed: {e}")
            return self.output_parser.parse("AFFECTED: NO\nCONFIDENCE: 30\nSEVERITY: UNKNOWN\nRECOMMENDATION: Manual review required\nREASONING: Automated analysis encountered an error")
    
    def analyze_cve_sync(
        self,
        cve_id: str,
        cve_description: str,
        package_name: str,
        current_version: Optional[str] = None,
        **kwargs
    ) -> CVEAnalysisResult:
        """
        Synchronous version of CVE analysis.
        
        Args:
            cve_id: CVE identifier
            cve_description: CVE description
            package_name: Package name
            current_version: Package version
            **kwargs: Additional parameters
            
        Returns:
            CVE analysis result
        """
        import asyncio
        
        try:
            # If we're already in an async context, we need to handle this carefully
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Create a new task for this
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self.analyze_cve(cve_id, cve_description, package_name, current_version, **kwargs)
                    )
                    return future.result()
            else:
                return asyncio.run(
                    self.analyze_cve(cve_id, cve_description, package_name, current_version, **kwargs)
                )
        except Exception as e:
            print(f"Sync CVE analysis failed: {e}")
            return CVEAnalysisResult(
                cve_id=cve_id,
                package_name=package_name,
                current_version=current_version,
                is_affected=True,
                confidence=0.2,
                severity=SeverityLevel.UNKNOWN,
                recommendation="Manual review required",
                reasoning=f"Analysis failed: {str(e)}",
                fixed_versions=[],
                workarounds=[]
            )
    
    def batch_analyze_cves(
        self,
        cve_data: List[Dict[str, Any]],
        package_name: str,
        current_version: Optional[str] = None
    ) -> List[CVEAnalysisResult]:
        """
        Analyze multiple CVEs for a package.
        
        Args:
            cve_data: List of CVE data dictionaries
            package_name: Package name
            current_version: Package version
            
        Returns:
            List of analysis results
        """
        results = []
        
        for cve in cve_data:
            try:
                result = self.analyze_cve_sync(
                    cve_id=cve.get("cve_id", ""),
                    cve_description=cve.get("description", ""),
                    package_name=package_name,
                    current_version=current_version,
                    cvss_score=cve.get("cvss_score"),
                    published_date=cve.get("published_date"),
                    affected_products=cve.get("affected_products")
                )
                results.append(result)
            except Exception as e:
                print(f"Failed to analyze CVE {cve.get('cve_id', 'unknown')}: {e}")
                continue
        
        return results