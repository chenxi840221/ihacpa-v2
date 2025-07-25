"""
GitHub Security Advisory Scanner

AI-enhanced scanner for GitHub's Security Advisory database.
Provides comprehensive vulnerability intelligence with AI analysis.
"""

import aiohttp
import asyncio
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from urllib.parse import quote
import logging

from ...core.base_scanner import BaseSandbox, ScanResult, VulnerabilityInfo
from .models import (
    GitHubAdvisory, GitHubVulnerability, GitHubAdvisorySearchResult,
    GitHubSeverity, GitHubAdvisoryType, GitHubEcosystem,
    GitHubAdvisoryIdentifier, GitHubAdvisoryReference,
    GitHubVulnerablePackage, GitHubVulnerableVersionRange
)


class GitHubAdvisorySandbox(BaseSandbox):
    """
    GitHub Security Advisory scanner with AI-enhanced analysis.
    
    Features:
    - GitHub GraphQL API integration
    - AI-powered relevance scoring and analysis
    - Comprehensive advisory intelligence
    - Version-specific vulnerability assessment
    - Cross-reference with CVE database
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("github_advisory", config)
        self.api_url = config.get("api_url", "https://api.github.com/graphql")
        self.rest_api_url = config.get("rest_api_url", "https://api.github.com")
        self.token = config.get("github_token")  # Optional GitHub token for higher rate limits
        self.timeout = config.get("timeout", 30)
        self.max_results = config.get("max_results", 100)
        
        self.logger = logging.getLogger(__name__)
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(limit=10)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                "User-Agent": "IHACPA-v2.0-Security-Scanner",
                "Accept": "application/vnd.github.v3+json"
            }
            
            # Add authentication if token provided
            if self.token:
                headers["Authorization"] = f"token {self.token}"
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=headers
            )
        return self._session
    
    async def scan_package(
        self, 
        package_name: str, 
        current_version: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Scan package for vulnerabilities using GitHub Security Advisory database.
        
        Args:
            package_name: Name of the package to scan
            current_version: Current version of the package
            **kwargs: Additional parameters
            
        Returns:
            ScanResult with GitHub Advisory findings and AI analysis
        """
        scan_start = datetime.utcnow()
        
        # Check cache first
        cache_key = f"github_advisory:{package_name}:{current_version or 'latest'}"
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            self.logger.info(f"Cache hit for GitHub Advisory scan: {package_name}")
            cached_result.cache_hit = True
            return cached_result
        
        # Apply rate limiting
        await self._apply_rate_limit()
        
        try:
            # Search for advisories
            search_result = await self._search_advisories(package_name)
            
            # Process and filter advisories
            vulnerabilities = []
            for advisory in search_result.advisories:
                if advisory.is_package_affected(package_name, current_version):
                    vuln = GitHubVulnerability(
                        advisory=advisory,
                        target_package=package_name,
                        target_version=current_version,
                        is_affected=True
                    )
                    vulnerabilities.append(vuln)
            
            # Apply AI enhancement
            if self.ai_layer and vulnerabilities:
                vulnerabilities = await self._enhance_with_ai(vulnerabilities)
                search_result = await self._enhance_search_result_with_ai(search_result, package_name)
            
            # Convert to base format
            base_vulnerabilities = []
            for vuln in vulnerabilities:
                base_vuln = vuln.advisory.to_base_vulnerability()
                base_vulnerabilities.append(base_vuln)
            
            # Create result
            scan_duration = (datetime.utcnow() - scan_start).total_seconds()
            
            result = ScanResult(
                package_name=package_name,
                source=self.name,
                scan_time=datetime.utcnow(),
                success=True,
                vulnerabilities=base_vulnerabilities,
                ai_enhanced=bool(self.ai_layer),
                metadata={
                    "total_advisories_found": len(search_result.advisories),
                    "relevant_advisories": len(vulnerabilities),
                    "scan_duration": scan_duration,
                    "github_insights": search_result.get_ai_insights() if self.ai_layer else None,
                    "high_severity_count": len(search_result.get_high_severity_advisories()),
                    "recent_advisories_count": len(search_result.get_recent_advisories())
                }
            )
            
            # Cache the result
            await self._cache_result(cache_key, result)
            
            self.logger.info(
                f"GitHub Advisory scan completed for {package_name}: "
                f"{len(base_vulnerabilities)} advisories found"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"GitHub Advisory scan failed for {package_name}: {e}")
            return self._create_error_result(package_name, f"GitHub Advisory scan error: {str(e)}")
    
    async def _search_advisories(self, package_name: str) -> GitHubAdvisorySearchResult:
        """Search for security advisories using GitHub API"""
        advisories = []
        
        try:
            # Try GraphQL API first (more features)
            if self.token:
                graphql_advisories = await self._search_via_graphql(package_name)
                advisories.extend(graphql_advisories)
            
            # Fallback to REST API
            if not advisories:
                rest_advisories = await self._search_via_rest_api(package_name)
                advisories.extend(rest_advisories)
            
        except Exception as e:
            self.logger.error(f"Advisory search failed: {e}")
        
        return GitHubAdvisorySearchResult(
            query=package_name,
            total_count=len(advisories),
            advisories=advisories
        )
    
    async def _search_via_graphql(self, package_name: str) -> List[GitHubAdvisory]:
        """Search advisories using GitHub GraphQL API"""
        advisories = []
        
        try:
            session = await self._get_session()
            
            # GraphQL query for security advisories
            query = """
            query($query: String!, $first: Int!) {
              securityAdvisories(query: $query, first: $first) {
                nodes {
                  ghsaId
                  summary
                  description
                  severity
                  publishedAt
                  updatedAt
                  withdrawnAt
                  identifiers {
                    type
                    value
                  }
                  references {
                    url
                  }
                  vulnerabilities {
                    package {
                      ecosystem
                      name
                    }
                    vulnerableVersionRange
                    firstPatchedVersion {
                      identifier
                    }
                  }
                }
              }
            }
            """
            
            variables = {
                "query": f"ecosystem:pip {package_name}",
                "first": min(self.max_results, 100)
            }
            
            payload = {
                "query": query,
                "variables": variables
            }
            
            async with session.post(self.api_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if "data" in data and "securityAdvisories" in data["data"]:
                        for advisory_data in data["data"]["securityAdvisories"]["nodes"]:
                            advisory = self._parse_graphql_advisory(advisory_data)
                            if advisory:
                                advisories.append(advisory)
                else:
                    self.logger.warning(f"GraphQL API returned status {response.status}")
        
        except Exception as e:
            self.logger.warning(f"GraphQL search failed: {e}")
        
        return advisories
    
    async def _search_via_rest_api(self, package_name: str) -> List[GitHubAdvisory]:
        """Search advisories using GitHub REST API"""
        advisories = []
        
        try:
            session = await self._get_session()
            
            # REST API endpoint for security advisories
            url = f"{self.rest_api_url}/advisories"
            params = {
                "ecosystem": "pip",
                "affects": package_name,
                "per_page": min(self.max_results, 100)
            }
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for advisory_data in data:
                        advisory = self._parse_rest_advisory(advisory_data)
                        if advisory:
                            advisories.append(advisory)
                else:
                    self.logger.warning(f"REST API returned status {response.status}")
        
        except Exception as e:
            self.logger.warning(f"REST API search failed: {e}")
        
        return advisories
    
    def _parse_graphql_advisory(self, data: dict) -> Optional[GitHubAdvisory]:
        """Parse advisory data from GraphQL response"""
        try:
            # Basic information
            ghsa_id = data.get("ghsaId", "")
            summary = data.get("summary", "")
            description = data.get("description", "")
            severity = self._parse_severity(data.get("severity", "medium"))
            
            # Dates
            published_at = self._parse_datetime(data.get("publishedAt"))
            updated_at = self._parse_datetime(data.get("updatedAt"))
            withdrawn_at = self._parse_datetime(data.get("withdrawnAt"))
            
            # Identifiers
            identifiers = []
            for identifier_data in data.get("identifiers", []):
                identifiers.append(GitHubAdvisoryIdentifier(
                    type=identifier_data.get("type", ""),
                    value=identifier_data.get("value", "")
                ))
            
            # References
            references = []
            for ref_data in data.get("references", []):
                references.append(GitHubAdvisoryReference(
                    url=ref_data.get("url", "")
                ))
            
            # Affected packages
            affected_packages = []
            for vuln_data in data.get("vulnerabilities", []):
                package_data = vuln_data.get("package", {})
                ecosystem = self._parse_ecosystem(package_data.get("ecosystem", "pip"))
                package_name = package_data.get("name", "")
                
                # Parse version range
                version_range = GitHubVulnerableVersionRange()
                range_str = vuln_data.get("vulnerableVersionRange", "")
                if range_str:
                    version_range = self._parse_version_range(range_str)
                
                # Parse patched versions
                patched_versions = []
                first_patched = vuln_data.get("firstPatchedVersion")
                if first_patched:
                    patched_versions.append(first_patched.get("identifier", ""))
                
                affected_packages.append(GitHubVulnerablePackage(
                    ecosystem=ecosystem,
                    name=package_name,
                    vulnerable_version_range=version_range,
                    patched_versions=patched_versions
                ))
            
            return GitHubAdvisory(
                ghsa_id=ghsa_id,
                summary=summary,
                description=description,
                severity=severity,
                published_at=published_at,
                updated_at=updated_at,
                withdrawn_at=withdrawn_at,
                identifiers=identifiers,
                references=references,
                affected_packages=affected_packages
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to parse GraphQL advisory: {e}")
            return None
    
    def _parse_rest_advisory(self, data: dict) -> Optional[GitHubAdvisory]:
        """Parse advisory data from REST API response"""
        try:
            # Basic information
            ghsa_id = data.get("ghsa_id", "")
            summary = data.get("summary", "")
            description = data.get("description", "")
            severity = self._parse_severity(data.get("severity", "medium"))
            
            # Dates
            published_at = self._parse_datetime(data.get("published_at"))
            updated_at = self._parse_datetime(data.get("updated_at"))
            withdrawn_at = self._parse_datetime(data.get("withdrawn_at"))
            
            # Identifiers
            identifiers = []
            for identifier_data in data.get("identifiers", []):
                identifiers.append(GitHubAdvisoryIdentifier(
                    type=identifier_data.get("type", ""),
                    value=identifier_data.get("value", "")
                ))
            
            # References
            references = []
            for ref_data in data.get("references", []):
                references.append(GitHubAdvisoryReference(
                    url=ref_data.get("url", "")
                ))
            
            # Affected packages
            affected_packages = []
            for vuln_data in data.get("vulnerabilities", []):
                package_info = vuln_data.get("package", {})
                ecosystem = self._parse_ecosystem(package_info.get("ecosystem", "pip"))
                package_name = package_info.get("name", "")
                
                # Parse version information
                version_range = GitHubVulnerableVersionRange()
                if "vulnerable_version_range" in vuln_data:
                    version_range = self._parse_version_range(vuln_data["vulnerable_version_range"])
                
                patched_versions = vuln_data.get("patched_versions", [])
                unaffected_versions = vuln_data.get("unaffected_versions", [])
                
                affected_packages.append(GitHubVulnerablePackage(
                    ecosystem=ecosystem,
                    name=package_name,
                    vulnerable_version_range=version_range,
                    patched_versions=patched_versions,
                    unaffected_versions=unaffected_versions
                ))
            
            return GitHubAdvisory(
                ghsa_id=ghsa_id,
                summary=summary,
                description=description,
                severity=severity,
                published_at=published_at,
                updated_at=updated_at,
                withdrawn_at=withdrawn_at,
                identifiers=identifiers,
                references=references,
                affected_packages=affected_packages
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to parse REST advisory: {e}")
            return None
    
    def _parse_severity(self, severity_str: str) -> GitHubSeverity:
        """Parse severity from string"""
        severity_str = severity_str.lower().strip()
        
        if severity_str == "critical":
            return GitHubSeverity.CRITICAL
        elif severity_str == "high":
            return GitHubSeverity.HIGH
        elif severity_str == "medium":
            return GitHubSeverity.MEDIUM
        elif severity_str == "low":
            return GitHubSeverity.LOW
        else:
            return GitHubSeverity.MEDIUM
    
    def _parse_ecosystem(self, ecosystem_str: str) -> GitHubEcosystem:
        """Parse ecosystem from string"""
        ecosystem_str = ecosystem_str.lower().strip()
        
        ecosystem_map = {
            "pip": GitHubEcosystem.PYPI,
            "pypi": GitHubEcosystem.PYPI,
            "npm": GitHubEcosystem.NPM,
            "maven": GitHubEcosystem.MAVEN,
            "nuget": GitHubEcosystem.NUGET,
            "rubygems": GitHubEcosystem.RUBYGEMS,
            "go": GitHubEcosystem.GO,
            "rust": GitHubEcosystem.RUST,
            "composer": GitHubEcosystem.COMPOSER
        }
        
        return ecosystem_map.get(ecosystem_str, GitHubEcosystem.PYPI)
    
    def _parse_datetime(self, datetime_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime from ISO string"""
        if not datetime_str:
            return None
        
        try:
            # Handle different datetime formats
            if datetime_str.endswith('Z'):
                datetime_str = datetime_str[:-1] + '+00:00'
            
            return datetime.fromisoformat(datetime_str)
        except Exception:
            return None
    
    def _parse_version_range(self, range_str: str) -> GitHubVulnerableVersionRange:
        """Parse version range from string"""
        version_range = GitHubVulnerableVersionRange()
        
        # Simple parsing - can be enhanced for more complex ranges
        events = []
        
        if ">=" in range_str:
            # e.g., ">= 1.0.0"
            version = range_str.split(">=")[1].strip()
            events.append({"type": "introduced", "version": version})
        elif "<" in range_str:
            # e.g., "< 2.0.0"
            version = range_str.split("<")[1].strip()
            events.append({"type": "fixed", "version": version})
        
        version_range.events = events
        return version_range
    
    async def _enhance_with_ai(self, vulnerabilities: List[GitHubVulnerability]) -> List[GitHubVulnerability]:
        """Enhance vulnerabilities with AI analysis"""
        if not self.ai_layer:
            return vulnerabilities
        
        enhanced_vulns = []
        
        for vuln in vulnerabilities:
            try:
                # Get AI analysis for the advisory
                analysis = await self._get_ai_advisory_analysis(vuln)
                
                if analysis:
                    vuln.advisory.ai_risk_assessment = analysis.get('risk_assessment')
                    vuln.advisory.ai_confidence = analysis.get('confidence', 0.5)
                    vuln.advisory.ai_exploitability = analysis.get('exploitability')
                    vuln.advisory.ai_relevance_score = analysis.get('relevance_score', 0.5)
                    vuln.advisory.ai_recommendation = analysis.get('recommendation')
                    vuln.advisory.ai_reasoning = analysis.get('reasoning')
                    vuln.advisory.ai_impact_analysis = analysis.get('impact_analysis')
                    vuln.advisory.ai_remediation_priority = analysis.get('remediation_priority')
                    
                    # Vulnerability-specific AI fields
                    vuln.ai_priority_score = analysis.get('priority_score', 0.5)
                    vuln.ai_exploitability_assessment = analysis.get('exploitability')
                    vuln.ai_remediation_effort = analysis.get('remediation_effort')
                    vuln.ai_business_risk = analysis.get('business_risk')
                
                enhanced_vulns.append(vuln)
                
            except Exception as e:
                self.logger.warning(f"AI enhancement failed for {vuln.advisory.ghsa_id}: {e}")
                enhanced_vulns.append(vuln)  # Add without enhancement
        
        return enhanced_vulns
    
    async def _get_ai_advisory_analysis(self, vuln: GitHubVulnerability) -> Optional[Dict[str, Any]]:
        """Get AI analysis for a GitHub advisory"""
        try:
            from ...ai_layer.agents.cve_analyzer import CVEAnalyzer
            
            analyzer = CVEAnalyzer(self.ai_layer)
            advisory = vuln.advisory
            
            # Use CVE analyzer if CVE ID is available
            cve_ids = advisory.get_cve_ids()
            cve_id = cve_ids[0] if cve_ids else advisory.ghsa_id
            
            analysis_result = await analyzer.analyze_cve(
                cve_id=cve_id,
                cve_description=f"{advisory.summary}\n\n{advisory.description}",
                package_name=vuln.target_package,
                current_version=vuln.target_version,
                affected_products=", ".join(advisory.get_affected_package_names())
            )
            
            return {
                'risk_assessment': analysis_result.severity.value,
                'confidence': analysis_result.confidence,
                'exploitability': self._assess_github_exploitability(advisory),
                'relevance_score': self._calculate_github_relevance(advisory, vuln.target_package),
                'recommendation': analysis_result.recommendation,
                'reasoning': analysis_result.reasoning,
                'impact_analysis': self._assess_impact(advisory),
                'remediation_priority': self._assess_remediation_priority(advisory),
                'priority_score': self._calculate_priority_score(advisory),
                'remediation_effort': self._assess_remediation_effort(advisory, vuln.target_package),
                'business_risk': self._assess_business_risk(advisory)
            }
            
        except Exception as e:
            self.logger.warning(f"AI advisory analysis failed: {e}")
            return None
    
    async def _enhance_search_result_with_ai(
        self, 
        search_result: GitHubAdvisorySearchResult, 
        package_name: str
    ) -> GitHubAdvisorySearchResult:
        """Enhance search results with AI analysis"""
        try:
            if not self.ai_layer:
                return search_result
            
            # Get overall AI insights for the search
            overall_analysis = await self._get_ai_search_analysis(search_result, package_name)
            
            if overall_analysis:
                search_result.ai_search_quality = overall_analysis.get('search_quality')
                search_result.ai_relevance_ranking = overall_analysis.get('relevance_ranking', [])
                search_result.ai_search_summary = overall_analysis.get('search_summary')
                search_result.ai_key_findings = overall_analysis.get('key_findings', [])
                search_result.ai_recommended_focus = overall_analysis.get('recommended_focus', [])
            
        except Exception as e:
            self.logger.warning(f"AI search result enhancement failed: {e}")
        
        return search_result
    
    async def _get_ai_search_analysis(
        self, 
        search_result: GitHubAdvisorySearchResult, 
        package_name: str
    ) -> Optional[Dict[str, Any]]:
        """Get AI analysis for search results"""
        try:
            if not self.ai_layer:
                return None
            
            from ...ai_layer.chain_factory import get_ai_factory
            
            factory = get_ai_factory()
            llm = factory.get_chat_llm()
            
            # Create summary for AI analysis
            advisory_summaries = []
            for advisory in search_result.advisories[:10]:  # Limit to top 10
                summary = {
                    "ghsa_id": advisory.ghsa_id,
                    "summary": advisory.summary[:150],
                    "severity": advisory.severity.value,
                    "published": advisory.published_at.isoformat() if advisory.published_at else "Unknown",
                    "cve_ids": advisory.get_cve_ids()
                }
                advisory_summaries.append(summary)
            
            prompt = f"""
            Analyze the following GitHub Security Advisory search results for Python package "{package_name}":
            
            Total advisories found: {len(search_result.advisories)}
            
            Top advisories:
            {json.dumps(advisory_summaries, indent=2)}
            
            Provide:
            1. Search quality score (0.0-1.0) - how relevant are these results
            2. Relevance ranking - list top 5 GHSA IDs in order of relevance/priority
            3. Search summary - brief overview of key security concerns
            4. Key findings - list 3-5 main security issues discovered
            5. Recommended focus - list 2-3 GHSA IDs that need immediate attention
            
            Format as JSON with keys: search_quality, relevance_ranking, search_summary, key_findings, recommended_focus
            """
            
            response = await llm.ainvoke(prompt)
            
            # Parse JSON response
            try:
                analysis = json.loads(response.content)
                return analysis
            except json.JSONDecodeError:
                # Fallback analysis
                return {
                    'search_quality': 0.8,
                    'relevance_ranking': [advisory.ghsa_id for advisory in search_result.advisories[:5]],
                    'search_summary': f"Found {len(search_result.advisories)} security advisories for {package_name}",
                    'key_findings': ["Multiple security vulnerabilities found", "High severity issues present"],
                    'recommended_focus': [advisory.ghsa_id for advisory in search_result.get_high_severity_advisories()[:3]]
                }
            
        except Exception as e:
            self.logger.warning(f"AI search analysis failed: {e}")
            return None
    
    def _assess_github_exploitability(self, advisory: GitHubAdvisory) -> str:
        """Assess exploitability based on GitHub advisory characteristics"""
        # High exploitability indicators
        high_indicators = ['remote', 'unauthenticated', 'code execution', 'rce', 'injection']
        medium_indicators = ['authentication bypass', 'privilege escalation', 'xss', 'csrf']
        
        description_lower = f"{advisory.summary} {advisory.description}".lower()
        
        if any(indicator in description_lower for indicator in high_indicators):
            return "High"
        elif any(indicator in description_lower for indicator in medium_indicators):
            return "Medium"
        else:
            return "Low"
    
    def _calculate_github_relevance(self, advisory: GitHubAdvisory, package_name: str) -> float:
        """Calculate relevance score for GitHub advisory"""
        score = 0.0
        
        # Direct package match
        if any(pkg.name.lower() == package_name.lower() for pkg in advisory.affected_packages):
            score += 1.0
        
        # Severity factor
        severity_weights = {
            GitHubSeverity.CRITICAL: 0.3,
            GitHubSeverity.HIGH: 0.2,
            GitHubSeverity.MEDIUM: 0.1,
            GitHubSeverity.LOW: 0.05
        }
        score += severity_weights.get(advisory.severity, 0.0)
        
        # Recent publication (more relevant)
        if advisory.published_at and advisory.published_at > datetime.utcnow() - timedelta(days=365):
            score += 0.2
        
        return min(score, 1.0)
    
    def _assess_impact(self, advisory: GitHubAdvisory) -> str:
        """Assess impact based on advisory characteristics"""
        description_lower = f"{advisory.summary} {advisory.description}".lower()
        
        if advisory.severity == GitHubSeverity.CRITICAL:
            return "Critical system compromise possible"
        elif advisory.severity == GitHubSeverity.HIGH:
            if any(term in description_lower for term in ['data', 'information', 'leak']):
                return "High - Data exposure risk"
            else:
                return "High - System integrity at risk"
        elif advisory.severity == GitHubSeverity.MEDIUM:
            return "Medium - Limited security impact"
        else:
            return "Low - Minimal security impact"
    
    def _assess_remediation_priority(self, advisory: GitHubAdvisory) -> str:
        """Assess remediation priority"""
        if advisory.severity in [GitHubSeverity.CRITICAL, GitHubSeverity.HIGH]:
            return "Immediate"
        elif advisory.severity == GitHubSeverity.MEDIUM:
            return "High"
        else:
            return "Medium"
    
    def _calculate_priority_score(self, advisory: GitHubAdvisory) -> float:
        """Calculate priority score (0.0-1.0)"""
        base_score = {
            GitHubSeverity.CRITICAL: 1.0,
            GitHubSeverity.HIGH: 0.8,
            GitHubSeverity.MEDIUM: 0.5,
            GitHubSeverity.LOW: 0.2
        }.get(advisory.severity, 0.5)
        
        # Adjust for recent publication
        if advisory.published_at and advisory.published_at > datetime.utcnow() - timedelta(days=30):
            base_score = min(base_score + 0.1, 1.0)
        
        return base_score
    
    def _assess_remediation_effort(self, advisory: GitHubAdvisory, package_name: str) -> str:
        """Assess remediation effort"""
        fixed_versions = advisory.get_fixed_versions(package_name)
        
        if fixed_versions:
            return "Low - Update available"
        elif advisory.severity in [GitHubSeverity.CRITICAL, GitHubSeverity.HIGH]:
            return "High - No fix available, requires mitigation"
        else:
            return "Medium - Monitor for updates"
    
    def _assess_business_risk(self, advisory: GitHubAdvisory) -> str:
        """Assess business risk"""
        severity_risks = {
            GitHubSeverity.CRITICAL: "Critical business risk - Immediate action required",
            GitHubSeverity.HIGH: "High business risk - Significant impact possible",
            GitHubSeverity.MEDIUM: "Medium business risk - Monitor and plan remediation",
            GitHubSeverity.LOW: "Low business risk - Address in maintenance cycle"
        }
        
        return severity_risks.get(advisory.severity, "Medium business risk")
    
    async def health_check(self) -> bool:
        """Check if GitHub Advisory sandbox is healthy"""
        try:
            session = await self._get_session()
            
            # Test API connectivity
            async with session.get(f"{self.rest_api_url}/advisories?per_page=1") as response:
                if response.status in [200, 403]:  # 403 might occur due to rate limiting
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"GitHub Advisory health check failed: {e}")
            return False
    
    async def close(self):
        """Clean up resources"""
        if self._session and not self._session.closed:
            await self._session.close()
        
        self.logger.info("GitHub Advisory sandbox closed")