"""
MITRE CVE Database Scanner

AI-enhanced scanner for MITRE's official CVE database.
Provides authoritative vulnerability information with intelligent analysis.
"""

import aiohttp
import asyncio
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode
import logging
import re

from ...core.base_scanner import BaseSandbox, ScanResult, VulnerabilityInfo, SeverityLevel
from .models import (
    MITREVulnerability, MITRECVEInfo, MITRESearchContext,
    MITREReference, MITREMetrics, MITREWeakness, MITREStatus,
    MITREAssignerType
)


class MITRESandbox(BaseSandbox):
    """
    MITRE CVE database scanner with AI-enhanced analysis.
    
    Features:
    - Official MITRE CVE database access
    - AI-powered relevance scoring and analysis
    - Comprehensive vulnerability intelligence
    - Cross-reference analysis with other databases
    - Intelligent search query expansion
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("mitre", config)
        self.base_url = config.get("base_url", "https://cveawg.mitre.org/api/cve")
        self.web_base_url = config.get("web_base_url", "https://cve.mitre.org")
        self.timeout = config.get("timeout", 30)
        self.max_results = config.get("max_results", 100)
        self.days_back = config.get("days_back", 365)
        
        self.logger = logging.getLogger(__name__)
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(limit=10)
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                "User-Agent": "IHACPA-v2.0-Security-Scanner",
                "Accept": "application/json"
            }
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
        Scan package for vulnerabilities using MITRE CVE database.
        
        Args:
            package_name: Name of the package to scan
            current_version: Current version of the package
            **kwargs: Additional parameters
            
        Returns:
            ScanResult with MITRE findings and AI analysis
        """
        scan_start = datetime.utcnow()
        
        # Check cache first
        cache_key = f"mitre:{package_name}:{current_version or 'latest'}"
        cached_result = await self._get_cached_result(cache_key)
        if cached_result:
            self.logger.info(f"Cache hit for MITRE scan: {package_name}")
            cached_result.cache_hit = True
            return cached_result
        
        # Apply rate limiting
        await self._apply_rate_limit()
        
        try:
            # Create search context
            search_context = MITRESearchContext(
                package_name=package_name,
                search_terms=self._generate_search_terms(package_name),
                max_results=self.max_results,
                ai_query_expansion=bool(self.ai_layer)
            )
            
            # Enhance search terms with AI if available
            if self.ai_layer:
                search_context = await self._enhance_search_with_ai(search_context)
            
            # Search for CVEs
            cve_info = await self._search_cves(search_context)
            
            # Apply AI enhancement to results
            if self.ai_layer and cve_info.vulnerabilities:
                cve_info = await self._enhance_results_with_ai(cve_info, package_name, current_version)
            
            # Filter and convert to base format
            base_vulnerabilities = []
            for vuln in cve_info.vulnerabilities:
                # Apply relevance filtering
                if self._is_relevant_to_package(vuln, package_name, current_version):
                    base_vuln = vuln.to_base_vulnerability()
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
                    "total_cves_found": len(cve_info.vulnerabilities),
                    "relevant_cves": len(base_vulnerabilities),
                    "scan_duration": scan_duration,
                    "search_query": search_context.get_search_query(),
                    "ai_insights": cve_info.get_ai_insights() if self.ai_layer else None,
                    "high_priority_count": len(cve_info.get_high_priority_cves()) if self.ai_layer else 0
                }
            )
            
            # Cache the result
            await self._cache_result(cache_key, result)
            
            self.logger.info(
                f"MITRE scan completed for {package_name}: "
                f"{len(base_vulnerabilities)} relevant CVEs found"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"MITRE scan failed for {package_name}: {e}")
            return self._create_error_result(package_name, f"MITRE scan error: {str(e)}")
    
    def _generate_search_terms(self, package_name: str) -> List[str]:
        """Generate initial search terms for a package"""
        terms = [package_name]
        
        # Add common variations
        if '-' in package_name:
            terms.append(package_name.replace('-', '_'))
            terms.append(package_name.replace('-', ''))
        if '_' in package_name:
            terms.append(package_name.replace('_', '-'))
            terms.append(package_name.replace('_', ''))
        
        # Add language context
        terms.extend([
            f"python {package_name}",
            f"python-{package_name}",
            f"pip {package_name}"
        ])
        
        return terms
    
    async def _enhance_search_with_ai(self, context: MITRESearchContext) -> MITRESearchContext:
        """Enhance search context using AI query expansion"""
        try:
            if not self.ai_layer:
                return context
            
            # Use AI to expand search terms
            expanded_terms = await self._get_ai_search_expansion(context)
            if expanded_terms:
                context.search_terms.extend(expanded_terms)
            
            return context
            
        except Exception as e:
            self.logger.warning(f"AI search enhancement failed: {e}")
            return context
    
    async def _get_ai_search_expansion(self, context: MITRESearchContext) -> List[str]:
        """Get AI-generated search term expansions"""
        try:
            from ...ai_layer.chain_factory import get_ai_factory
            
            factory = get_ai_factory()
            llm = factory.get_chat_llm()
            
            prompt = f"""
            You are a cybersecurity expert helping to find relevant CVE vulnerabilities.
            
            Package: {context.package_name}
            Current search terms: {', '.join(context.search_terms)}
            
            Generate additional search terms that might help find CVE vulnerabilities related to this Python package.
            Consider:
            1. Alternative package names or spellings
            2. Related technologies or frameworks
            3. Common vulnerability types for this type of package
            4. Vendor or organization names
            
            Return only the additional search terms, one per line, maximum 5 terms.
            Do not include explanations.
            """
            
            response = await llm.ainvoke(prompt)
            
            # Parse response
            additional_terms = []
            for line in response.content.split('\n'):
                term = line.strip()
                if term and not term.startswith('#') and len(term) < 50:
                    additional_terms.append(term)
            
            return additional_terms[:5]  # Limit to 5 additional terms
            
        except Exception as e:
            self.logger.warning(f"AI search expansion failed: {e}")
            return []
    
    async def _search_cves(self, context: MITRESearchContext) -> MITRECVEInfo:
        """Search for CVEs using MITRE API"""
        vulnerabilities = []
        
        try:
            # Try API search first
            api_results = await self._search_via_api(context)
            vulnerabilities.extend(api_results)
            
            # If no results or too few, try web search
            if len(vulnerabilities) < 5:
                web_results = await self._search_via_web(context)
                vulnerabilities.extend(web_results)
            
        except Exception as e:
            self.logger.error(f"CVE search failed: {e}")
        
        return MITRECVEInfo(
            search_query=context.get_search_query(),
            total_results=len(vulnerabilities),
            vulnerabilities=vulnerabilities
        )
    
    async def _search_via_api(self, context: MITRESearchContext) -> List[MITREVulnerability]:
        """Search CVEs using MITRE API"""
        vulnerabilities = []
        
        try:
            session = await self._get_session()
            
            # Build search parameters
            params = {
                "keyword": context.package_name,
                "resultsPerPage": min(context.max_results, 100),
                "startIndex": 0
            }
            
            # Add date filter
            if context.date_range:
                params["publishedStartDate"] = context.date_range[0].isoformat()
                params["publishedEndDate"] = context.date_range[1].isoformat()
            else:
                # Default to last year
                start_date = datetime.utcnow() - timedelta(days=self.days_back)
                params["publishedStartDate"] = start_date.isoformat()
            
            url = f"{self.base_url}/2.0"
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if "vulnerabilities" in data:
                        for cve_data in data["vulnerabilities"]:
                            vuln = self._parse_api_cve(cve_data)
                            if vuln:
                                vulnerabilities.append(vuln)
                else:
                    self.logger.warning(f"MITRE API returned status {response.status}")
        
        except Exception as e:
            self.logger.warning(f"MITRE API search failed: {e}")
        
        return vulnerabilities
    
    async def _search_via_web(self, context: MITRESearchContext) -> List[MITREVulnerability]:
        """Search CVEs using web interface (fallback)"""
        vulnerabilities = []
        
        try:
            session = await self._get_session()
            
            # Use the CVE search interface
            search_url = f"{self.web_base_url}/cgi-bin/cvekey.cgi"
            
            # Try different search terms
            for term in context.search_terms[:3]:  # Limit to avoid too many requests
                params = {
                    "keyword": term
                }
                
                async with session.get(search_url, params=params) as response:
                    if response.status == 200:
                        text = await response.text()
                        cve_ids = self._extract_cve_ids_from_html(text)
                        
                        # Get details for each CVE
                        for cve_id in cve_ids[:10]:  # Limit to 10 per search term
                            cve_detail = await self._get_cve_details(cve_id)
                            if cve_detail:
                                vulnerabilities.append(cve_detail)
        
        except Exception as e:
            self.logger.warning(f"MITRE web search failed: {e}")
        
        return vulnerabilities
    
    def _extract_cve_ids_from_html(self, html: str) -> List[str]:
        """Extract CVE IDs from HTML response"""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        matches = re.findall(cve_pattern, html)
        return list(set(matches))  # Remove duplicates
    
    async def _get_cve_details(self, cve_id: str) -> Optional[MITREVulnerability]:
        """Get detailed information for a specific CVE"""
        try:
            session = await self._get_session()
            
            # Try API first
            api_url = f"{self.base_url}/2.0/{cve_id}"
            
            async with session.get(api_url) as response:
                if response.status == 200:
                    data = await response.json()
                    return self._parse_api_cve(data)
            
            # Fallback to web scraping
            web_url = f"{self.web_base_url}/cgi-bin/cvename.cgi?name={cve_id}"
            
            async with session.get(web_url) as response:
                if response.status == 200:
                    html = await response.text()
                    return self._parse_web_cve(cve_id, html)
        
        except Exception as e:
            self.logger.warning(f"Failed to get details for {cve_id}: {e}")
        
        return None
    
    def _parse_api_cve(self, cve_data: dict) -> Optional[MITREVulnerability]:
        """Parse CVE data from API response"""
        try:
            cve_info = cve_data.get("cveMetadata", {})
            containers = cve_data.get("containers", {})
            
            cve_id = cve_info.get("cveId", "")
            if not cve_id:
                return None
            
            # Extract basic information
            description = ""
            if "adp" in containers:
                for adp in containers["adp"]:
                    if "descriptions" in adp:
                        for desc in adp["descriptions"]:
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")
                                break
            
            if not description and "cna" in containers:
                cna = containers["cna"]
                if "descriptions" in cna:
                    for desc in cna["descriptions"]:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
            
            # Parse dates
            published_date = None
            modified_date = None
            
            if "datePublished" in cve_info:
                published_date = datetime.fromisoformat(cve_info["datePublished"].replace("Z", "+00:00"))
            if "dateUpdated" in cve_info:
                modified_date = datetime.fromisoformat(cve_info["dateUpdated"].replace("Z", "+00:00"))
            
            # Extract references
            references = []
            if "cna" in containers and "references" in containers["cna"]:
                for ref in containers["cna"]["references"]:
                    url = ref.get("url", "")
                    if url:
                        references.append(MITREReference(
                            url=url,
                            name=ref.get("name"),
                            tags=ref.get("tags", [])
                        ))
            
            # Extract metrics (CVSS)
            metrics = None
            if "cna" in containers and "metrics" in containers["cna"]:
                for metric in containers["cna"]["metrics"]:
                    if "cvssV3_1" in metric:
                        cvss = metric["cvssV3_1"]
                        metrics = MITREMetrics(
                            cvss_version="3.1",
                            cvss_vector=cvss.get("vectorString"),
                            base_score=cvss.get("baseScore"),
                            base_severity=cvss.get("baseSeverity"),
                            exploitability_score=cvss.get("exploitabilityScore"),
                            impact_score=cvss.get("impactScore")
                        )
                        break
            
            # Extract weaknesses (CWE)
            weaknesses = []
            if "cna" in containers and "problemTypes" in containers["cna"]:
                for problem in containers["cna"]["problemTypes"]:
                    for desc in problem.get("descriptions", []):
                        cwe_id = desc.get("cweId")
                        if cwe_id:
                            weaknesses.append(MITREWeakness(
                                cwe_id=cwe_id,
                                description=desc.get("description", "")
                            ))
            
            # Extract affected products/vendors
            affected_vendors = []
            affected_products = []
            if "cna" in containers and "affected" in containers["cna"]:
                for affected in containers["cna"]["affected"]:
                    vendor = affected.get("vendor")
                    product = affected.get("product")
                    if vendor:
                        affected_vendors.append(vendor)
                    if product:
                        affected_products.append(product)
            
            return MITREVulnerability(
                cve_id=cve_id,
                description=description,
                status=MITREStatus.PUBLISHED,
                assigner=cve_info.get("assignerOrgId"),
                published_date=published_date,
                last_modified=modified_date,
                references=references,
                metrics=metrics,
                weaknesses=weaknesses,
                affected_vendors=list(set(affected_vendors)),
                affected_products=list(set(affected_products))
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to parse API CVE data: {e}")
            return None
    
    def _parse_web_cve(self, cve_id: str, html: str) -> Optional[MITREVulnerability]:
        """Parse CVE data from web page (basic extraction)"""
        try:
            # Extract description
            desc_match = re.search(r'<td[^>]*>\s*Description\s*</td>\s*<td[^>]*>(.*?)</td>', html, re.DOTALL | re.IGNORECASE)
            description = ""
            if desc_match:
                description = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip()
            
            # Extract references
            references = []
            ref_matches = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>([^<]+)</a>', html)
            for url, name in ref_matches:
                if url.startswith('http'):
                    references.append(MITREReference(url=url, name=name))
            
            return MITREVulnerability(
                cve_id=cve_id,
                description=description,
                references=references,
                published_date=datetime.utcnow()  # Placeholder
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to parse web CVE data for {cve_id}: {e}")
            return None
    
    async def _enhance_results_with_ai(
        self, 
        cve_info: MITRECVEInfo, 
        package_name: str, 
        current_version: Optional[str]
    ) -> MITRECVEInfo:
        """Enhance CVE results with AI analysis"""
        if not self.ai_layer or not cve_info.vulnerabilities:
            return cve_info
        
        try:
            # Analyze each CVE with AI
            for vuln in cve_info.vulnerabilities:
                ai_analysis = await self._get_ai_cve_analysis(vuln, package_name, current_version)
                if ai_analysis:
                    vuln.ai_severity_assessment = ai_analysis.get('severity')
                    vuln.ai_confidence = ai_analysis.get('confidence', 0.5)
                    vuln.ai_exploitability = ai_analysis.get('exploitability')
                    vuln.ai_relevance_score = ai_analysis.get('relevance_score', 0.5)
                    vuln.ai_recommendation = ai_analysis.get('recommendation')
                    vuln.ai_reasoning = ai_analysis.get('reasoning')
                    vuln.ai_attack_vectors = ai_analysis.get('attack_vectors', [])
                    vuln.ai_business_impact = ai_analysis.get('business_impact')
            
            # Get overall AI insights for the search results
            overall_analysis = await self._get_ai_overall_analysis(cve_info, package_name)
            if overall_analysis:
                cve_info.ai_search_relevance = overall_analysis.get('search_relevance')
                cve_info.ai_priority_ranking = overall_analysis.get('priority_ranking', [])
                cve_info.ai_search_summary = overall_analysis.get('search_summary')
                cve_info.ai_recommended_actions = overall_analysis.get('recommended_actions', [])
            
        except Exception as e:
            self.logger.warning(f"AI enhancement failed: {e}")
        
        return cve_info
    
    async def _get_ai_cve_analysis(
        self, 
        vuln: MITREVulnerability, 
        package_name: str, 
        current_version: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Get AI analysis for a specific CVE"""
        try:
            from ...ai_layer.agents.cve_analyzer import CVEAnalyzer
            
            analyzer = CVEAnalyzer(self.ai_layer)
            
            # Use the CVE analyzer
            analysis_result = await analyzer.analyze_cve(
                cve_id=vuln.cve_id,
                cve_description=vuln.description,
                package_name=package_name,
                current_version=current_version,
                cvss_score=vuln.metrics.base_score if vuln.metrics else None,
                published_date=vuln.published_date,
                affected_products=", ".join(vuln.affected_products) if vuln.affected_products else None
            )
            
            return {
                'severity': analysis_result.severity,
                'confidence': analysis_result.confidence,
                'exploitability': self._assess_exploitability(vuln),
                'relevance_score': self._calculate_relevance_score(vuln, package_name),
                'recommendation': analysis_result.recommendation,
                'reasoning': analysis_result.reasoning,
                'attack_vectors': self._extract_attack_vectors(vuln),
                'business_impact': self._assess_business_impact(vuln, analysis_result.severity)
            }
            
        except Exception as e:
            self.logger.warning(f"AI CVE analysis failed for {vuln.cve_id}: {e}")
            return None
    
    async def _get_ai_overall_analysis(
        self, 
        cve_info: MITRECVEInfo, 
        package_name: str
    ) -> Optional[Dict[str, Any]]:
        """Get AI analysis for overall search results"""
        try:
            if not self.ai_layer:
                return None
            
            from ...ai_layer.chain_factory import get_ai_factory
            
            factory = get_ai_factory()
            llm = factory.get_chat_llm()
            
            # Create summary of CVEs for AI analysis
            cve_summary = []
            for vuln in cve_info.vulnerabilities[:10]:  # Limit to top 10
                summary = {
                    "cve_id": vuln.cve_id,
                    "description": vuln.description[:200] + "..." if len(vuln.description) > 200 else vuln.description,
                    "severity": vuln.ai_severity_assessment.value if vuln.ai_severity_assessment else "Unknown",
                    "relevance": vuln.ai_relevance_score or 0.5
                }
                cve_summary.append(summary)
            
            prompt = f"""
            Analyze the following CVE search results for the Python package "{package_name}":
            
            Total CVEs found: {len(cve_info.vulnerabilities)}
            
            Top CVEs:
            {json.dumps(cve_summary, indent=2)}
            
            Provide:
            1. Search relevance score (0.0-1.0) - how relevant are these results to the package
            2. Priority ranking - list the top 5 CVE IDs in order of priority
            3. Search summary - brief overview of findings
            4. Recommended actions - list of 3-5 specific actions
            
            Format as JSON with keys: search_relevance, priority_ranking, search_summary, recommended_actions
            """
            
            response = await llm.ainvoke(prompt)
            
            # Parse JSON response
            try:
                analysis = json.loads(response.content)
                return analysis
            except json.JSONDecodeError:
                # Fallback parsing
                return {
                    'search_relevance': 0.7,
                    'priority_ranking': [v.cve_id for v in cve_info.vulnerabilities[:5]],
                    'search_summary': f"Found {len(cve_info.vulnerabilities)} CVEs potentially related to {package_name}",
                    'recommended_actions': ["Review high-severity CVEs", "Check for patches", "Monitor for updates"]
                }
            
        except Exception as e:
            self.logger.warning(f"AI overall analysis failed: {e}")
            return None
    
    def _assess_exploitability(self, vuln: MITREVulnerability) -> str:
        """Assess exploitability based on CVE characteristics"""
        if vuln.metrics and vuln.metrics.exploitability_score:
            if vuln.metrics.exploitability_score >= 3.0:
                return "High"
            elif vuln.metrics.exploitability_score >= 2.0:
                return "Medium"
            else:
                return "Low"
        
        # Fallback based on description keywords
        description_lower = vuln.description.lower()
        if any(keyword in description_lower for keyword in ["remote", "unauthenticated", "buffer overflow"]):
            return "High"
        elif any(keyword in description_lower for keyword in ["authenticated", "local"]):
            return "Medium"
        else:
            return "Low"
    
    def _calculate_relevance_score(self, vuln: MITREVulnerability, package_name: str) -> float:
        """Calculate relevance score for a CVE"""
        score = 0.0
        description_lower = vuln.description.lower()
        package_lower = package_name.lower()
        
        # Direct package name mention
        if package_lower in description_lower:
            score += 0.8
        
        # Product/vendor mention
        if any(package_lower in prod.lower() for prod in vuln.affected_products):
            score += 0.6
        
        # Python-related keywords
        if any(keyword in description_lower for keyword in ["python", "pip", "pypi"]):
            score += 0.3
        
        # Recent CVE (more relevant)
        if vuln.published_date and vuln.published_date > datetime.utcnow() - timedelta(days=365):
            score += 0.2
        
        return min(score, 1.0)
    
    def _extract_attack_vectors(self, vuln: MITREVulnerability) -> List[str]:
        """Extract attack vectors from CVE information"""
        vectors = []
        
        if vuln.metrics and vuln.metrics.cvss_vector:
            # Parse CVSS vector for attack vector info
            vector_str = vuln.metrics.cvss_vector
            if "AV:N" in vector_str:
                vectors.append("Network")
            elif "AV:A" in vector_str:
                vectors.append("Adjacent Network")
            elif "AV:L" in vector_str:
                vectors.append("Local")
            elif "AV:P" in vector_str:
                vectors.append("Physical")
        
        # Extract from description
        description_lower = vuln.description.lower()
        if "remote" in description_lower:
            vectors.append("Remote")
        if "local" in description_lower:
            vectors.append("Local")
        if "web" in description_lower or "http" in description_lower:
            vectors.append("Web Application")
        
        return list(set(vectors))
    
    def _assess_business_impact(self, vuln: MITREVulnerability, severity: SeverityLevel) -> str:
        """Assess business impact based on CVE characteristics"""
        if severity == SeverityLevel.CRITICAL:
            return "Critical - Immediate business risk"
        elif severity == SeverityLevel.HIGH:
            return "High - Significant business impact"
        elif severity == SeverityLevel.MEDIUM:
            return "Medium - Moderate business impact"
        else:
            return "Low - Minor business impact"
    
    def _is_relevant_to_package(
        self, 
        vuln: MITREVulnerability, 
        package_name: str, 
        current_version: Optional[str]
    ) -> bool:
        """Determine if a CVE is relevant to the specified package"""
        # Use AI relevance score if available
        if vuln.ai_relevance_score is not None:
            return vuln.ai_relevance_score >= 0.3
        
        # Fallback to basic relevance checking
        package_lower = package_name.lower()
        description_lower = vuln.description.lower()
        
        # Direct mention
        if package_lower in description_lower:
            return True
        
        # Product mention
        if any(package_lower in prod.lower() for prod in vuln.affected_products):
            return True
        
        # Vendor mention (less reliable)
        if any(package_lower in vendor.lower() for vendor in vuln.affected_vendors):
            return True
        
        return False
    
    async def health_check(self) -> bool:
        """Check if MITRE sandbox is healthy"""
        try:
            session = await self._get_session()
            
            # Test API connectivity
            async with session.get(f"{self.base_url}/2.0") as response:
                if response.status in [200, 400]:  # 400 is expected for no query params
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"MITRE health check failed: {e}")
            return False
    
    async def close(self):
        """Clean up resources"""
        if self._session and not self._session.closed:
            await self._session.close()
        
        self.logger.info("MITRE sandbox closed")