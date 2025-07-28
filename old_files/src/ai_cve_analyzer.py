#!/usr/bin/env python3
"""
AI-powered CVE (Common Vulnerabilities and Exposures) Analyzer
Uses OpenAI API to analyze CVE results and assess version-specific impacts
"""

import os
import logging
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime
import json

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv is optional

try:
    import openai
except ImportError:
    openai = None


class AICVEAnalyzer:
    """AI-powered CVE analyzer using OpenAI API (Standard or Azure)"""
    
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, 
                 azure_endpoint: Optional[str] = None, api_version: Optional[str] = None):
        """Initialize CVE analyzer with Azure OpenAI API key authentication
        
        Args:
            api_key: Azure OpenAI API key
            model: Azure deployment name (e.g., gpt-4.1)
            azure_endpoint: Azure OpenAI endpoint URL
            api_version: Azure API version
        """
        self.logger = logging.getLogger(__name__)
        self.is_azure = True  # Always use Azure OpenAI
        
        # Set up API key
        self.api_key = api_key or os.getenv('AZURE_OPENAI_KEY')
        
        # Set up Azure endpoint
        self.azure_endpoint = azure_endpoint or os.getenv('AZURE_OPENAI_ENDPOINT')
        
        # Set up model (deployment name)
        self.model = model or os.getenv('AZURE_OPENAI_MODEL')
        
        # Set up API version
        self.api_version = api_version or os.getenv('AZURE_OPENAI_API_VERSION')
        
        if not self.api_key:
            self.logger.warning("Azure OpenAI API key not provided. AI CVE analysis will be disabled.")
            self.enabled = False
            return
            
        if not self.azure_endpoint:
            self.logger.warning("Azure OpenAI endpoint not provided. AI CVE analysis will be disabled.")
            self.enabled = False
            return
            
        if not self.model:
            self.logger.warning("Azure OpenAI model/deployment not provided. AI CVE analysis will be disabled.")
            self.enabled = False
            return
            
        if not openai:
            self.logger.warning("OpenAI library not installed. AI CVE analysis will be disabled.")
            self.enabled = False
            return
            
        # Configure Azure OpenAI client with API key authentication
        try:
            self.client = openai.AzureOpenAI(
                api_key=self.api_key,
                api_version=self.api_version,
                azure_endpoint=self.azure_endpoint
            )
            
            # Verify deployment is available with a test call
            self._verify_deployment()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Azure OpenAI client: {e}")
            self.enabled = False
    
    def _verify_deployment(self):
        """Verify that the deployment is available with a test call"""
        try:
            self.logger.info(f"Verifying Azure OpenAI deployment: {self.model}")
            test_response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5,
                temperature=0
            )
            
            if test_response.choices:
                self.logger.info(f"✅ AI CVE Analyzer verified - Deployment: {self.model}, API Version: {self.api_version}")
                self.enabled = True
            else:
                self.logger.error("Test call succeeded but no response received")
                self.enabled = False
                
        except Exception as e:
            self.logger.error(f"Deployment verification failed: {e}")
            if "DeploymentNotFound" in str(e):
                self.logger.error(f"❌ Deployment '{self.model}' not found in Azure OpenAI resource")
            self.enabled = False
    
    def is_enabled(self) -> bool:
        """Check if AI analysis is available"""
        return self.enabled
    
    async def analyze_cve_result(self, package_name: str, current_version: str, 
                               cve_lookup_url: str, raw_cve_data: str = None) -> str:
        """
        Analyze CVE results using AI and assess impact on current version
        
        Args:
            package_name: Name of the Python package
            current_version: Currently installed version
            cve_lookup_url: MITRE CVE lookup URL that was searched
            raw_cve_data: Raw data from CVE lookup (optional)
        
        Returns:
            AI-analyzed result with version-specific impact assessment
        """
        if not self.enabled:
            return "AI analysis not available - manual review required"
            
        try:
            # Create analysis prompt
            prompt = self._create_analysis_prompt(
                package_name, current_version, cve_lookup_url, raw_cve_data
            )
            
            # Call OpenAI API
            response = await self._call_openai_api(prompt)
            
            if response:
                self.logger.debug(f"AI CVE analysis completed for {package_name} v{current_version}")
                return response
            else:
                return f"AI analysis failed - manual review required for {package_name} v{current_version}"
                
        except Exception as e:
            self.logger.error(f"Error in AI CVE analysis for {package_name}: {e}")
            return f"AI analysis error - manual review required: {str(e)}"
    
    async def analyze_snyk_result(self, package_name: str, current_version: str, 
                                snyk_lookup_url: str, raw_snyk_data: str = None) -> str:
        """
        Analyze SNYK vulnerability results using AI and assess impact on current version
        
        Args:
            package_name: Name of the Python package
            current_version: Currently installed version
            snyk_lookup_url: SNYK vulnerability lookup URL that was searched
            raw_snyk_data: Raw data from SNYK lookup (optional)
        
        Returns:
            AI-analyzed result with version-specific impact assessment
        """
        if not self.enabled:
            return "AI analysis not available - manual review required"
            
        try:
            # Create SNYK-specific analysis prompt
            prompt = self._create_snyk_analysis_prompt(
                package_name, current_version, snyk_lookup_url, raw_snyk_data
            )
            
            # Call OpenAI API
            response = await self._call_openai_api(prompt)
            
            if response:
                self.logger.debug(f"AI SNYK analysis completed for {package_name} v{current_version}")
                return response
            else:
                return f"AI SNYK analysis failed - manual review required for {package_name} v{current_version}"
                
        except Exception as e:
            self.logger.error(f"Error in AI SNYK analysis for {package_name}: {e}")
            return f"AI SNYK analysis error - manual review required: {str(e)}"
    
    async def analyze_exploit_db_result(self, package_name: str, current_version: str, 
                                      exploit_db_lookup_url: str, raw_exploit_data: str = None) -> str:
        """
        Analyze Exploit Database results using AI and assess impact on current version
        
        Args:
            package_name: Name of the Python package
            current_version: Currently installed version
            exploit_db_lookup_url: Exploit Database lookup URL that was searched
            raw_exploit_data: Raw data from Exploit Database lookup (optional)
        
        Returns:
            AI-analyzed result with version-specific impact assessment
        """
        if not self.enabled:
            return "AI analysis not available - manual review required"
            
        try:
            # Create Exploit Database-specific analysis prompt
            prompt = self._create_exploit_db_analysis_prompt(
                package_name, current_version, exploit_db_lookup_url, raw_exploit_data
            )
            
            # Call OpenAI API
            response = await self._call_openai_api(prompt)
            
            if response:
                self.logger.debug(f"AI Exploit Database analysis completed for {package_name} v{current_version}")
                return response
            else:
                return f"AI Exploit Database analysis failed - manual review required for {package_name} v{current_version}"
                
        except Exception as e:
            self.logger.error(f"Error in AI Exploit Database analysis for {package_name}: {e}")
            return f"AI Exploit Database analysis error - manual review required: {str(e)}"
    
    async def analyze_nist_nvd_result(self, package_name: str, current_version: str, 
                                     nist_nvd_url: str, raw_nist_data: str = None) -> str:
        """
        Analyze NIST NVD vulnerability results using AI and assess impact on current version
        
        Args:
            package_name: Name of the Python package
            current_version: Currently installed version
            nist_nvd_url: NIST NVD lookup URL that was searched
            raw_nist_data: Raw data from NIST NVD lookup (optional)
        
        Returns:
            AI-analyzed result with version-specific impact assessment
        """
        if not self.enabled:
            return "AI analysis not available - manual review required"
            
        try:
            # Create NIST NVD-specific analysis prompt
            prompt = self._create_nist_nvd_analysis_prompt(
                package_name, current_version, nist_nvd_url, raw_nist_data
            )
            
            # Call OpenAI API
            response = await self._call_openai_api(prompt)
            
            if response:
                self.logger.debug(f"AI NIST NVD analysis completed for {package_name} v{current_version}")
                return response
            else:
                return f"AI NIST NVD analysis failed - manual review required for {package_name} v{current_version}"
                
        except Exception as e:
            self.logger.error(f"Error in AI NIST NVD analysis for {package_name}: {e}")
            return f"AI NIST NVD analysis error - manual review required: {str(e)}"

    async def analyze_github_advisory_result(self, package_name: str, current_version: str, 
                                           github_advisory_url: str, raw_github_data: str = None) -> str:
        """
        Analyze GitHub Security Advisory results using AI and assess impact on current version
        
        Args:
            package_name: Name of the Python package
            current_version: Currently installed version
            github_advisory_url: GitHub Security Advisory lookup URL that was searched
            raw_github_data: Raw data from GitHub Security Advisory lookup (optional)
        
        Returns:
            AI-analyzed result with version-specific impact assessment
        """
        if not self.enabled:
            return "AI analysis not available - manual review required"
            
        try:
            # Create GitHub Security Advisory-specific analysis prompt
            prompt = self._create_github_advisory_analysis_prompt(
                package_name, current_version, github_advisory_url, raw_github_data
            )
            
            # Call OpenAI API
            response = await self._call_openai_api(prompt)
            
            if response:
                self.logger.debug(f"AI GitHub Security Advisory analysis completed for {package_name} v{current_version}")
                return response
            else:
                return f"AI GitHub Security Advisory analysis failed - manual review required for {package_name} v{current_version}"
                
        except Exception as e:
            self.logger.error(f"Error in AI GitHub Security Advisory analysis for {package_name}: {e}")
            return f"AI GitHub Security Advisory analysis error - manual review required: {str(e)}"
    
    def _create_analysis_prompt(self, package_name: str, current_version: str, 
                              cve_lookup_url: str, raw_cve_data: str = None) -> str:
        """Create AI analysis prompt for CVE assessment"""
        
        base_prompt = f"""
You are a cybersecurity expert analyzing CVE (Common Vulnerabilities and Exposures) data for Python packages. 

PACKAGE INFORMATION:
- Package Name: {package_name}
- Current Version: {current_version}
- CVE Lookup URL: {cve_lookup_url}

TASK:
Analyze the CVE information for this specific package and version. Provide a concise assessment that includes:

1. VULNERABILITY STATUS: Are there any CVEs that affect the current version {current_version}?
2. SEVERITY ASSESSMENT: If vulnerabilities exist, what is the highest severity level?
3. VERSION IMPACT: Does the current version {current_version} have known vulnerabilities?
4. RISK ASSESSMENT: What is the overall risk level for this version?
5. RECOMMENDATION: Should this version be updated or is it safe to use?

RESPONSE FORMAT:
Provide a concise response (2-3 sentences max) in this format:
"CVE Analysis: [FOUND/NOT_FOUND] - [Brief summary]. Severity: [CRITICAL/HIGH/MEDIUM/LOW/NONE]. Current version {current_version}: [AFFECTED/NOT_AFFECTED]. Recommendation: [ACTION_NEEDED/MONITOR/SAFE_TO_USE]"

GUIDELINES:
- Be specific about version impact
- Focus on the current version {current_version}, not future versions
- Use clear, actionable language
- If no specific version information is available, state "version impact unclear"
- Prioritize security over convenience
"""
        
        # Add raw CVE data if available
        if raw_cve_data:
            base_prompt += f"\n\nRAW CVE DATA:\n{raw_cve_data[:2000]}..."  # Limit to avoid token limits
            
        return base_prompt
    
    def _create_snyk_analysis_prompt(self, package_name: str, current_version: str, 
                                   snyk_lookup_url: str, raw_snyk_data: str = None) -> str:
        """Create AI analysis prompt for SNYK vulnerability assessment"""
        
        base_prompt = f"""
You are a cybersecurity expert analyzing SNYK vulnerability data for Python packages. 

PACKAGE INFORMATION:
- Package Name: {package_name}
- Current Version: {current_version}
- SNYK Lookup URL: {snyk_lookup_url}

TASK:
Analyze the SNYK vulnerability information for this specific package and version. SNYK is a specialized security platform that provides detailed vulnerability analysis for open source packages. Provide a concise assessment that includes:

1. VULNERABILITY STATUS: Are there any vulnerabilities in SNYK database that affect the current version {current_version}?
2. SEVERITY ASSESSMENT: If vulnerabilities exist, what is the highest severity level according to SNYK?
3. VERSION IMPACT: Does the current version {current_version} have known vulnerabilities in SNYK?
4. RISK ASSESSMENT: What is the overall security risk level for this version based on SNYK data?
5. RECOMMENDATION: Should this version be updated or is it safe to use according to SNYK analysis?

RESPONSE FORMAT:
Provide a concise response (2-3 sentences max) in this format:
"SNYK Analysis: [FOUND/NOT_FOUND] - [Brief summary]. Severity: [CRITICAL/HIGH/MEDIUM/LOW/NONE]. Current version {current_version}: [AFFECTED/NOT_AFFECTED]. Recommendation: [ACTION_NEEDED/MONITOR/SAFE_TO_USE]"

GUIDELINES:
- Be specific about version impact based on SNYK vulnerability database
- Focus on the current version {current_version}, not future versions
- Use clear, actionable language for security recommendations
- If no specific version information is available, state "version impact unclear"
- Consider SNYK's reputation for accurate vulnerability detection
- Prioritize security over convenience
"""
        
        # Add raw SNYK data if available
        if raw_snyk_data:
            base_prompt += f"\n\nRAW SNYK DATA:\n{raw_snyk_data[:2000]}..."  # Limit to avoid token limits
            
        return base_prompt
    
    def _create_exploit_db_analysis_prompt(self, package_name: str, current_version: str, 
                                         exploit_db_lookup_url: str, raw_exploit_data: str = None) -> str:
        """Create AI analysis prompt for Exploit Database assessment"""
        
        base_prompt = f"""
You are a cybersecurity expert analyzing Exploit Database (exploit-db.com) data for Python packages. 

PACKAGE INFORMATION:
- Package Name: {package_name}
- Current Version: {current_version}
- Exploit Database Lookup URL: {exploit_db_lookup_url}

TASK:
Analyze the Exploit Database information for this specific package and version. Exploit Database is a comprehensive archive of public exploits and corresponding vulnerable software. Provide a concise assessment that includes:

1. EXPLOIT STATUS: Are there any public exploits in Exploit Database that affect the current version {current_version}?
2. SEVERITY ASSESSMENT: If exploits exist, what is the highest risk level based on exploit availability?
3. VERSION IMPACT: Does the current version {current_version} have known public exploits?
4. RISK ASSESSMENT: What is the overall security risk level considering exploit availability?
5. RECOMMENDATION: Should this version be updated urgently given exploit availability?

RESPONSE FORMAT:
Provide a concise response (2-3 sentences max) in this format:
"Exploit Database Analysis: [FOUND/NOT_FOUND] - [Brief summary]. Severity: [CRITICAL/HIGH/MEDIUM/LOW/NONE]. Current version {current_version}: [AFFECTED/NOT_AFFECTED]. Recommendation: [URGENT_UPDATE/ACTION_NEEDED/MONITOR/SAFE_TO_USE]"

GUIDELINES:
- Focus on PUBLIC EXPLOITS which represent immediate actionable threats
- Be specific about version impact based on Exploit Database records
- Consider that exploit availability significantly increases risk severity
- Use clear, urgent language if public exploits are found
- If no specific version information is available, state "version impact unclear"
- Prioritize immediate security action when exploits are publicly available
- Remember that Exploit Database focuses on proven, working exploits
"""
        
        # Add raw Exploit Database data if available
        if raw_exploit_data:
            base_prompt += f"\n\nRAW EXPLOIT DATABASE DATA:\n{raw_exploit_data[:2000]}..."  # Limit to avoid token limits
            
        return base_prompt
    
    def _create_github_advisory_analysis_prompt(self, package_name: str, current_version: str, 
                                               github_advisory_url: str, raw_github_data: str = None) -> str:
        """Create AI analysis prompt for GitHub Security Advisory assessment"""
        
        base_prompt = f"""
You are a cybersecurity expert analyzing GitHub Security Advisory data for Python packages. 

PACKAGE INFORMATION:
- Package Name: {package_name}
- Current Version: {current_version}
- GitHub Advisory URL: {github_advisory_url}

TASK:
Analyze the GitHub Security Advisory information for this specific package and version. GitHub Security Advisories are a comprehensive database of vulnerabilities reported by the GitHub community and maintainers. Provide a concise assessment that includes:

1. ADVISORY STATUS: Are there any security advisories in GitHub that affect the current version {current_version}?
2. SEVERITY ASSESSMENT: If advisories exist, what is the highest severity level reported?
3. VERSION IMPACT: Does the current version {current_version} have known security advisories?
4. RISK ASSESSMENT: What is the overall security risk level based on GitHub Advisory data?
5. RECOMMENDATION: Should this version be updated based on GitHub Security Advisory findings?

RESPONSE FORMAT:
Provide a concise response (2-3 sentences max) in this format:
"GitHub Security Advisory Analysis: [FOUND/NOT_FOUND] - [Brief summary]. Severity: [CRITICAL/HIGH/MEDIUM/LOW/NONE]. Current version {current_version}: [AFFECTED/NOT_AFFECTED]. Recommendation: [ACTION_NEEDED/MONITOR/SAFE_TO_USE]"

GUIDELINES:
- Focus on SECURITY ADVISORIES which represent reported vulnerabilities
- Be specific about version impact based on GitHub Advisory records
- Consider that GitHub Advisories often include detailed remediation guidance
- Use clear, actionable language for security recommendations
- If no specific version information is available, state "version impact unclear"
- Prioritize security best practices and community-reported vulnerabilities
- Remember that GitHub Advisories are often the first place vulnerabilities are disclosed
"""
        
        # Add raw GitHub Advisory data if available
        if raw_github_data:
            base_prompt += f"\n\nRAW GITHUB ADVISORY DATA:\n{raw_github_data[:2000]}..."  # Limit to avoid token limits
            
        return base_prompt
    
    def _create_nist_nvd_analysis_prompt(self, package_name: str, current_version: str, 
                                        nist_nvd_url: str, raw_nist_data: str = None) -> str:
        """Create AI analysis prompt for NIST NVD vulnerability assessment"""
        
        base_prompt = f"""
You are a cybersecurity expert analyzing NIST NVD (National Vulnerability Database) data for Python packages. 

PACKAGE INFORMATION:
- Package Name: {package_name}
- Current Version: {current_version}
- NIST NVD URL: {nist_nvd_url}

TASK:
Analyze the NIST NVD vulnerability information for this specific package and version. NIST NVD is the authoritative U.S. government repository of standards-based vulnerability management data. Provide a concise assessment that includes:

1. VULNERABILITY STATUS: Are there any CVEs in NIST NVD that affect the current version {current_version}?
2. SEVERITY ASSESSMENT: If vulnerabilities exist, what is the highest CVSS severity level?
3. VERSION IMPACT: Does the current version {current_version} have known vulnerabilities in NIST NVD?
4. RISK ASSESSMENT: What is the overall security risk level based on NIST NVD data?
5. RECOMMENDATION: Should this version be updated based on NIST NVD findings?

RESPONSE FORMAT:
Provide a concise response (2-3 sentences max) in this format:
"NIST NVD Analysis: [FOUND/NOT_FOUND] - [Brief summary]. Severity: [CRITICAL/HIGH/MEDIUM/LOW/NONE]. Current version {current_version}: [AFFECTED/NOT_AFFECTED]. Recommendation: [ACTION_NEEDED/MONITOR/SAFE_TO_USE]"

GUIDELINES:
- Focus on CVEs with CVSS scores which represent official vulnerability assessments
- Be specific about version impact based on NIST NVD vulnerability records
- Consider NIST NVD's role as the official U.S. government vulnerability database
- Use clear, actionable language for security recommendations
- If no specific version information is available, state "version impact unclear"
- Prioritize security based on official CVSS scoring and severity levels
- Remember that NIST NVD provides the most authoritative vulnerability data
"""
        
        # Add raw NIST NVD data if available
        if raw_nist_data:
            base_prompt += f"\n\nRAW NIST NVD DATA:\n{raw_nist_data[:2000]}..."  # Limit to avoid token limits
            
        return base_prompt
    
    async def _call_openai_api(self, prompt: str) -> Optional[str]:
        """Call OpenAI API with error handling and rate limiting"""
        try:
            # Add a longer delay to respect rate limits and avoid deployment issues
            await asyncio.sleep(2.0)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a cybersecurity expert specializing in Python package vulnerability analysis. Provide concise, accurate CVE assessments."
                    },
                    {
                        "role": "user", 
                        "content": prompt
                    }
                ],
                max_tokens=300,
                temperature=0.1,  # Low temperature for consistent, factual responses
                timeout=30
            )
            
            if response.choices and response.choices[0].message:
                return response.choices[0].message.content.strip()
            else:
                self.logger.warning("Empty response from OpenAI API")
                return None
                
        except Exception as e:
            self.logger.error(f"OpenAI API call failed: {e}")
            self.logger.error(f"API Configuration - Model: {self.model}, Endpoint: {self.azure_endpoint}, API Version: {self.api_version}")
            
            # If deployment not found, wait longer and retry once
            if "DeploymentNotFound" in str(e):
                self.logger.warning("Deployment not found - waiting 5 seconds and retrying once...")
                await asyncio.sleep(5.0)
                try:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system", 
                                "content": "You are a cybersecurity expert specializing in Python package vulnerability analysis. Provide concise, accurate CVE assessments."
                            },
                            {
                                "role": "user", 
                                "content": prompt
                            }
                        ],
                        max_tokens=300,
                        temperature=0.1,
                        timeout=30
                    )
                    
                    if response.choices and response.choices[0].message:
                        self.logger.info("Retry successful after deployment error")
                        return response.choices[0].message.content.strip()
                except Exception as retry_e:
                    self.logger.error(f"Retry also failed: {retry_e}")
            
            return None
    
    def analyze_multiple_cves(self, package_name: str, current_version: str, 
                            cve_results: Dict[str, Any]) -> str:
        """
        Analyze multiple CVE results and provide consolidated assessment
        
        Args:
            package_name: Name of the Python package
            current_version: Currently installed version
            cve_results: Dictionary containing CVE results from multiple sources
        
        Returns:
            Consolidated AI analysis
        """
        if not self.enabled:
            return "AI analysis not available - manual review required"
            
        try:
            # Extract CVE information from multiple sources
            cve_summary = self._extract_cve_summary(cve_results)
            
            # Create comprehensive analysis prompt
            prompt = f"""
Analyze CVE information for {package_name} version {current_version}.

CVE SOURCES SUMMARY:
{cve_summary}

Provide a consolidated security assessment focusing on:
1. Overall vulnerability status for version {current_version}
2. Highest severity level found
3. Specific version impact
4. Actionable recommendation

Response format: "Multi-source CVE Analysis: [status] - [summary]. Severity: [level]. Version {current_version}: [impact]. Action: [recommendation]"
"""
            
            # This would be async in practice, but keeping simpler for now
            return f"Multi-source analysis pending for {package_name} v{current_version} - manual review recommended"
            
        except Exception as e:
            self.logger.error(f"Error in multi-CVE analysis: {e}")
            return f"Multi-source analysis failed - manual review required"
    
    def _extract_cve_summary(self, cve_results: Dict[str, Any]) -> str:
        """Extract and summarize CVE information from multiple sources"""
        summary_parts = []
        
        # Process MITRE CVE results
        if 'mitre_cve_result' in cve_results:
            summary_parts.append(f"MITRE: {cve_results['mitre_cve_result']}")
            
        # Process NIST NVD results  
        if 'nist_nvd_result' in cve_results:
            summary_parts.append(f"NIST NVD: {cve_results['nist_nvd_result']}")
            
        # Process other vulnerability sources
        for source in ['snyk_result', 'github_advisory_result']:
            if source in cve_results:
                summary_parts.append(f"{source.split('_')[0].upper()}: {cve_results[source]}")
        
        return "\n".join(summary_parts) if summary_parts else "No CVE data available"
    
    async def batch_analyze_packages(self, packages: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Perform batch AI analysis on multiple packages
        
        Args:
            packages: List of package dictionaries with CVE information
        
        Returns:
            Dictionary mapping package names to AI analysis results
        """
        if not self.enabled:
            return {}
            
        results = {}
        
        # Process packages in small batches to respect API limits
        batch_size = 5
        for i in range(0, len(packages), batch_size):
            batch = packages[i:i + batch_size]
            
            # Process batch concurrently
            tasks = []
            for package in batch:
                task = self.analyze_cve_result(
                    package.get('package_name', ''),
                    package.get('current_version', ''),
                    package.get('mitre_cve_url', ''),
                    package.get('raw_cve_data', None)
                )
                tasks.append(task)
            
            # Wait for batch completion
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Store results
            for package, result in zip(batch, batch_results):
                package_name = package.get('package_name', '')
                if isinstance(result, Exception):
                    results[package_name] = f"Analysis failed: {str(result)}"
                else:
                    results[package_name] = result
            
            # Rate limiting between batches
            if i + batch_size < len(packages):
                await asyncio.sleep(1)
        
        return results
    
    def get_analysis_stats(self) -> Dict[str, Any]:
        """Get statistics about AI analysis usage"""
        return {
            'enabled': self.enabled,
            'model': self.model if self.enabled else None,
            'api_key_configured': bool(self.api_key),
            'openai_library_available': openai is not None,
            'service_type': 'Azure OpenAI' if self.is_azure else 'Standard OpenAI',
            'azure_endpoint': self.azure_endpoint if self.is_azure else None,
            'api_version': self.api_version if self.is_azure else None
        }


# Example usage and testing functions
async def test_cve_analyzer():
    """Test function for CVE analyzer"""
    analyzer = AICVEAnalyzer()
    
    if not analyzer.is_enabled():
        print("❌ AI CVE Analyzer not available")
        return
        
    # Test analysis
    result = await analyzer.analyze_cve_result(
        package_name="requests",
        current_version="2.28.0",
        cve_lookup_url="https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=requests",
        raw_cve_data="Sample CVE data for testing"
    )
    
    print(f"✅ AI Analysis Result: {result}")


if __name__ == "__main__":
    # Run test
    asyncio.run(test_cve_analyzer())