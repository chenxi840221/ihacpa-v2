"""
AI Analyzer for IHACPA v2.0

Provides AI-enhanced analysis capabilities for security assessment,
recommendation generation, and GitHub security analysis.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
import json


class AIAnalyzer:
    """AI-powered analysis for security assessment and recommendations"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize AI analyzer.
        
        Args:
            config: AI configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.enabled = config.get('enabled', False)
        self.provider = config.get('provider', 'mock')
        self.model = config.get('model', 'gpt-4')
        
        # Initialize AI client based on provider
        self.client = None
        if self.enabled:
            self._initialize_client()
    
    def _initialize_client(self):
        """Initialize AI client based on provider configuration"""
        try:
            if self.provider == 'azure':
                self._initialize_azure_client()
            elif self.provider == 'openai':
                self._initialize_openai_client()
            elif self.provider == 'mock':
                self._initialize_mock_client()
            else:
                self.logger.warning(f"Unknown AI provider: {self.provider}")
                self.enabled = False
        except Exception as e:
            self.logger.error(f"Failed to initialize AI client: {e}")
            self.enabled = False
    
    def _initialize_azure_client(self):
        """Initialize Azure OpenAI client"""
        try:
            from openai import AzureOpenAI
            import os
            
            self.client = AzureOpenAI(
                api_key=os.getenv('AZURE_OPENAI_KEY'),
                api_version=self.config.get('azure_api_version', '2024-02-01'),
                azure_endpoint=os.getenv('AZURE_OPENAI_ENDPOINT')
            )
            self.logger.info("Azure OpenAI client initialized")
            
        except ImportError:
            self.logger.error("Azure OpenAI client not available - install openai package")
            self.enabled = False
        except Exception as e:
            self.logger.error(f"Azure OpenAI initialization failed: {e}")
            self.enabled = False
    
    def _initialize_openai_client(self):
        """Initialize standard OpenAI client"""
        try:
            from openai import OpenAI
            import os
            
            self.client = OpenAI(
                api_key=os.getenv('OPENAI_API_KEY')
            )
            self.logger.info("OpenAI client initialized")
            
        except ImportError:
            self.logger.error("OpenAI client not available - install openai package")
            self.enabled = False
        except Exception as e:
            self.logger.error(f"OpenAI initialization failed: {e}")
            self.enabled = False
    
    def _initialize_mock_client(self):
        """Initialize mock client for testing"""
        self.client = MockAIClient()
        self.logger.info("Mock AI client initialized")
    
    async def generate_recommendation(self, package_name: str, 
                                    vulnerability_results: Dict[str, Any]) -> Optional[str]:
        """
        Generate AI-powered security recommendation.
        
        Args:
            package_name: Name of the Python package
            vulnerability_results: Results from vulnerability scans
            
        Returns:
            AI-generated recommendation if successful, None otherwise
        """
        if not self.enabled or not self.client:
            return None
        
        try:
            self.logger.debug(f"Generating AI recommendation for {package_name}")
            
            # Prepare context for AI analysis
            context = self._prepare_recommendation_context(package_name, vulnerability_results)
            
            # Generate recommendation using AI
            if hasattr(self.client, 'generate_recommendation'):
                recommendation = await self.client.generate_recommendation(context)
            else:
                recommendation = await self._call_ai_api(
                    self._build_recommendation_prompt(context)
                )
            
            if recommendation:
                self.logger.debug(f"AI recommendation generated for {package_name}")
                return recommendation
            
            return None
            
        except Exception as e:
            self.logger.error(f"AI recommendation generation failed for {package_name}: {e}")
            return None
    
    async def analyze_github_security(self, package_name: str, current_version: str, 
                                    security_url: str) -> Optional[Dict[str, Any]]:
        """
        AI-powered GitHub security analysis.
        
        Args:
            package_name: Name of the Python package
            current_version: Current version being analyzed
            security_url: GitHub security advisories URL
            
        Returns:
            AI analysis results if successful, None otherwise
        """
        if not self.enabled or not self.client:
            return None
        
        try:
            self.logger.debug(f"Performing AI GitHub security analysis for {package_name}")
            
            # Prepare context for AI analysis
            context = {
                'package_name': package_name,
                'current_version': current_version,
                'security_url': security_url,
                'analysis_type': 'github_security'
            }
            
            # Perform AI analysis
            if hasattr(self.client, 'analyze_github_security'):
                result = await self.client.analyze_github_security(context)
            else:
                prompt = self._build_github_security_prompt(context)
                ai_response = await self._call_ai_api(prompt)
                result = self._parse_github_security_response(ai_response)
            
            if result:
                self.logger.debug(f"AI GitHub security analysis completed for {package_name}")
                return result
            
            return None
            
        except Exception as e:
            self.logger.error(f"AI GitHub security analysis failed for {package_name}: {e}")
            return None
    
    def _prepare_recommendation_context(self, package_name: str, 
                                      vulnerability_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare context for recommendation generation"""
        return {
            'package_name': package_name,
            'critical_vulnerabilities': vulnerability_results.get('critical_vulnerabilities', 0),
            'high_risk_vulnerabilities': vulnerability_results.get('high_risk_vulnerabilities', 0),
            'medium_risk_vulnerabilities': vulnerability_results.get('medium_risk_vulnerabilities', 0),
            'low_risk_vulnerabilities': vulnerability_results.get('low_risk_vulnerabilities', 0),
            'total_vulnerabilities': vulnerability_results.get('total_vulnerabilities', 0),
            'nvd_results': vulnerability_results.get('nvd_results', {}),
            'mitre_results': vulnerability_results.get('mitre_results', {}),
            'snyk_results': vulnerability_results.get('snyk_results', {}),
            'exploit_db_results': vulnerability_results.get('exploit_db_results', {}),
            'business_context': self.config.get('business_context', {})
        }
    
    def _build_recommendation_prompt(self, context: Dict[str, Any]) -> str:
        """Build prompt for recommendation generation"""
        package_name = context['package_name']
        critical = context['critical_vulnerabilities']
        high = context['high_risk_vulnerabilities']
        total = context['total_vulnerabilities']
        
        prompt = f"""
        As a cybersecurity expert, analyze the following Python package vulnerability scan results and provide a concise security recommendation:

        Package: {package_name}
        Critical Vulnerabilities: {critical}
        High-Risk Vulnerabilities: {high}
        Total Vulnerabilities: {total}

        Business Context:
        - Industry: {context.get('business_context', {}).get('industry', 'technology')}
        - Asset Criticality: {context.get('business_context', {}).get('asset_criticality', 'high')}
        - Data Sensitivity: {context.get('business_context', {}).get('data_sensitivity', 'confidential')}

        Provide a single, actionable recommendation (10 words or less) that indicates the urgency level:
        - CRITICAL - IMMEDIATE ACTION REQUIRED (for critical vulnerabilities)
        - HIGH RISK - UPDATE REQUIRED (for multiple high-risk vulnerabilities)
        - MODERATE RISK - REVIEW AND UPDATE (for moderate vulnerabilities)
        - LOW RISK - MONITOR (for low-risk vulnerabilities only)
        - PROCEED (for no significant vulnerabilities)

        Recommendation:
        """
        
        return prompt
    
    def _build_github_security_prompt(self, context: Dict[str, Any]) -> str:
        """Build prompt for GitHub security analysis"""
        prompt = f"""
        Analyze the GitHub Security Advisories for the Python package '{context['package_name']}' version {context['current_version']}.
        
        Security URL: {context['security_url']}
        
        Please provide:
        1. Whether vulnerabilities are found (true/false)
        2. Number of vulnerabilities found
        3. Maximum severity level (CRITICAL, HIGH, MEDIUM, LOW, NONE)
        4. Brief summary of findings
        
        Format your response as JSON:
        {{
            "vulnerabilities_found": boolean,
            "vulnerability_count": number,
            "max_severity": "string",
            "summary": "string"
        }}
        """
        
        return prompt
    
    def _parse_github_security_response(self, ai_response: str) -> Optional[Dict[str, Any]]:
        """Parse AI response for GitHub security analysis"""
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            # Fallback: parse text response
            lines = ai_response.strip().split('\n')
            result = {
                'vulnerabilities_found': 'vulnerabilities found' in ai_response.lower(),
                'vulnerability_count': 0,
                'max_severity': 'UNKNOWN',
                'summary': ai_response[:200] + '...' if len(ai_response) > 200 else ai_response
            }
            
            # Try to extract numbers
            numbers = re.findall(r'\d+', ai_response)
            if numbers:
                result['vulnerability_count'] = int(numbers[0])
            
            # Try to extract severity
            severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            for severity in severities:
                if severity in ai_response.upper():
                    result['max_severity'] = severity
                    break
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to parse AI GitHub security response: {e}")
            return None
    
    async def _call_ai_api(self, prompt: str) -> Optional[str]:
        """Make API call to AI service"""
        try:
            if self.provider in ['azure', 'openai']:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert specializing in Python package security assessment."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=self.config.get('max_tokens', 1000),
                    temperature=self.config.get('temperature', 0.1)
                )
                return response.choices[0].message.content
            
            elif self.provider == 'mock':
                return await self.client.generate_response(prompt)
            
            return None
            
        except Exception as e:
            self.logger.error(f"AI API call failed: {e}")
            return None
    
    def is_enabled(self) -> bool:
        """Check if AI analysis is enabled and available"""
        return self.enabled and self.client is not None


class MockAIClient:
    """Mock AI client for testing and demonstration"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def generate_recommendation(self, context: Dict[str, Any]) -> str:
        """Generate mock recommendation"""
        critical = context.get('critical_vulnerabilities', 0)
        high = context.get('high_risk_vulnerabilities', 0)
        total = context.get('total_vulnerabilities', 0)
        
        if critical > 0:
            return "CRITICAL - IMMEDIATE ACTION REQUIRED"
        elif high > 2:
            return "HIGH RISK - UPDATE REQUIRED"
        elif total > 5:
            return "MODERATE RISK - REVIEW AND UPDATE"
        elif total > 0:
            return "LOW RISK - MONITOR"
        else:
            return "PROCEED"
    
    async def analyze_github_security(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate mock GitHub security analysis"""
        package_name = context.get('package_name', 'unknown')
        
        # Simple mock logic based on package name patterns
        if any(pattern in package_name.lower() for pattern in ['test', 'demo', 'sample']):
            return {
                'vulnerabilities_found': False,
                'vulnerability_count': 0,
                'max_severity': 'NONE',
                'summary': f'Mock analysis: No vulnerabilities found for {package_name}'
            }
        else:
            return {
                'vulnerabilities_found': True,
                'vulnerability_count': 1,
                'max_severity': 'MEDIUM',
                'summary': f'Mock analysis: 1 medium-severity vulnerability found for {package_name}'
            }
    
    async def generate_response(self, prompt: str) -> str:
        """Generate mock response to prompt"""
        if 'recommendation' in prompt.lower():
            if 'critical' in prompt.lower():
                return "CRITICAL - IMMEDIATE ACTION REQUIRED"
            elif 'high' in prompt.lower():
                return "HIGH RISK - UPDATE REQUIRED"
            else:
                return "PROCEED"
        
        elif 'github security' in prompt.lower():
            return '''
            {
                "vulnerabilities_found": false,
                "vulnerability_count": 0,
                "max_severity": "NONE",
                "summary": "Mock GitHub security analysis completed - no vulnerabilities found"
            }
            '''
        
        return "Mock AI response generated"