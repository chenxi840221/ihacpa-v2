# 📚 IHACPA v2.0 API Reference

**Complete API documentation for developers**

## 🏗️ **Core API**

### **SandboxManager**

The main orchestration class for all scanning operations.

#### **Constructor**
```python
class SandboxManager:
    def __init__(self, config: Optional[Dict[str, Any]] = None)
```

**Parameters:**
- `config` (dict, optional): Configuration dictionary

**Example:**
```python
# Default configuration
manager = SandboxManager()

# Custom configuration
config = {
    "ai": {"enabled": True, "provider": "azure"},
    "performance": {"max_concurrent_scans": 3},
    "redis": {"enabled": False}
}
manager = SandboxManager(config)
```

#### **Methods**

##### **initialize()**
```python
async def initialize(self) -> None
```
Initializes all sandboxes, AI layer, and connections.

**Raises:**
- `ConnectionError`: If Azure OpenAI connection fails
- `ImportError`: If required dependencies are missing

**Example:**
```python
manager = SandboxManager()
await manager.initialize()
# Registers: PyPI, NVD, SNYK, MITRE, GitHub Advisory, Exploit-DB sandboxes
```

##### **scan_package_with_ai_analysis()** ⭐ *New*
```python
async def scan_package_with_ai_analysis(
    self, 
    package_name: str, 
    current_version: Optional[str] = None,
    include_correlation_analysis: bool = True,
    include_risk_assessment: bool = True,
    **kwargs
) -> Dict[str, Any]
```

**Enhanced scanning with AI-powered correlation and risk assessment.**

**Parameters:**
- `package_name` (str): Name of the package to scan
- `current_version` (str, optional): Current version of the package
- `include_correlation_analysis` (bool): Enable cross-database correlation
- `include_risk_assessment` (bool): Enable AI risk assessment
- `**kwargs`: Additional parameters passed to scanners

**Returns:**
- `Dict[str, Any]`: Enhanced scan results with AI analysis

**Example:**
```python
results = await manager.scan_package_with_ai_analysis(
    package_name="requests",
    current_version="2.30.0",
    include_correlation_analysis=True,
    include_risk_assessment=True
)

# Access results
scan_results = results["scan_results"]
correlation_analysis = results["correlation_analysis"]
risk_assessment = results["risk_assessment"]
```

##### **get_enhanced_scan_summary()** ⭐ *New*
```python
async def get_enhanced_scan_summary(
    self, 
    scan_results: Dict[str, Any]
) -> Dict[str, Any]
```

**Get enhanced summary with AI insights.**

**Parameters:**
- `scan_results` (dict): Results from `scan_package_with_ai_analysis()`

**Returns:**
- `Dict[str, Any]`: Enhanced summary with key insights

**Example:**
```python
summary = await manager.get_enhanced_scan_summary(results)
print(f"Overall Risk: {summary['risk_insights']['overall_package_risk']}")
print(f"Priority Vulns: {summary['risk_insights']['top_priority_vulnerabilities']}")
```
await manager.cleanup()
```

##### **scan_package()**
```python
async def scan_package(
    self,
    package_name: str,
    current_version: Optional[str] = None,
    parallel: bool = True
) -> Dict[str, ScanResult]
```

**Parameters:**
- `package_name` (str): Name of the Python package
- `current_version` (str, optional): Specific version to analyze
- `parallel` (bool): Whether to run sandboxes in parallel (default: True)

**Returns:**
- `Dict[str, ScanResult]`: Results from each sandbox

**Example:**
```python
# Scan latest version
results = await manager.scan_package("requests")

# Scan specific version
results = await manager.scan_package("requests", "2.30.0")

# Sequential scanning (slower but uses less resources)
results = await manager.scan_package("requests", parallel=False)
```

##### **aggregate_results()**
```python
async def aggregate_results(
    self, 
    results: Dict[str, ScanResult]
) -> AggregatedResult
```

**Parameters:**
- `results` (dict): Results from scan_package()

**Returns:**
- `AggregatedResult`: Combined and deduplicated results

**Example:**
```python
results = await manager.scan_package("django")
aggregated = await manager.aggregate_results(results)

print(f"Total vulnerabilities: {len(aggregated.vulnerabilities)}")
print(f"Success rate: {aggregated.metadata['success_rate']}")
```

##### **get_stats()**
```python
async def get_stats(self) -> Dict[str, Any]
```

**Returns:**
- `Dict[str, Any]`: Performance and usage statistics

**Example:**
```python
stats = await manager.get_stats()
print(f"Total scans: {stats['scan_count']}")
print(f"Cache hits: {stats['cache_hits']}")
```

##### **cleanup()**
```python
async def cleanup(self) -> None
```
Properly closes all connections and cleans up resources.

**Example:**
```python
try:
    await manager.initialize()
    # ... scanning operations
finally:
    await manager.cleanup()
```

### **ScanResult**

Result object returned by individual sandboxes.

#### **Attributes**
```python
@dataclass
class ScanResult:
    success: bool
    vulnerabilities: List[VulnerabilityInfo]
    ai_enhanced: bool
    cache_hit: bool
    scan_time: float
    error_message: Optional[str]
    metadata: Dict[str, Any]
```

**Properties:**
- `success` (bool): Whether the scan completed successfully
- `vulnerabilities` (List[VulnerabilityInfo]): Found vulnerabilities
- `ai_enhanced` (bool): Whether AI analysis was performed
- `cache_hit` (bool): Whether result came from cache
- `scan_time` (float): Time taken for scan in seconds
- `error_message` (str, optional): Error description if failed
- `metadata` (dict): Additional scan information

**Example:**
```python
for source, result in results.items():
    if result.success:
        print(f"{source}: {len(result.vulnerabilities)} vulnerabilities")
        print(f"AI Enhanced: {result.ai_enhanced}")
        print(f"Scan Time: {result.scan_time:.2f}s")
        print(f"From Cache: {result.cache_hit}")
    else:
        print(f"{source} failed: {result.error_message}")
```

### **VulnerabilityInfo**

Information about a specific vulnerability.

#### **Attributes**
```python
@dataclass
class VulnerabilityInfo:
    title: str
    description: str
    severity: SeverityLevel
    cve_id: Optional[str]
    cvss_score: Optional[float]
    published_date: Optional[datetime]
    source_url: Optional[str]
    affected_versions: List[str]
    confidence: Optional[ConfidenceLevel]
    ai_reasoning: Optional[str]
    recommendation: Optional[str]
```

**Properties:**
- `title` (str): Vulnerability title/summary
- `description` (str): Detailed description
- `severity` (SeverityLevel): Risk level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `cve_id` (str, optional): CVE identifier if available
- `cvss_score` (float, optional): CVSS v3 score (0.0-10.0)
- `published_date` (datetime, optional): When vulnerability was disclosed
- `source_url` (str, optional): Link to original vulnerability report
- `affected_versions` (List[str]): Package versions affected
- `confidence` (ConfidenceLevel, optional): AI confidence in assessment
- `ai_reasoning` (str, optional): AI explanation of the analysis
- `recommendation` (str, optional): AI-generated recommendation

**Example:**
```python
for vuln in result.vulnerabilities:
    print(f"Title: {vuln.title}")
    print(f"Severity: {vuln.severity.value}")
    if vuln.cve_id:
        print(f"CVE: {vuln.cve_id}")
    if vuln.confidence:
        print(f"AI Confidence: {vuln.confidence.value}")
    if vuln.recommendation:
        print(f"Recommendation: {vuln.recommendation}")
```

## 🤖 **AI Layer API**

### **AIChainFactory**

Factory for creating AI chains with different providers.

#### **Constructor**
```python
class AIChainFactory:
    def __init__(self, config: Dict[str, Any])
```

**Parameters:**
- `config` (dict): AI configuration

**Example:**
```python
config = {
    "provider": "azure",
    "model": "gpt-4.1",
    "temperature": 0.1,
    "timeout": 45
}
factory = AIChainFactory(config)
```

#### **Methods**

##### **get_provider_info()**
```python
def get_provider_info(self) -> Dict[str, Any]
```

**Returns:**
- `Dict[str, Any]`: Information about the AI provider

## 🤖 **AI Agent APIs** ⭐ *New*

### **CrossDatabaseCorrelationAnalyzer**

AI-powered analyzer for correlating vulnerabilities across multiple databases.

#### **Constructor**
```python
from src.ai_layer.agents import CrossDatabaseCorrelationAnalyzer

analyzer = CrossDatabaseCorrelationAnalyzer(ai_factory=None)
```

#### **Methods**

##### **analyze_cross_database_results()**
```python
async def analyze_cross_database_results(
    self,
    package_name: str,
    scan_results: Dict[str, ScanResult]
) -> CrossDatabaseAnalysis
```

**Perform comprehensive cross-database correlation analysis.**

**Parameters:**
- `package_name` (str): Name of the scanned package
- `scan_results` (dict): Dictionary of scan results from different sources

**Returns:**
- `CrossDatabaseAnalysis`: Comprehensive analysis with correlations and insights

**Example:**
```python
analyzer = CrossDatabaseCorrelationAnalyzer()
correlation_analysis = await analyzer.analyze_cross_database_results(
    package_name="requests", 
    scan_results=scan_results
)

print(f"Unique Vulnerabilities: {len(correlation_analysis.unique_vulnerabilities)}")
print(f"Correlations Found: {len(correlation_analysis.correlations)}")
print(f"AI Overall Risk: {correlation_analysis.ai_overall_risk_assessment}")
```

### **AIRiskAssessor**

AI-powered risk assessment engine for comprehensive vulnerability analysis.

#### **Constructor**
```python
from src.ai_layer.agents import AIRiskAssessor, ThreatContext

risk_assessor = AIRiskAssessor(ai_factory=None)
```

#### **Methods**

##### **assess_vulnerability_risk()**
```python
async def assess_vulnerability_risk(
    self,
    vulnerability: VulnerabilityInfo,
    package_name: str,
    context: ThreatContext = ThreatContext.PRODUCTION,
    business_context: Optional[Dict[str, Any]] = None
) -> ComprehensiveRiskAssessment
```

**Perform comprehensive risk assessment for a single vulnerability.**

**Parameters:**
- `vulnerability` (VulnerabilityInfo): Vulnerability to assess
- `package_name` (str): Name of the affected package
- `context` (ThreatContext): Deployment/threat context
- `business_context` (dict, optional): Business context information

**Returns:**
- `ComprehensiveRiskAssessment`: Detailed risk assessment

##### **assess_package_risk_profile()**
```python
async def assess_package_risk_profile(
    self,
    vulnerabilities: List[VulnerabilityInfo],
    package_name: str,
    context: ThreatContext = ThreatContext.PRODUCTION,
    business_context: Optional[Dict[str, Any]] = None
) -> PackageRiskProfile
```

**Assess overall risk profile for a package with multiple vulnerabilities.**

**Example:**
```python
risk_assessor = AIRiskAssessor()
risk_profile = await risk_assessor.assess_package_risk_profile(
    vulnerabilities=vulnerabilities,
    package_name="requests",
    context=ThreatContext.PRODUCTION
)

print(f"Overall Package Risk: {risk_profile.overall_package_risk}")
print(f"Critical Vulnerabilities: {risk_profile.critical_vulnerabilities}")
print(f"Immediate Actions: {risk_profile.immediate_actions}")

# Get top priority vulnerabilities
top_priority = risk_profile.get_top_priority_vulnerabilities(limit=5)
for vuln_assessment in top_priority:
    print(f"- {vuln_assessment.vulnerability.title}")
    print(f"  Risk Score: {vuln_assessment.overall_risk_score}")
    print(f"  Urgency: {vuln_assessment.urgency_level}")
```

### **CVEAnalyzer**

AI-powered CVE analysis agent for intelligent vulnerability assessment.

#### **Constructor**
```python
from src.ai_layer.agents import CVEAnalyzer

analyzer = CVEAnalyzer(ai_factory=None)
```

#### **Methods**

##### **analyze_cve()**
```python
async def analyze_cve(
    self,
    cve_id: str,
    cve_description: str,
    package_name: str,
    current_version: Optional[str] = None,
    **kwargs
) -> CVEAnalysisResult
```

**Analyze a CVE for package-specific impact.**

**Example:**
```python
analyzer = CVEAnalyzer()
analysis = await analyzer.analyze_cve(
    cve_id="CVE-2023-12345",
    cve_description="SQL injection vulnerability in requests library",
    package_name="requests",
    current_version="2.28.0"
)

print(f"Is Affected: {analysis.is_affected}")
print(f"Confidence: {analysis.confidence}")
print(f"Recommendation: {analysis.recommendation}")
```

## 📊 **Enhanced Data Models** ⭐ *New*

### **CrossDatabaseAnalysis**

Comprehensive analysis result across multiple vulnerability databases.

#### **Attributes**
```python
@dataclass
class CrossDatabaseAnalysis:
    package_name: str
    correlations: List[VulnerabilityCorrelation]
    unique_vulnerabilities: List[VulnerabilityInfo]
    ai_overall_risk_assessment: str
    ai_priority_vulnerabilities: List[str]
    ai_threat_landscape_summary: str
    database_coverage: Dict[str, float]
    consensus_confidence: float
```

### **PackageRiskProfile**

Overall risk profile for a package based on all vulnerabilities.

#### **Attributes**
```python
@dataclass
class PackageRiskProfile:
    package_name: str
    overall_package_risk: float
    critical_vulnerabilities: int
    high_risk_vulnerabilities: int
    immediate_actions: List[str]
    ai_package_assessment: str
    ai_strategic_recommendations: str
```

#### **Methods**

##### **get_top_priority_vulnerabilities()**
```python
def get_top_priority_vulnerabilities(self, limit: int = 5) -> List[ComprehensiveRiskAssessment]
```

**Get top priority vulnerabilities for immediate attention.**

### **ThreatContext Enum**

Threat context for risk assessment.

```python
class ThreatContext(Enum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"
    INTERNAL = "internal"
    PUBLIC_FACING = "public_facing"
    CRITICAL_INFRASTRUCTURE = "critical_infrastructure"
```

## 🎯 **Sandbox-Specific APIs**

### **SNYK Sandbox**
- Commercial vulnerability intelligence
- AI risk assessment and exploit maturity analysis
- License and dependency analysis

### **MITRE Sandbox**
- Authoritative CVE database access
- AI relevance filtering and search enhancement
- Cross-database correlation

### **GitHub Advisory Sandbox**
- Security advisories with AI priority scoring
- Version-specific vulnerability assessment
- Integration with CVE database

### **Exploit-DB Sandbox**
- Exploit intelligence and threat analysis
- IoC (Indicators of Compromise) extraction
- MITRE ATT&CK technique mapping

**This comprehensive API enables enterprise-grade vulnerability intelligence with AI-powered analysis, correlation, and risk assessment capabilities.**

**Example:**
```python
info = factory.get_provider_info()
print(f"Provider: {info['provider']}")
print(f"Model: {info['model']}")
print(f"Has API Key: {info['has_api_key']}")
```

##### **test_connection()**
```python
def test_connection(self) -> bool
```

**Returns:**
- `bool`: Whether connection to AI provider is successful

**Example:**
```python
if factory.test_connection():
    print("AI provider is available")
else:
    print("AI provider connection failed")
```

### **CVEAnalyzer**

AI agent for analyzing CVE relevance and impact.

#### **Constructor**
```python
class CVEAnalyzer:
    def __init__(self, chain_factory: AIChainFactory)
```

#### **Methods**

##### **analyze_cve()**
```python
async def analyze_cve(
    self,
    cve_id: str,
    cve_description: str,
    package_name: str,
    current_version: Optional[str] = None,
    cvss_score: Optional[float] = None
) -> CVEAnalysisResult
```

**Parameters:**
- `cve_id` (str): CVE identifier
- `cve_description` (str): CVE description
- `package_name` (str): Package being analyzed
- `current_version` (str, optional): Current package version
- `cvss_score` (float, optional): CVSS score if available

**Returns:**
- `CVEAnalysisResult`: AI analysis results

**Example:**
```python
from src.ai_layer.agents.cve_analyzer import CVEAnalyzer

analyzer = CVEAnalyzer(factory)
result = await analyzer.analyze_cve(
    cve_id="CVE-2023-32681",
    cve_description="Requests library vulnerability...",
    package_name="requests",
    current_version="2.30.0"
)

print(f"Affected: {result.is_affected}")
print(f"Confidence: {result.confidence:.1%}")
print(f"Reasoning: {result.reasoning}")
```

### **CVEAnalysisResult**

Result of AI CVE analysis.

#### **Attributes**
```python
@dataclass
class CVEAnalysisResult:
    cve_id: str
    package_name: str
    current_version: Optional[str]
    is_affected: bool
    confidence: float
    severity: SeverityLevel
    reasoning: str
    recommendation: str
```

## 🔧 **Sandbox API**

### **BaseSandbox**

Abstract base class for all sandboxes.

#### **Abstract Methods**

##### **scan_package()**
```python
@abstractmethod
async def scan_package(
    self, 
    package_name: str, 
    current_version: Optional[str] = None
) -> ScanResult
```

##### **health_check()**
```python
@abstractmethod
async def health_check(self) -> bool
```

### **Individual Sandboxes**

#### **PyPISandbox**
```python
class PyPISandbox(BaseSandbox):
    async def scan_package(self, package_name: str, current_version: Optional[str] = None) -> ScanResult
    async def get_package_info(self, package_name: str) -> Dict[str, Any]
    async def check_version_updates(self, package_name: str, current_version: str) -> Dict[str, Any]
```

#### **NVDSandbox**
```python
class NVDSandbox(BaseSandbox):
    async def scan_package(self, package_name: str, current_version: Optional[str] = None) -> ScanResult
    async def search_cves(self, package_name: str) -> List[Dict[str, Any]]
    async def analyze_cve_relevance(self, cve_data: Dict, package_name: str, version: str) -> bool
```

#### **SNYKSandbox**
```python
class SNYKSandbox(BaseSandbox):
    async def scan_package(self, package_name: str, current_version: Optional[str] = None) -> ScanResult
    async def scrape_vulnerabilities(self, package_name: str) -> List[Dict[str, Any]]
```

## 📊 **Enums and Constants**

### **SeverityLevel**
```python
from enum import Enum

class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
```

### **ConfidenceLevel**
```python
class ConfidenceLevel(Enum):
    HIGH = "HIGH"      # 0.8 - 1.0
    MEDIUM = "MEDIUM"  # 0.6 - 0.8
    LOW = "LOW"        # 0.0 - 0.6
```

## 🔧 **Utility Functions**

### **Configuration Helpers**

#### **load_config()**
```python
def load_config(config_path: Optional[str] = None) -> Dict[str, Any]
```

**Parameters:**
- `config_path` (str, optional): Path to configuration file

**Returns:**
- `Dict[str, Any]`: Loaded configuration

**Example:**
```python
from src.utils.config import load_config

config = load_config("config/custom_settings.yaml")
manager = SandboxManager(config)
```

#### **validate_config()**
```python
def validate_config(config: Dict[str, Any]) -> bool
```

**Parameters:**
- `config` (dict): Configuration to validate

**Returns:**
- `bool`: Whether configuration is valid

### **Caching Utilities**

#### **CacheManager**
```python
class CacheManager:
    async def get(self, key: str) -> Optional[Any]
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None
    async def delete(self, key: str) -> None
    async def clear(self) -> None
```

**Example:**
```python
cache = CacheManager("redis://localhost:6379")
await cache.set("scan_results_requests", results, ttl=3600)
cached_results = await cache.get("scan_results_requests")
```

## 🚨 **Error Handling**

### **Exception Classes**

#### **ScannerError**
```python
class ScannerError(Exception):
    """Base exception for scanner errors"""
    pass
```

#### **ConnectionError**
```python
class ConnectionError(ScannerError):
    """Raised when connection to external service fails"""
    pass
```

#### **ConfigurationError**
```python
class ConfigurationError(ScannerError):
    """Raised when configuration is invalid"""
    pass
```

#### **RateLimitError**
```python
class RateLimitError(ScannerError):
    """Raised when rate limit is exceeded"""
    pass
```

### **Error Handling Patterns**

#### **Graceful Degradation**
```python
async def scan_with_fallback():
    manager = SandboxManager()
    await manager.initialize()
    
    try:
        results = await manager.scan_package("requests")
    except ConnectionError as e:
        print(f"Connection failed: {e}")
        # Try with reduced functionality
        results = await manager.scan_package("requests", parallel=False)
    except RateLimitError as e:
        print(f"Rate limited: {e}")
        # Wait and retry
        await asyncio.sleep(60)
        results = await manager.scan_package("requests")
    
    await manager.cleanup()
    return results
```

#### **Retry Logic**
```python
import asyncio
from typing import Callable, Any

async def retry_on_failure(
    func: Callable, 
    max_retries: int = 3, 
    delay: float = 1.0
) -> Any:
    for attempt in range(max_retries):
        try:
            return await func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            print(f"Attempt {attempt + 1} failed: {e}")
            await asyncio.sleep(delay * (2 ** attempt))  # Exponential backoff
```

## 📊 **Performance Monitoring API**

### **Metrics Collection**
```python
class MetricsCollector:
    def record_scan_time(self, duration: float) -> None
    def record_cache_hit(self) -> None
    def record_cache_miss(self) -> None
    def record_api_call(self, service: str) -> None
    def get_metrics(self) -> Dict[str, Any]
```

### **Health Check API**
```python
class HealthChecker:
    async def check_azure_connection(self) -> bool
    async def check_redis_connection(self) -> bool
    async def check_sandbox_health(self) -> Dict[str, bool]
    async def comprehensive_health_check(self) -> Dict[str, Any]
```

## 🔧 **Custom Sandbox Development**

### **Creating a New Sandbox**

#### **1. Implement BaseSandbox**
```python
from src.core.base_scanner import BaseSandbox, ScanResult

class CustomSandbox(BaseSandbox):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_url = config.get('api_url')
        self.api_key = config.get('api_key')
    
    async def scan_package(self, package_name: str, current_version: Optional[str] = None) -> ScanResult:
        try:
            # Your custom scanning logic here
            vulnerabilities = await self._fetch_vulnerabilities(package_name)
            
            return ScanResult(
                success=True,
                vulnerabilities=vulnerabilities,
                ai_enhanced=False,  # Set to True if using AI
                cache_hit=False,
                scan_time=time.time() - start_time,
                metadata={"source": "custom_api"}
            )
        except Exception as e:
            return ScanResult(
                success=False,
                vulnerabilities=[],
                ai_enhanced=False,
                cache_hit=False,
                scan_time=0,
                error_message=str(e),
                metadata={}
            )
    
    async def health_check(self) -> bool:
        try:
            # Test your API connection
            response = await self._test_api_connection()
            return response.status_code == 200
        except:
            return False
```

#### **2. Register the Sandbox**
```python
# In sandbox_manager.py
def _initialize_sandboxes(self):
    # ... existing sandboxes
    self.sandboxes['custom'] = CustomSandbox(self.config.get('custom', {}))
```

---

**This API reference covers all the major components and interfaces in IHACPA v2.0. For implementation examples, see the user guide and architecture documentation.**