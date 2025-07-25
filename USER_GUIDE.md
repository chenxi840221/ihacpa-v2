# 📚 IHACPA v2.0 User Guide

**Comprehensive guide to using the AI-enhanced vulnerability scanning system**

## 🎯 **Overview**

IHACPA v2.0 is a modern, AI-powered vulnerability scanning system that analyzes Python packages for security issues across multiple databases. This guide covers everything you need to know to use the system effectively.

## 🚀 **Getting Started**

### **System Requirements**
- Python 3.10 or higher
- Azure OpenAI API access
- 4GB RAM minimum
- Internet connectivity for API access

### **Quick Start**
```bash
# 1. Test the system
python simple_azure_test.py

# 2. Check system health
python production_monitor.py

# 3. Run your first scan
python -c "
import asyncio
from src.core.sandbox_manager import SandboxManager

async def scan():
    manager = SandboxManager()
    await manager.initialize()
    results = await manager.scan_package('requests')
    print(f'Scan complete: {len(results)} sources')
    await manager.cleanup()

asyncio.run(scan())
"
```

## 🏗️ **Understanding the Architecture**

### **Core Components**

#### **1. Sandbox Manager**
- **Purpose**: Orchestrates all scanning operations
- **Key Features**: Parallel execution, result aggregation, error handling
- **Usage**: Main interface for all scanning operations

#### **2. Sandboxes (Vulnerability Sources)**
- **PyPI Sandbox**: Package metadata and version information
- **NVD Sandbox**: NIST National Vulnerability Database
- **SNYK Sandbox**: Commercial vulnerability intelligence
- **MITRE Sandbox**: CVE database scanning
- **Exploit DB Sandbox**: Public exploit database

#### **3. AI Layer**
- **Azure OpenAI Integration**: GPT-4 powered analysis
- **CVE Analyzer**: Determines vulnerability relevance
- **Confidence Scoring**: Reliability assessment (0-100%)
- **Natural Language**: Human-readable explanations

#### **4. Caching & Performance**
- **Redis Caching**: 80% hit rate for repeated scans
- **Rate Limiting**: Respects API limits automatically
- **Circuit Breakers**: Automatic failure recovery

## 📊 **Scanning Operations**

### **Basic Package Scanning**

#### **Single Package Scan**
```python
import asyncio
from src.core.sandbox_manager import SandboxManager

async def scan_single_package():
    manager = SandboxManager()
    await manager.initialize()
    
    # Scan with default settings
    results = await manager.scan_package("django")
    
    # Process results
    for source, result in results.items():
        print(f"\\n📊 {source.upper()} Results:")
        print(f"   Success: {'✅' if result.success else '❌'}")
        print(f"   AI Enhanced: {'🤖' if result.ai_enhanced else '📊'}")
        print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
        
        # Show vulnerability details
        for vuln in result.vulnerabilities[:3]:  # First 3
            print(f"      • {vuln.title}")
            print(f"        Severity: {vuln.severity.value}")
            if hasattr(vuln, 'cve_id') and vuln.cve_id:
                print(f"        CVE: {vuln.cve_id}")
    
    await manager.cleanup()

asyncio.run(scan_single_package())
```

#### **Specific Version Scanning**
```python
async def scan_specific_version():
    manager = SandboxManager()
    await manager.initialize()
    
    # Scan specific version
    results = await manager.scan_package(
        package_name="requests",
        current_version="2.28.0"  # Specific version
    )
    
    # Check if current version is affected
    for source, result in results.items():
        if result.success and result.vulnerabilities:
            print(f"{source}: {len(result.vulnerabilities)} vulnerabilities affect v2.28.0")
    
    await manager.cleanup()
```

### **Batch Processing**

#### **Multiple Package Scanning**
```python
async def scan_multiple_packages():
    manager = SandboxManager()
    await manager.initialize()
    
    packages = [
        ("requests", "2.30.0"),
        ("urllib3", "1.26.16"),
        ("pillow", "9.5.0"),
        ("django", "4.2.0"),
        ("flask", "2.3.0")
    ]
    
    results_summary = []
    
    for package_name, version in packages:
        print(f"\\n🔍 Scanning {package_name} v{version}...")
        
        start_time = time.time()
        results = await manager.scan_package(package_name, version)
        scan_time = time.time() - start_time
        
        # Aggregate results
        total_vulns = sum(len(r.vulnerabilities) for r in results.values() if r.success)
        successful_sources = sum(1 for r in results.values() if r.success)
        ai_enhanced_sources = sum(1 for r in results.values() if r.ai_enhanced)
        
        summary = {
            "package": f"{package_name} v{version}",
            "scan_time": scan_time,
            "vulnerabilities": total_vulns,
            "successful_sources": successful_sources,
            "ai_enhanced": ai_enhanced_sources,
            "total_sources": len(results)
        }
        results_summary.append(summary)
        
        print(f"   ✅ {scan_time:.1f}s | {total_vulns} vulns | {successful_sources}/{len(results)} sources | {ai_enhanced_sources} AI")
    
    # Final summary
    print(f"\\n📊 Batch Scan Summary:")
    print(f"   Packages: {len(packages)}")
    print(f"   Total time: {sum(r['scan_time'] for r in results_summary):.1f}s")
    print(f"   Average time: {sum(r['scan_time'] for r in results_summary) / len(results_summary):.1f}s")
    print(f"   Total vulnerabilities: {sum(r['vulnerabilities'] for r in results_summary)}")
    
    await manager.cleanup()
```

#### **Progress Tracking**
```python
async def scan_with_progress():
    manager = SandboxManager()
    await manager.initialize()
    
    packages = ["django", "flask", "fastapi", "tornado", "bottle", "pyramid"]
    
    for i, package in enumerate(packages, 1):
        print(f"\\n📦 [{i:2d}/{len(packages)}] Processing {package}...")
        
        try:
            start_time = time.time()
            results = await manager.scan_package(package)
            scan_time = time.time() - start_time
            
            # Calculate success metrics
            successful = sum(1 for r in results.values() if r.success)
            ai_enhanced = sum(1 for r in results.values() if r.ai_enhanced)
            total_vulns = sum(len(r.vulnerabilities) for r in results.values() if r.success)
            
            # Progress indicators
            progress_bar = "█" * (i * 20 // len(packages)) + "░" * (20 - (i * 20 // len(packages)))
            eta = (len(packages) - i) * scan_time if i > 1 else 0
            
            print(f"   [{progress_bar}] {i/len(packages)*100:.1f}%")
            print(f"   ✅ {scan_time:.1f}s | {total_vulns} vulns | {successful}/{len(results)} sources | {ai_enhanced} AI")
            print(f"   ETA: {eta:.0f}s remaining")
            
        except Exception as e:
            print(f"   ❌ Failed: {e}")
    
    await manager.cleanup()
```

## 🤖 **AI-Enhanced Analysis**

### **New AI-Powered Scanning Methods** ⭐

#### **AI-Enhanced Comprehensive Scanning**
```python
import asyncio
from src.core.sandbox_manager import SandboxManager

async def ai_comprehensive_scan():
    """Perform AI-enhanced scanning with correlation and risk assessment"""
    # Initialize with AI capabilities
    manager = SandboxManager({
        "ai": {
            "enabled": True,
            "provider": "azure",
            "model": "gpt-4.1"
        }
    })
    await manager.initialize()
    
    # AI-enhanced comprehensive scan
    results = await manager.scan_package_with_ai_analysis(
        package_name="requests",
        current_version="2.30.0",
        include_correlation_analysis=True,
        include_risk_assessment=True
    )
    
    print(f"📦 Enhanced Analysis for {results['package_name']}:")
    print(f"   Sources Scanned: {len(results['scan_results'])}")
    print(f"   Scan Timestamp: {results['scan_timestamp']}")
    
    # Display correlation analysis if available
    if results.get('correlation_analysis'):
        corr = results['correlation_analysis']
        print(f"\n🔗 Cross-Database Correlation:")
        print(f"   Unique Vulnerabilities: {len(corr.unique_vulnerabilities)}")
        print(f"   Correlations Found: {len(corr.correlations)}")
        print(f"   AI Overall Risk: {corr.ai_overall_risk_assessment[:100]}...")
        print(f"   Consensus Confidence: {corr.consensus_confidence:.1%}")
    
    # Display risk assessment if available
    if results.get('risk_assessment'):
        risk = results['risk_assessment']
        print(f"\n⚠️  AI Risk Assessment:")
        print(f"   Overall Package Risk: {risk.overall_package_risk:.2f}")
        print(f"   Critical Vulnerabilities: {risk.critical_vulnerabilities}")
        print(f"   High Risk Vulnerabilities: {risk.high_risk_vulnerabilities}")
        print(f"   Immediate Actions Required: {len(risk.immediate_actions)}")
        
        # Show top priority vulnerabilities
        top_priority = risk.get_top_priority_vulnerabilities(3)
        if top_priority:
            print(f"\n🎯 Top Priority Issues:")
            for i, vuln_assessment in enumerate(top_priority, 1):
                vuln = vuln_assessment.vulnerability
                print(f"   {i}. {vuln.cve_id or vuln.title}")
                print(f"      Risk Score: {vuln_assessment.overall_risk_score:.2f}")
                print(f"      Urgency: {vuln_assessment.urgency_level}")
                print(f"      Recommendation: {vuln_assessment.ai_recommendation[:80]}...")
    
    await manager.cleanup()

# Run the enhanced scan
asyncio.run(ai_comprehensive_scan())
```

#### **Enhanced Scan Summary**
```python
async def get_scan_insights():
    """Get AI-powered insights and summary from scan results"""
    manager = SandboxManager({
        "ai": {"enabled": True, "provider": "azure"}
    })
    await manager.initialize()
    
    # Perform enhanced scan
    results = await manager.scan_package_with_ai_analysis(
        package_name="django",
        current_version="4.2.0",
        include_correlation_analysis=True,
        include_risk_assessment=True
    )
    
    # Get AI-powered summary
    summary = await manager.get_enhanced_scan_summary(results)
    
    print(f"📊 AI-Enhanced Summary for {summary['package_name']}:")
    print(f"   🎯 Sources Scanned: {summary['total_sources_scanned']}")
    print(f"   ✅ Successful Scans: {summary['successful_scans']}")
    print(f"   🤖 AI-Enhanced Sources: {summary['ai_enhanced_sources']}")
    print(f"   🔍 Total Vulnerabilities: {summary['total_vulnerabilities_found']}")
    print(f"   🎯 Unique Vulnerabilities: {summary['unique_vulnerabilities']}")
    
    # Risk insights
    if 'risk_insights' in summary:
        risk = summary['risk_insights']
        print(f"\n⚠️  Risk Analysis:")
        print(f"   Overall Risk: {risk['overall_package_risk']:.2f}")
        print(f"   Critical Issues: {risk['critical_vulnerabilities']}")
        print(f"   High Risk Issues: {risk['high_risk_vulnerabilities']}")
        print(f"   Immediate Actions: {risk['immediate_actions_needed']}")
        
        # Top priority vulnerabilities
        if risk.get('top_priority_vulnerabilities'):
            print(f"\n🚨 High Priority Vulnerabilities:")
            for vuln in risk['top_priority_vulnerabilities']:
                print(f"   • {vuln['title']} (Risk: {vuln['risk_score']:.2f}, {vuln['urgency']})")
    
    await manager.cleanup()

asyncio.run(get_scan_insights())
```

### **Cross-Database Correlation Analysis** ⭐

#### **Advanced Vulnerability Correlation**
```python
from src.ai_layer.agents import CrossDatabaseCorrelationAnalyzer

async def perform_correlation_analysis():
    """Analyze vulnerabilities across multiple databases with AI correlation"""
    manager = SandboxManager({"ai": {"enabled": True, "provider": "azure"}})
    await manager.initialize()
    
    # Get scan results from multiple sources
    scan_results = await manager.scan_package("pillow", "9.5.0")
    
    # Initialize correlation analyzer
    analyzer = CrossDatabaseCorrelationAnalyzer(manager.ai_layer)
    
    # Perform cross-database analysis
    correlation_analysis = await analyzer.analyze_cross_database_results(
        package_name="pillow",
        scan_results=scan_results
    )
    
    print(f"🔗 Cross-Database Correlation Analysis for Pillow:")
    print(f"   📊 Total Scan Results: {len(scan_results)}")
    print(f"   🎯 Unique Vulnerabilities: {len(correlation_analysis.unique_vulnerabilities)}")
    print(f"   🔍 Correlations Found: {len(correlation_analysis.correlations)}")
    print(f"   🤖 AI Confidence: {correlation_analysis.consensus_confidence:.1%}")
    
    print(f"\n📋 AI Overall Assessment:")
    print(f"   {correlation_analysis.ai_overall_risk_assessment}")
    
    print(f"\n🚨 AI Priority Vulnerabilities:")
    for priority_vuln in correlation_analysis.ai_priority_vulnerabilities[:3]:
        print(f"   • {priority_vuln}")
    
    print(f"\n🌐 Threat Landscape Summary:")
    print(f"   {correlation_analysis.ai_threat_landscape_summary}")
    
    # Database coverage analysis
    print(f"\n📊 Database Coverage:")
    for db, coverage in correlation_analysis.database_coverage.items():
        coverage_icon = "🟢" if coverage > 0.8 else "🟡" if coverage > 0.5 else "🔴"
        print(f"   {coverage_icon} {db}: {coverage:.1%} coverage")
    
    await manager.cleanup()

asyncio.run(perform_correlation_analysis())
```

### **AI Risk Assessment Engine** ⭐

#### **Comprehensive Risk Analysis**
```python
from src.ai_layer.agents import AIRiskAssessor, ThreatContext

async def comprehensive_risk_assessment():
    """Perform AI-powered risk assessment with business context"""
    manager = SandboxManager({"ai": {"enabled": True, "provider": "azure"}})
    await manager.initialize()
    
    # Get vulnerabilities for analysis
    scan_results = await manager.scan_package("urllib3", "1.26.16")
    
    # Collect all vulnerabilities
    all_vulnerabilities = []
    for result in scan_results.values():
        if result.success:
            all_vulnerabilities.extend(result.vulnerabilities)
    
    if not all_vulnerabilities:
        print("No vulnerabilities found for analysis")
        return
    
    # Initialize risk assessor
    risk_assessor = AIRiskAssessor(manager.ai_layer)
    
    # Define business context
    business_context = {
        "industry": "financial_services",
        "asset_criticality": "high",
        "data_sensitivity": "confidential",
        "regulatory_requirements": ["PCI-DSS", "SOX", "GDPR"]
    }
    
    # Assess individual vulnerability risk
    print(f"🔍 Individual Vulnerability Risk Assessment:")
    individual_assessments = []
    
    for i, vuln in enumerate(all_vulnerabilities[:3], 1):  # Analyze top 3
        assessment = await risk_assessor.assess_vulnerability_risk(
            vulnerability=vuln,
            package_name="urllib3",
            context=ThreatContext.PRODUCTION,
            business_context=business_context
        )
        individual_assessments.append(assessment)
        
        print(f"\n   {i}. {vuln.cve_id or vuln.title}")
        print(f"      Overall Risk Score: {assessment.overall_risk_score:.2f}")
        print(f"      AI Severity: {assessment.ai_severity_assessment.value}")
        print(f"      Business Impact: {assessment.business_impact_score:.2f}")
        print(f"      Exploit Available: {'Yes' if assessment.exploit_availability else 'No'}")
        print(f"      Urgency Level: {assessment.urgency_level}")
        print(f"      Time to Exploit: {assessment.time_to_exploit}")
        print(f"      Mitigation Complexity: {assessment.mitigation_complexity}")
        print(f"      AI Confidence: {assessment.ai_confidence:.1%}")
        print(f"      Recommendation: {assessment.ai_recommendation[:100]}...")
    
    # Assess overall package risk profile
    print(f"\n📊 Package Risk Profile Assessment:")
    package_profile = await risk_assessor.assess_package_risk_profile(
        vulnerabilities=all_vulnerabilities,
        package_name="urllib3",
        context=ThreatContext.PRODUCTION,
        business_context=business_context
    )
    
    print(f"   📦 Package: {package_profile.package_name}")
    print(f"   ⚠️  Overall Risk: {package_profile.overall_package_risk:.2f}")
    print(f"   🎯 Highest Individual Risk: {package_profile.highest_individual_risk:.2f}")
    print(f"   📈 Average Risk Score: {package_profile.average_risk_score:.2f}")
    
    print(f"\n📊 Risk Distribution:")
    print(f"   🚨 Critical: {package_profile.critical_vulnerabilities}")
    print(f"   🔴 High: {package_profile.high_risk_vulnerabilities}")
    print(f"   🟡 Medium: {package_profile.medium_risk_vulnerabilities}")
    print(f"   🟢 Low: {package_profile.low_risk_vulnerabilities}")
    
    print(f"\n💼 Business Impact Analysis:")
    print(f"   Business Impact: {package_profile.aggregate_business_impact:.2f}")
    print(f"   Compliance Risk: {package_profile.aggregate_compliance_risk:.2f}")
    print(f"   Reputational Risk: {package_profile.aggregate_reputational_risk:.2f}")
    
    print(f"\n🎯 Action Plan:")
    print(f"   Immediate Actions ({len(package_profile.immediate_actions)}):")
    for action in package_profile.immediate_actions:
        print(f"     • {action}")
    
    print(f"   Short-term Actions ({len(package_profile.short_term_actions)}):")
    for action in package_profile.short_term_actions[:3]:
        print(f"     • {action}")
    
    print(f"\n🤖 AI Strategic Assessment:")
    print(f"   {package_profile.ai_package_assessment}")
    
    print(f"\n📈 Risk Trends:")
    print(f"   {package_profile.ai_risk_trends}")
    
    print(f"\n💡 Strategic Recommendations:")
    print(f"   {package_profile.ai_strategic_recommendations}")
    
    await manager.cleanup()

asyncio.run(comprehensive_risk_assessment())
```

### **Understanding AI Results**

#### **Confidence Scoring**
```python
async def analyze_ai_confidence():
    manager = SandboxManager()
    await manager.initialize()
    
    results = await manager.scan_package("requests")
    
    for source, result in results.items():
        if result.ai_enhanced and result.vulnerabilities:
            print(f"\\n🤖 {source.upper()} AI Analysis:")
            
            for vuln in result.vulnerabilities:
                confidence = getattr(vuln, 'confidence', None)
                if confidence:
                    confidence_level = (
                        "🟢 HIGH" if confidence >= 0.8 else
                        "🟡 MEDIUM" if confidence >= 0.6 else
                        "🔴 LOW"
                    )
                    print(f"   {vuln.title}")
                    print(f"   Confidence: {confidence:.1%} {confidence_level}")
                    
                    # Show AI reasoning if available
                    if hasattr(vuln, 'ai_reasoning'):
                        print(f"   Reasoning: {vuln.ai_reasoning[:100]}...")
    
    await manager.cleanup()
```

#### **AI Recommendation Analysis**
```python
async def analyze_ai_recommendations():
    manager = SandboxManager()
    await manager.initialize()
    
    packages = ["requests", "urllib3", "pillow"]
    
    for package in packages:
        print(f"\\n📦 {package} AI Recommendations:")
        results = await manager.scan_package(package)
        
        # Aggregate AI insights
        all_recommendations = []
        for source, result in results.items():
            if result.ai_enhanced:
                for vuln in result.vulnerabilities:
                    if hasattr(vuln, 'recommendation'):
                        all_recommendations.append({
                            "source": source,
                            "cve": getattr(vuln, 'cve_id', 'N/A'),
                            "severity": vuln.severity.value,
                            "recommendation": vuln.recommendation
                        })
        
        # Show prioritized recommendations
        high_priority = [r for r in all_recommendations if r['severity'] in ['CRITICAL', 'HIGH']]
        if high_priority:
            print(f"   🚨 High Priority Actions:")
            for rec in high_priority[:3]:  # Top 3
                print(f"      • {rec['cve']}: {rec['recommendation']}")
        
        medium_priority = [r for r in all_recommendations if r['severity'] == 'MEDIUM']
        if medium_priority:
            print(f"   🟡 Medium Priority Actions:")
            for rec in medium_priority[:2]:  # Top 2
                print(f"      • {rec['cve']}: {rec['recommendation']}")
    
    await manager.cleanup()
```

## 📊 **Result Analysis & Interpretation**

### **Understanding Scan Results**

#### **Result Structure**
Each scan returns results from multiple sources:
```python
{
    "pypi": ScanResult(
        success=True,
        vulnerabilities=[...],
        ai_enhanced=True,
        cache_hit=False,
        scan_time=1.2,
        metadata={...}
    ),
    "nvd": ScanResult(...),
    "snyk": ScanResult(...),
    # ... more sources
}
```

#### **Result Aggregation**
```python
async def aggregate_and_analyze():
    manager = SandboxManager()
    await manager.initialize()
    
    results = await manager.scan_package("django", "4.2.0")
    
    # Aggregate across all sources
    aggregated = await manager.aggregate_results(results)
    
    print(f"📊 Aggregated Analysis for Django v4.2.0:")
    print(f"   Total Vulnerabilities: {len(aggregated.vulnerabilities)}")
    print(f"   Success Rate: {aggregated.metadata['success_rate']:.1%}")
    print(f"   Sources: {', '.join(aggregated.metadata['successful_sources'])}")
    
    # Severity breakdown
    severity_counts = {}
    for vuln in aggregated.vulnerabilities:
        severity = vuln.severity.value
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"   Severity Breakdown:")
    for severity, count in sorted(severity_counts.items()):
        emoji = {
            'CRITICAL': '🚨', 'HIGH': '🔴', 'MEDIUM': '🟡', 
            'LOW': '🟢', 'INFO': 'ℹ️'
        }.get(severity, '❓')
        print(f"      {emoji} {severity}: {count}")
    
    await manager.cleanup()
```

### **Risk Assessment**

#### **Vulnerability Prioritization**
```python
async def prioritize_vulnerabilities():
    manager = SandboxManager()
    await manager.initialize()
    
    packages = ["requests", "urllib3", "pillow", "django"]
    package_risks = []
    
    for package in packages:
        results = await manager.scan_package(package)
        
        # Calculate risk score
        total_vulns = sum(len(r.vulnerabilities) for r in results.values() if r.success)
        critical_vulns = 0
        high_vulns = 0
        
        for source, result in results.items():
            if result.success:
                for vuln in result.vulnerabilities:
                    if vuln.severity.value == 'CRITICAL':
                        critical_vulns += 1
                    elif vuln.severity.value == 'HIGH':
                        high_vulns += 1
        
        # Simple risk score calculation
        risk_score = (critical_vulns * 10) + (high_vulns * 5) + total_vulns
        
        package_risks.append({
            "package": package,
            "total_vulns": total_vulns,
            "critical": critical_vulns,
            "high": high_vulns,
            "risk_score": risk_score
        })
    
    # Sort by risk score
    package_risks.sort(key=lambda x: x['risk_score'], reverse=True)
    
    print(f"📊 Package Risk Assessment:")
    print(f"{'Package':<15} {'Total':<8} {'Critical':<10} {'High':<6} {'Risk Score':<12}")
    print("-" * 60)
    
    for pkg in package_risks:
        risk_level = (
            "🚨 CRITICAL" if pkg['risk_score'] >= 50 else
            "🔴 HIGH" if pkg['risk_score'] >= 20 else
            "🟡 MEDIUM" if pkg['risk_score'] >= 5 else
            "🟢 LOW"
        )
        print(f"{pkg['package']:<15} {pkg['total_vulns']:<8} {pkg['critical']:<10} {pkg['high']:<6} {pkg['risk_score']:<12} {risk_level}")
    
    await manager.cleanup()
```

## ⚙️ **Configuration & Customization**

### **AI-Enhanced Configuration** ⭐

#### **Advanced AI Configuration**
```python
# AI-enhanced configuration with correlation and risk assessment
ai_enhanced_config = {
    "ai": {
        "enabled": True,
        "provider": "azure",
        "model": "gpt-4.1",
        "temperature": 0.1,
        "timeout": 45,
        "max_retries": 3
    },
    "correlation_analysis": {
        "enabled": True,
        "confidence_threshold": 0.7,
        "max_correlations_per_vulnerability": 5,
        "dedupe_similarity_threshold": 0.8
    },
    "risk_assessment": {
        "enabled": True,
        "business_context": {
            "industry": "technology",
            "asset_criticality": "high",
            "data_sensitivity": "confidential",
            "regulatory_requirements": ["SOC2", "ISO27001"]
        },
        "threat_context": "production",
        "risk_tolerance": "low"  # low, medium, high
    },
    "performance": {
        "max_concurrent_scans": 5,
        "ai_analysis_batch_size": 3,
        "correlation_cache_ttl": 7200,  # 2 hours
        "risk_assessment_cache_ttl": 3600  # 1 hour
    }
}

# Use enhanced configuration
manager = SandboxManager(ai_enhanced_config)
```

### **System Configuration**

#### **Environment Variables**
```bash
# Azure OpenAI (Required)
export AZURE_OPENAI_ENDPOINT="https://automation-seanchen.openai.azure.com/"
export AZURE_OPENAI_KEY="your-api-key"
export AZURE_OPENAI_MODEL="gpt-4.1"
export AZURE_OPENAI_API_VERSION="2025-01-01-preview"

# AI Enhancement Settings
export AI_CORRELATION_ENABLED="true"
export AI_RISK_ASSESSMENT_ENABLED="true"
export AI_CONFIDENCE_THRESHOLD="0.7"
export AI_BATCH_SIZE="3"

# Performance Tuning
export MAX_CONCURRENT_SCANS="5"
export REQUEST_TIMEOUT="45"
export RATE_LIMIT_REQUESTS="10"
export RATE_LIMIT_PERIOD="60"

# Caching (Optional)
export REDIS_URL="redis://localhost:6379"
export REDIS_TTL="3600"
export REDIS_ENABLED="true"

# AI Caching
export AI_CORRELATION_CACHE_TTL="7200"
export AI_RISK_CACHE_TTL="3600"

# Debugging
export LOG_LEVEL="INFO"
export DEBUG_MODE="false"
```

#### **Enhanced Configuration Files**
```yaml
# config/global/settings.yaml
performance:
  max_concurrent_scans: 5
  request_timeout: 45
  batch_size: 10
  rate_limit_requests: 10
  rate_limit_period: 60
  ai_analysis_batch_size: 3

ai:
  enabled: true
  provider: "azure"
  model: "gpt-4.1"
  temperature: 0.1
  timeout: 45
  max_retries: 3

# New AI Enhancement Features
correlation_analysis:
  enabled: true
  confidence_threshold: 0.7
  max_correlations_per_vulnerability: 5
  dedupe_similarity_threshold: 0.8
  cache_ttl: 7200  # 2 hours

risk_assessment:
  enabled: true
  business_context:
    industry: "technology"
    asset_criticality: "high"
    data_sensitivity: "confidential"
    regulatory_requirements:
      - "SOC2"
      - "ISO27001"
      - "GDPR"
  threat_context: "production"  # production, development, testing, etc.
  risk_tolerance: "low"  # low, medium, high
  cache_ttl: 3600  # 1 hour

# Sandbox-specific AI configurations
sandboxes:
  snyk:
    ai_risk_assessment: true
    ai_exploit_maturity_analysis: true
  mitre:
    ai_relevance_filtering: true
    ai_search_enhancement: true
  github_advisory:
    ai_priority_scoring: true
    ai_version_assessment: true
  exploit_db:
    ai_threat_analysis: true
    ai_ioc_extraction: true

redis:
  enabled: true
  url: "redis://localhost:6379"
  ttl: 3600
  max_connections: 10
  # AI-specific cache settings
  ai_cache_prefix: "ihacpa:ai:"
  correlation_cache_ttl: 7200
  risk_assessment_cache_ttl: 3600

logging:
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file_rotation: true
  max_file_size: "10MB"
  backup_count: 5
  # AI-specific logging
  ai_analysis_log: true
  correlation_analysis_log: true
  risk_assessment_log: true
```

### **Custom AI-Enhanced Configuration**
```python
async def custom_ai_configuration():
    # Create comprehensive AI-enhanced configuration
    custom_config = {
        "ai": {
            "enabled": True,
            "provider": "azure",
            "temperature": 0.2,  # More creative responses
            "timeout": 60        # Longer timeout
        },
        "correlation_analysis": {
            "enabled": True,
            "confidence_threshold": 0.8,  # Higher confidence required
            "max_correlations_per_vulnerability": 3,  # Limit correlations
            "dedupe_similarity_threshold": 0.9  # Stricter deduplication
        },
        "risk_assessment": {
            "enabled": True,
            "business_context": {
                "industry": "healthcare",
                "asset_criticality": "critical",
                "data_sensitivity": "pii_phi",
                "regulatory_requirements": ["HIPAA", "SOC2", "GDPR"]
            },
            "threat_context": "critical_infrastructure",
            "risk_tolerance": "very_low"
        },
        "performance": {
            "max_concurrent_scans": 2,  # Conservative for critical systems
            "request_timeout": 30,
            "ai_analysis_batch_size": 1  # Process one at a time
        },
        "redis": {
            "enabled": True,
            "correlation_cache_ttl": 14400,  # 4 hours
            "risk_assessment_cache_ttl": 7200  # 2 hours
        }
    }
    
    # Use custom configuration
    manager = SandboxManager(custom_config)
    await manager.initialize()
    
    # Perform AI-enhanced scanning
    results = await manager.scan_package_with_ai_analysis(
        package_name="cryptography",
        current_version="41.0.0",
        include_correlation_analysis=True,
        include_risk_assessment=True
    )
    
    # Get enhanced summary with AI insights
    summary = await manager.get_enhanced_scan_summary(results)
    
    print(f"Healthcare-Specific Risk Analysis:")
    print(f"Overall Risk: {summary.get('risk_insights', {}).get('overall_package_risk', 'N/A')}")
    print(f"Critical Issues: {summary.get('risk_insights', {}).get('critical_vulnerabilities', 0)}")
    
    await manager.cleanup()

asyncio.run(custom_ai_configuration())
```

### **Industry-Specific Configurations**

#### **Financial Services Configuration**
```python
financial_config = {
    "risk_assessment": {
        "business_context": {
            "industry": "financial_services",
            "asset_criticality": "critical",
            "data_sensitivity": "financial_data",
            "regulatory_requirements": ["PCI-DSS", "SOX", "GDPR", "CCPA"]
        },
        "threat_context": "public_facing",
        "risk_tolerance": "very_low"
    },
    "correlation_analysis": {
        "confidence_threshold": 0.9,  # Very high confidence
        "focus_areas": ["authentication", "encryption", "data_exposure"]
    }
}
```

#### **Healthcare Configuration**
```python
healthcare_config = {
    "risk_assessment": {
        "business_context": {
            "industry": "healthcare",
            "asset_criticality": "critical",
            "data_sensitivity": "pii_phi",
            "regulatory_requirements": ["HIPAA", "HITECH", "GDPR"]
        },
        "threat_context": "critical_infrastructure",
        "risk_tolerance": "minimal"
    },
    "correlation_analysis": {
        "focus_areas": ["data_privacy", "access_control", "audit_logging"]
    }
}
```

#### **E-commerce Configuration**
```python
ecommerce_config = {
    "risk_assessment": {
        "business_context": {
            "industry": "retail_ecommerce",
            "asset_criticality": "high",
            "data_sensitivity": "customer_data",
            "regulatory_requirements": ["PCI-DSS", "GDPR", "CCPA"]
        },
        "threat_context": "public_facing",
        "risk_tolerance": "low"
    },
    "correlation_analysis": {
        "focus_areas": ["payment_processing", "session_management", "injection_attacks"]
    }
}
```

## 📈 **Monitoring & Performance**

### **Performance Monitoring**

#### **Real-time Metrics**
```python
async def monitor_performance():
    manager = SandboxManager()
    await manager.initialize()
    
    # Enable performance tracking
    manager.enable_metrics()
    
    packages = ["requests", "urllib3", "pillow"]
    
    for package in packages:
        start_time = time.time()
        results = await manager.scan_package(package)
        end_time = time.time()
        
        # Get performance metrics
        stats = await manager.get_stats()
        
        print(f"{package}:")
        print(f"  Scan time: {end_time - start_time:.2f}s")
        print(f"  Cache hits: {stats.get('cache_hits', 0)}")
        print(f"  API calls: {stats.get('api_calls', 0)}")
        print(f"  Success rate: {stats.get('success_rate', 0):.1%}")
    
    await manager.cleanup()
```

#### **Detailed Performance Analysis**
```python
import json
from datetime import datetime

def analyze_performance_metrics():
    # Load metrics from file
    try:
        with open("production_metrics.json") as f:
            data = json.load(f)
            metrics = data["metrics"]
        
        print(f"📊 Performance Analysis (as of {data['timestamp']}):")
        print(f"   Total Scans: {metrics['scan_count']}")
        
        if metrics['scan_count'] > 0:
            success_rate = (metrics['successful_scans'] / metrics['scan_count']) * 100
            avg_time = metrics['total_scan_time'] / metrics['scan_count']
            
            print(f"   Success Rate: {success_rate:.1f}%")
            print(f"   Average Scan Time: {avg_time:.2f}s")
            print(f"   Total Vulnerabilities Found: {metrics['vulnerabilities_found']}")
            
            if metrics.get('azure_api_calls', 0) > 0:
                api_efficiency = metrics['scan_count'] / metrics['azure_api_calls']
                print(f"   API Efficiency: {api_efficiency:.2f} scans per API call")
            
            if metrics.get('cache_hits', 0) > 0:
                cache_rate = (metrics['cache_hits'] / metrics['scan_count']) * 100
                print(f"   Cache Hit Rate: {cache_rate:.1f}%")
    
    except FileNotFoundError:
        print("No metrics available yet. Run some scans to generate metrics.")
```

### **Health Monitoring**

#### **System Health Checks**
```python
async def comprehensive_health_check():
    print("🔍 IHACPA v2.0 Comprehensive Health Check")
    print("=" * 50)
    
    # Test core components
    try:
        from src.core.sandbox_manager import SandboxManager
        print("✅ Core modules: Available")
    except ImportError as e:
        print(f"❌ Core modules: Failed - {e}")
        return
    
    # Test AI layer
    try:
        from src.ai_layer.chain_factory import AIChainFactory
        factory = AIChainFactory({"provider": "azure"})
        if factory.test_connection():
            print("✅ Azure OpenAI: Connected")
        else:
            print("❌ Azure OpenAI: Connection failed")
    except Exception as e:
        print(f"❌ Azure OpenAI: Failed - {e}")
    
    # Test sandbox availability
    try:
        manager = SandboxManager()
        await manager.initialize()
        sandbox_count = len([s for s in dir(manager) if 'sandbox' in s.lower()])
        print(f"✅ Sandboxes: {sandbox_count} available")
        await manager.cleanup()
    except Exception as e:
        print(f"❌ Sandboxes: Failed - {e}")
    
    # Test Redis (optional)
    try:
        import redis
        r = redis.Redis.from_url("redis://localhost:6379")
        r.ping()
        print("✅ Redis: Connected")
    except Exception:
        print("⚠️  Redis: Not available (optional)")
    
    # Test filesystem
    import os
    required_dirs = ["src/", "config/", "logs/"]
    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            print(f"✅ Directory {dir_path}: Available")
        else:
            print(f"❌ Directory {dir_path}: Missing")

# Run health check
asyncio.run(comprehensive_health_check())
```

## 🚨 **Error Handling & Troubleshooting**

### **Common Issues & Solutions**

#### **Azure OpenAI Connection Issues**
```python
async def diagnose_azure_issues():
    print("🔍 Azure OpenAI Diagnostic")
    
    # Check environment variables
    import os
    required_vars = [
        'AZURE_OPENAI_ENDPOINT',
        'AZURE_OPENAI_KEY', 
        'AZURE_OPENAI_MODEL',
        'AZURE_OPENAI_API_VERSION'
    ]
    
    print("📋 Environment Variables:")
    all_set = True
    for var in required_vars:
        value = os.getenv(var)
        if value:
            display_value = f"{value[:10]}..." if 'KEY' in var else value
            print(f"   ✅ {var}: {display_value}")
        else:
            print(f"   ❌ {var}: Not set")
            all_set = False
    
    if not all_set:
        print("\\n💡 Solution: Set missing environment variables")
        return
    
    # Test connection
    try:
        from langchain_openai import AzureChatOpenAI
        
        llm = AzureChatOpenAI(
            azure_endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
            api_key=os.getenv('AZURE_OPENAI_KEY'),
            azure_deployment=os.getenv('AZURE_OPENAI_MODEL'),
            api_version=os.getenv('AZURE_OPENAI_API_VERSION'),
            temperature=0.1
        )
        
        response = await llm.ainvoke("Test connection")
        print("✅ Azure OpenAI connection successful")
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        print("\\n💡 Solutions:")
        print("   1. Verify API key is valid")
        print("   2. Check endpoint URL format")
        print("   3. Confirm model deployment name")
        print("   4. Verify API version compatibility")

asyncio.run(diagnose_azure_issues())
```

#### **Performance Issues**
```python
async def diagnose_performance():
    print("⚡ Performance Diagnostic")
    
    manager = SandboxManager()
    await manager.initialize()
    
    # Test single package scan time
    test_package = "requests"
    start_time = time.time()
    
    try:
        results = await manager.scan_package(test_package)
        scan_time = time.time() - start_time
        
        print(f"📊 Performance Test Results:")
        print(f"   Package: {test_package}")
        print(f"   Scan Time: {scan_time:.2f}s")
        
        if scan_time > 10:
            print("⚠️  Performance Issue Detected")
            print("💡 Possible Solutions:")
            print("   1. Check Azure OpenAI latency")
            print("   2. Reduce MAX_CONCURRENT_SCANS")
            print("   3. Enable Redis caching")
            print("   4. Check network connectivity")
        elif scan_time > 5:
            print("🟡 Performance is acceptable but could be improved")
            print("💡 Suggestions:")
            print("   1. Enable Redis for caching")
            print("   2. Monitor Azure OpenAI response times")
        else:
            print("✅ Performance is excellent")
        
        # Analyze results
        successful = sum(1 for r in results.values() if r.success)
        ai_enhanced = sum(1 for r in results.values() if r.ai_enhanced)
        
        print(f"   Success Rate: {successful}/{len(results)} sources")
        print(f"   AI Enhancement: {ai_enhanced}/{len(results)} sources")
        
    except Exception as e:
        print(f"❌ Performance test failed: {e}")
    
    await manager.cleanup()

asyncio.run(diagnose_performance())
```

## 📚 **Best Practices**

### **Development Best Practices**

1. **Always Test Azure Connection First**
   ```bash
   python simple_azure_test.py
   ```

2. **Start Small, Scale Up**
   ```python
   # Test with 1-2 packages first
   await manager.scan_package("requests")
   # Then scale to larger batches
   ```

3. **Monitor Azure Costs**
   - Check Azure portal for OpenAI usage
   - Set up billing alerts
   - Use appropriate concurrency limits

4. **Use Error Handling**
   ```python
   try:
       results = await manager.scan_package(package)
   except Exception as e:
       print(f"Scan failed: {e}")
       # Handle gracefully
   ```

### **Production Best Practices**

1. **Enable Redis Caching**
   ```bash
   docker run -d -p 6379:6379 redis:latest
   export REDIS_URL="redis://localhost:6379"
   ```

2. **Set Up Monitoring**
   ```bash
   # Regular health checks
   python production_monitor.py
   
   # Monitor performance metrics
   cat production_metrics.json
   ```

3. **Configure Appropriate Limits**
   ```bash
   export MAX_CONCURRENT_SCANS="5"  # Azure-optimized
   export REQUEST_TIMEOUT="45"      # Conservative
   ```

4. **Implement Proper Logging**
   ```python
   import logging
   logging.basicConfig(level=logging.INFO)
   ```

---

**This guide covers the essential aspects of using IHACPA v2.0 effectively. For additional technical details, see the API documentation and architecture guides.**