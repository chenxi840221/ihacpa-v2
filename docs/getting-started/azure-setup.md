# 🔷 Azure OpenAI Setup Guide

## 📋 Overview

IHACPA v2.0 is optimized for your existing Azure OpenAI configuration. This guide will help you set up the AI layer using your current Azure OpenAI resource.

## ⚡ Quick Setup

### 1. Auto-Setup Script
```bash
cd ihacpa-v2/
python scripts/setup/setup_azure_env.py
```

This script will:
- ✅ Read your existing `azure_settings.yaml` 
- ✅ Create `.env` file with Azure configuration
- ✅ Test the connection (if API key is available)

### 2. Manual Setup

#### Environment Variables
```bash
# Your existing Azure OpenAI configuration
export AZURE_OPENAI_ENDPOINT="https://automation-seanchen.openai.azure.com/"
export AZURE_OPENAI_KEY="your-actual-api-key-here"
export AZURE_OPENAI_MODEL="gpt-4.1"
export AZURE_OPENAI_API_VERSION="2025-01-01-preview"
```

#### .env File
Create `ihacpa-v2/.env`:
```env
# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT=https://automation-seanchen.openai.azure.com/
AZURE_OPENAI_KEY=your-actual-api-key-here
AZURE_OPENAI_MODEL=gpt-4.1
AZURE_OPENAI_API_VERSION=2025-01-01-preview

# Performance Settings (optimized for Azure)
MAX_CONCURRENT_SCANS=2
REQUEST_TIMEOUT=45
```

## 🔧 Configuration Details

### Azure OpenAI Settings (from your azure_settings.yaml)
```yaml
azure_openai:
  enabled: true
  deployment_name: "gpt-4.1"           # ✅ Your deployment
  api_version: "2025-01-01-preview"    # ✅ Latest API version
  endpoint: "https://automation-seanchen.openai.azure.com/"  # ✅ Your endpoint
  max_retries: 2
  retry_delay: 5.0
```

### Performance Optimizations
The v2.0 system includes Azure-specific optimizations:

| Setting | Value | Reason |
|---------|-------|---------|
| **Concurrent Requests** | 2 | Azure rate limit optimization |
| **Timeout** | 45s | Increased for Azure API latency |
| **Retry Delay** | 5s | Conservative retry strategy |
| **Temperature** | 0.1 | Consistent, deterministic results |

## 🧪 Test Your Setup

### 1. Connection Test
```bash
cd ihacpa-v2/
python scripts/setup/setup_azure_env.py
```

### 2. Full Demo
```bash
python demo.py
```

**Expected Output:**
```
✅ Azure OpenAI initialized: gpt-4.1 at https://automation-seanchen.openai.azure.com/
✅ AI layer initialized
✅ Registered sandbox: pypi (healthy)  
✅ Registered sandbox: nvd (healthy)

📦 Scanning requests (current version: 2.30.0)
🤖 AI Enhanced CVE analysis in progress...
```

### 3. API Test
```python
from src.ai_layer.chain_factory import AIChainFactory

# Test Azure OpenAI connection
factory = AIChainFactory({
    "provider": "azure",
    "model": "gpt-4.1"
})

print("Azure OpenAI Status:", factory.test_connection())
print("Provider Info:", factory.get_provider_info())
```

## 🎯 AI Features Available

### CVE Analysis Agent
```python
from src.ai_layer.agents.cve_analyzer import CVEAnalyzer

analyzer = CVEAnalyzer()
result = await analyzer.analyze_cve(
    cve_id="CVE-2023-32681",
    cve_description="Requests library vulnerability...",
    package_name="requests",
    current_version="2.30.0"
)

print(f"Risk Level: {result.severity}")
print(f"Confidence: {result.confidence:.1%}")
print(f"Recommendation: {result.recommendation}")
```

### Smart Version Matching
- Understands complex version ranges (`>=2.0,<3.0`)
- Handles pre-release versions (`2.1.0rc1`)
- AI-powered semantic version comparison

## 📊 Rate Limiting & Performance

### Azure OpenAI Limits
Your configuration is optimized for typical Azure limits:

| Resource | Limit | IHACPA Setting |
|----------|-------|----------------|
| **Requests/min** | 60 | 2 concurrent max |
| **Tokens/min** | 150,000 | 1,000 max per request |
| **Concurrent** | 10 | 2 parallel scans |

### Performance Monitoring
```python
# Get AI usage statistics
stats = await manager.get_stats()
ai_stats = stats.get("ai_layer", {})

print(f"AI Requests: {ai_stats.get('total_requests', 0)}")
print(f"Average Latency: {ai_stats.get('avg_latency', 0):.2f}s")
print(f"Error Rate: {ai_stats.get('error_rate', 0):.1%}")
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Connection Failed
```
❌ Azure OpenAI connection failed
```
**Solution:**
- Verify your `AZURE_OPENAI_KEY` is correct
- Check that your Azure resource is active
- Ensure your IP is not blocked

#### 2. Model Not Found  
```
❌ Model 'gpt-4.1' not found
```
**Solution:**
- Verify deployment name matches your Azure configuration
- Use the exact deployment name from Azure portal
- Check if deployment is active and not paused

#### 3. Rate Limit Exceeded
```
⚠️ Rate limit exceeded, slowing down
```
**Solution:**
- Reduce `MAX_CONCURRENT_SCANS` to 1
- Increase `REQUEST_TIMEOUT` to 60s
- Check your Azure quota usage

### Debug Mode
Enable detailed AI logging:
```bash
export DEBUG=true
export LOG_LEVEL=DEBUG
python demo.py
```

## 🔒 Security Best Practices

### API Key Management
- ✅ Store keys in environment variables, not code
- ✅ Use `.env` file for local development
- ✅ Add `.env` to `.gitignore`
- ✅ Rotate keys regularly

### Network Security
- ✅ Use HTTPS endpoints only
- ✅ Validate SSL certificates
- ✅ Monitor API usage for anomalies

## 🚀 Next Steps

1. **Run the demo**: `python demo.py`
2. **Scan your packages**: Use your existing package lists
3. **Monitor usage**: Check Azure OpenAI metrics
4. **Scale up**: Add more sandboxes (SNYK, MITRE)

Your Azure OpenAI integration is ready for production! 🎯