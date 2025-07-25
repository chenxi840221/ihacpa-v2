# 🚀 IHACPA v2.0 Quick Start Guide

Get up and running with the new modular vulnerability scanning system in minutes!

## 📋 Prerequisites

- **Python 3.11+**
- **Docker** (for Redis)
- **Git**

## ⚡ 1-Minute Setup

### 1. Install Dependencies
```bash
cd ihacpa-v2/
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 2. Start Redis Cache
```bash
docker-compose up -d redis
```

### 3. Install Browser Automation
```bash
playwright install
```

### 4. Run Demo
```bash
python demo.py
```

That's it! 🎉 You should see vulnerability scanning in action.

## 🧪 Your First Scan

### Python API
```python
import asyncio
from src.core.sandbox_manager import SandboxManager

async def scan_package():
    # Initialize
    manager = SandboxManager()
    await manager.initialize()
    
    # Scan a package
    results = await manager.scan_package(
        package_name="requests",
        current_version="2.30.0"
    )
    
    # Check results
    for source, result in results.items():
        print(f"{source}: {len(result.vulnerabilities)} issues found")
    
    # Cleanup
    await manager.cleanup()

# Run the scan
asyncio.run(scan_package())
```

### Expected Output
```
✅ Connected to Redis at redis://localhost:6379
✅ Rate limiter initialized
✅ Registered sandbox: pypi (healthy)
✅ SandboxManager initialized with 1 sandboxes
📦 Scanning requests across 1 sources: ['pypi']
🔄 Scan completed in 0.45s: 1 successful, 0 failed, 0 cache hits

pypi: 2 issues found
  ℹ️ Package Update Available
  🟢 Missing License Information
```

## 🎯 What Just Happened?

1. **System Initialized**: Redis cache, rate limiter, and PyPI sandbox
2. **Package Scanned**: Fetched metadata from PyPI API
3. **Analysis Performed**: Checked for updates, license, suspicious patterns
4. **Results Returned**: Structured vulnerability information

## 🔧 Configuration

### Basic Configuration
```yaml
# config/global/settings.yaml
redis:
  enabled: true
  url: "redis://localhost:6379"

performance:
  parallel_scanning: true
  max_concurrent_scans: 10

ai:
  enabled: true
  provider: "openai"
  model: "gpt-4"
```

### Environment Variables
```bash
# Optional: Set API keys for enhanced features
export OPENAI_API_KEY="your-key-here"
export ANTHROPIC_API_KEY="your-key-here"
```

## 📊 Available Sandboxes

| Sandbox | Status | Description |
|---------|--------|-------------|
| **PyPI** | ✅ Ready | Package metadata and basic analysis |
| **NVD** | 🚧 Coming Soon | NIST vulnerability database |
| **SNYK** | 🚧 Coming Soon | Commercial vulnerability database |
| **MITRE** | 🚧 Coming Soon | CVE database |
| **GitHub** | 🚧 Coming Soon | GitHub security advisories |

## 🧪 Run Tests

```bash
# Unit tests
pytest tests/unit/

# Specific test
pytest tests/unit/test_sandboxes/test_pypi_sandbox.py -v

# With coverage
pytest --cov=src tests/
```

## 📈 Monitor Performance

### Redis Dashboard
Visit http://localhost:8081 to see cache performance.

### System Statistics
```python
# Get comprehensive stats
stats = await manager.get_stats()
print(f"Cache hit rate: {stats['cache_stats']['hit_rate_percent']}%")
print(f"Scan success rate: {stats['scan_stats']['successful_scans']}")
```

## 🎨 Customize Analysis

### Add Custom Checks
```python
# Create custom vulnerability detector
async def check_custom_pattern(package_info):
    if "bitcoin" in package_info.description.lower():
        return VulnerabilityInfo(
            title="Cryptocurrency Related Package",
            description="Package mentions cryptocurrency",
            severity=SeverityLevel.INFO
        )
    return None
```

### Configure Sandbox Behavior
```yaml
# config/sandboxes/pypi.yaml
pypi:
  analysis:
    flag_old_packages: true
    old_package_threshold_days: 365  # 1 year instead of 2
    
    suspicious_keywords:
      - "bitcoin"
      - "mining"
      - "wallet"
```

## 🚨 Troubleshooting

### Redis Connection Failed
```bash
# Start Redis
docker-compose up -d redis

# Check Redis status
docker-compose ps

# View Redis logs
docker-compose logs redis
```

### Import Errors
```bash
# Ensure you're in the right directory
cd ihacpa-v2/

# Install all dependencies
pip install -r requirements.txt

# Check Python path
python -c "import sys; print(sys.path)"
```

### Slow Performance
```bash
# Check Redis connection
redis-cli ping

# Monitor cache hit rate
python -c "
import asyncio
from src.core.cache_manager import CacheManager

async def check():
    cache = CacheManager()
    await cache.connect()
    stats = await cache.get_stats()
    print(f'Hit rate: {stats[\"hit_rate_percent\"]}%')

asyncio.run(check())
"
```

## 🎯 Next Steps

1. **Add More Sandboxes**: Implement NVD, SNYK scanners
2. **AI Integration**: Set up LangChain for intelligent analysis
3. **API Deployment**: Deploy as REST API with FastAPI
4. **Custom Rules**: Add organization-specific vulnerability checks
5. **Monitoring**: Set up Prometheus/Grafana dashboards

## 📚 Learn More

- [Architecture Overview](../architecture/overview.md)
- [Creating Sandboxes](../sandboxes/creating-sandbox.md)
- [AI Integration Guide](../ai-features/langchain-setup.md)
- [API Reference](../api-reference/python-api.md)

Ready to scan smarter! 🎯