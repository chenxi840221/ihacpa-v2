# 🚨 IHACPA v2.0 Troubleshooting Guide

**Quick solutions to common issues**

## 🎯 **Quick Diagnostic Commands**

```bash
# System health check
python production_monitor.py

# Azure OpenAI test
python simple_azure_test.py

# Current system status
python status.py

# Check environment variables
python -c "
import os
vars_to_check = ['AZURE_OPENAI_ENDPOINT', 'AZURE_OPENAI_KEY', 'AZURE_OPENAI_MODEL']
for var in vars_to_check:
    status = '✅' if os.getenv(var) else '❌'
    print(f'{var}: {status}')
"
```

## 🚨 **Common Issues & Solutions**

### **1. Azure OpenAI Connection Failed**

#### **Symptoms:**
- `❌ Azure OpenAI: Failed - Missing credentials`
- `Connection timeout` errors
- `Authentication failed` messages

#### **Quick Fix:**
```bash
# Check credentials
echo $AZURE_OPENAI_KEY
echo $AZURE_OPENAI_ENDPOINT

# Test connection directly
python simple_azure_test.py
```

#### **Solutions:**

**Missing Environment Variables:**
```bash
# Set required variables
export AZURE_OPENAI_ENDPOINT="https://automation-seanchen.openai.azure.com/"
export AZURE_OPENAI_KEY="your-api-key"
export AZURE_OPENAI_MODEL="gpt-4.1"
export AZURE_OPENAI_API_VERSION="2025-01-01-preview"

# Make permanent by adding to ~/.bashrc or .env file
```

**Invalid API Key:**
```bash
# Verify key format (should be long alphanumeric string)
python -c "
import os
key = os.getenv('AZURE_OPENAI_KEY', '')
print(f'Key length: {len(key)}')
print(f'Key format: {\"Valid\" if len(key) > 30 else \"Invalid\"}')
"

# Get new key from Azure portal if needed
```

**Wrong Endpoint URL:**
```bash
# Verify endpoint format
python -c "
import os
endpoint = os.getenv('AZURE_OPENAI_ENDPOINT', '')
print(f'Endpoint: {endpoint}')
print(f'Format OK: {endpoint.startswith(\"https://\") and endpoint.endswith(\".openai.azure.com/\")}')
"
```

**Model Deployment Issues:**
```bash
# Verify model deployment name
python -c "
import os
model = os.getenv('AZURE_OPENAI_MODEL', '')
print(f'Model deployment: {model}')
# Should match your Azure deployment name (e.g., 'gpt-4.1')
"
```

### **2. Import Errors**

#### **Symptoms:**
- `ModuleNotFoundError: No module named 'langchain'`
- `ImportError: attempted relative import beyond top-level package`
- `No module named 'src'`

#### **Solutions:**

**Missing Dependencies:**
```bash
# Install all required packages
pip install -r requirements.txt

# Verify installation
python -c "
try:
    import langchain
    import langchain_openai
    import playwright
    print('✅ All dependencies installed')
except ImportError as e:
    print(f'❌ Missing dependency: {e}')
"
```

**Wrong Working Directory:**
```bash
# Make sure you're in the ihacpa-v2 directory
pwd  # Should show .../IHACPA-Python-Review-Automation/ihacpa-v2

# If not, navigate to correct directory
cd /path/to/IHACPA-Python-Review-Automation/ihacpa-v2
```

**Python Path Issues:**
```python
# Add current directory to Python path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# Or run from correct directory
os.chdir('/path/to/ihacpa-v2')
```

### **3. Redis Connection Issues**

#### **Symptoms:**
- `Error 111 connecting to localhost:6379`
- `Redis connection failed`
- Cache-related errors

#### **Solutions:**

**Redis Not Running:**
```bash
# Check if Redis is running
redis-cli ping
# Expected response: PONG

# Start Redis if not running
# Option 1: Docker
docker run -d -p 6379:6379 redis:latest

# Option 2: System service
sudo systemctl start redis

# Option 3: Direct command
redis-server
```

**Disable Redis (Quick Fix):**
```bash
# Run without Redis caching
export REDIS_ENABLED=false
python production_monitor.py

# Or in code
config = {"redis": {"enabled": False}}
manager = SandboxManager(config)
```

**Wrong Redis URL:**
```bash
# Check Redis URL format
echo $REDIS_URL
# Should be: redis://localhost:6379

# Test connection
python -c "
import redis
try:
    r = redis.from_url('redis://localhost:6379')
    r.ping()
    print('✅ Redis connection OK')
except Exception as e:
    print(f'❌ Redis connection failed: {e}')
"
```

### **4. Performance Issues**

#### **Symptoms:**
- Scans taking longer than 10 seconds
- Timeout errors
- High memory usage

#### **Solutions:**

**Reduce Concurrency:**
```bash
# Lower concurrent scans
export MAX_CONCURRENT_SCANS=2

# Increase timeout
export REQUEST_TIMEOUT=60
```

**Check Azure OpenAI Latency:**
```python
import time
import asyncio
from langchain_openai import AzureChatOpenAI

async def test_latency():
    llm = AzureChatOpenAI(
        azure_endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
        api_key=os.getenv('AZURE_OPENAI_KEY'),
        azure_deployment=os.getenv('AZURE_OPENAI_MODEL'),
        api_version=os.getenv('AZURE_OPENAI_API_VERSION')
    )
    
    start = time.time()
    await llm.ainvoke("Quick test")
    latency = time.time() - start
    
    print(f"Azure OpenAI latency: {latency:.2f}s")
    if latency > 5:
        print("⚠️  High latency detected - check Azure region/network")

asyncio.run(test_latency())
```

**Enable Caching:**
```bash
# Make sure Redis is enabled for better performance
export REDIS_ENABLED=true
export REDIS_URL="redis://localhost:6379"
```

### **5. High Azure OpenAI Costs**

#### **Symptoms:**
- Unexpected high charges in Azure portal
- Rate limiting messages
- Budget alerts

#### **Solutions:**

**Monitor Usage:**
```bash
# Check Azure portal for OpenAI usage
# Navigate to: Azure Portal > Your OpenAI Resource > Metrics

# Set up cost alerts in Azure
```

**Reduce API Calls:**
```bash
# Enable caching to reduce repeat calls
export REDIS_ENABLED=true

# Lower concurrency
export MAX_CONCURRENT_SCANS=2

# Use specific versions to improve cache hit rate
await manager.scan_package("requests", "2.30.0")  # More cacheable
```

**Optimize Configuration:**
```python
# Conservative configuration
config = {
    "ai": {
        "temperature": 0.1,  # Lower temperature = more deterministic = better caching
        "timeout": 30        # Shorter timeout
    },
    "performance": {
        "max_concurrent_scans": 2  # Lower concurrency
    }
}
```

### **6. AI Analysis Not Working**

#### **Symptoms:**
- `ai_enhanced: false` in all results
- No AI reasoning in outputs
- Generic vulnerability descriptions

#### **Solutions:**

**Check AI Configuration:**
```python
# Verify AI is enabled
config = {
    "ai": {
        "enabled": True,
        "provider": "azure",
        "model": "gpt-4.1"
    }
}
manager = SandboxManager(config)
```

**Test AI Components:**
```python
# Test AI factory directly
from src.ai_layer.chain_factory import AIChainFactory

factory = AIChainFactory({"provider": "azure"})
info = factory.get_provider_info()
print(f"AI Provider: {info}")

if factory.test_connection():
    print("✅ AI connection working")
else:
    print("❌ AI connection failed")
```

**Check AI Agent:**
```python
# Test CVE analyzer
from src.ai_layer.agents.cve_analyzer import CVEAnalyzer

analyzer = CVEAnalyzer(factory)
result = await analyzer.analyze_cve(
    cve_id="CVE-2023-TEST",
    cve_description="Test vulnerability",
    package_name="requests"
)
print(f"AI Analysis: {result}")
```

## 🔍 **Diagnostic Scripts**

### **Complete System Diagnostic**

```python
#!/usr/bin/env python3
"""Complete IHACPA v2.0 system diagnostic"""

import asyncio
import os
import sys
import time
from pathlib import Path

async def run_complete_diagnostic():
    print("🔍 IHACPA v2.0 Complete System Diagnostic")
    print("=" * 60)
    
    # 1. Environment Check
    print("\\n1️⃣ Environment Variables:")
    required_vars = [
        'AZURE_OPENAI_ENDPOINT',
        'AZURE_OPENAI_KEY', 
        'AZURE_OPENAI_MODEL',
        'AZURE_OPENAI_API_VERSION'
    ]
    
    env_ok = True
    for var in required_vars:
        value = os.getenv(var)
        if value:
            display = f"{value[:10]}..." if 'KEY' in var else value
            print(f"   ✅ {var}: {display}")
        else:
            print(f"   ❌ {var}: Not set")
            env_ok = False
    
    if not env_ok:
        print("   💡 Fix: Set missing environment variables")
        return
    
    # 2. Dependencies Check
    print("\\n2️⃣ Dependencies:")
    deps = ['langchain', 'langchain_openai', 'playwright', 'redis', 'aioredis']
    for dep in deps:
        try:
            __import__(dep)
            print(f"   ✅ {dep}: Available")
        except ImportError:
            print(f"   ❌ {dep}: Missing")
    
    # 3. File System Check
    print("\\n3️⃣ File System:")
    required_paths = [
        'src/core/sandbox_manager.py',
        'src/ai_layer/chain_factory.py',
        'config/global/settings.yaml'
    ]
    
    for path in required_paths:
        if Path(path).exists():
            print(f"   ✅ {path}: Exists")
        else:
            print(f"   ❌ {path}: Missing")
    
    # 4. Azure OpenAI Test
    print("\\n4️⃣ Azure OpenAI Connection:")
    try:
        from langchain_openai import AzureChatOpenAI
        
        llm = AzureChatOpenAI(
            azure_endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
            api_key=os.getenv('AZURE_OPENAI_KEY'),
            azure_deployment=os.getenv('AZURE_OPENAI_MODEL'),
            api_version=os.getenv('AZURE_OPENAI_API_VERSION'),
            temperature=0.1
        )
        
        start_time = time.time()
        response = await llm.ainvoke("Test connection")
        latency = time.time() - start_time
        
        print(f"   ✅ Connection: Successful")
        print(f"   ⏱️ Latency: {latency:.2f}s")
        
        if latency > 5:
            print(f"   ⚠️  High latency - check network/region")
        
    except Exception as e:
        print(f"   ❌ Connection failed: {e}")
    
    # 5. Redis Test
    print("\\n5️⃣ Redis Connection:")
    try:
        import redis
        r = redis.Redis.from_url("redis://localhost:6379")
        r.ping()
        print("   ✅ Redis: Connected")
    except Exception as e:
        print(f"   ⚠️  Redis: Not available - {e}")
        print("   💡 Optional: Redis improves performance but not required")
    
    # 6. Core System Test
    print("\\n6️⃣ Core System Test:")
    try:
        sys.path.insert(0, str(Path.cwd() / 'src'))
        from core.sandbox_manager import SandboxManager
        
        manager = SandboxManager({"redis": {"enabled": False}})
        await manager.initialize()
        
        # Quick scan test
        start_time = time.time()
        results = await manager.scan_package("requests")
        scan_time = time.time() - start_time
        
        successful = sum(1 for r in results.values() if r.success)
        ai_enhanced = sum(1 for r in results.values() if r.ai_enhanced)
        
        print(f"   ✅ Scan test: Successful")
        print(f"   ⏱️ Scan time: {scan_time:.2f}s")
        print(f"   📊 Success rate: {successful}/{len(results)} sources")
        print(f"   🤖 AI enhanced: {ai_enhanced}/{len(results)} sources")
        
        await manager.cleanup()
        
    except Exception as e:
        print(f"   ❌ Core system test failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\\n✅ Diagnostic Complete!")
    print("\\n📋 Next Steps:")
    print("   1. Fix any ❌ issues above")
    print("   2. Run: python simple_azure_test.py")
    print("   3. Try: python production_monitor.py")

# Run diagnostic
if __name__ == "__main__":
    asyncio.run(run_complete_diagnostic())
```

### **Performance Diagnostic**

```python
#!/usr/bin/env python3
"""Performance diagnostic and optimization suggestions"""

import asyncio
import time
import psutil
import os

async def performance_diagnostic():
    print("⚡ IHACPA v2.0 Performance Diagnostic")
    print("=" * 50)
    
    # System resources
    print("\\n💻 System Resources:")
    memory = psutil.virtual_memory()
    cpu_percent = psutil.cpu_percent()
    print(f"   RAM: {memory.available / 1024**3:.1f}GB available / {memory.total / 1024**3:.1f}GB total")
    print(f"   CPU: {cpu_percent}% usage")
    
    if memory.available < 2 * 1024**3:  # Less than 2GB
        print("   ⚠️  Low memory - consider reducing concurrency")
    
    # Network latency test
    print("\\n🌐 Network Latency Test:")
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            start = time.time()
            async with session.get('https://www.google.com') as response:
                latency = time.time() - start
                print(f"   Internet latency: {latency:.2f}s")
                
                if latency > 2:
                    print("   ⚠️  High network latency detected")
    except Exception as e:
        print(f"   ❌ Network test failed: {e}")
    
    # Azure OpenAI latency
    print("\\n🤖 Azure OpenAI Performance:")
    try:
        from langchain_openai import AzureChatOpenAI
        
        llm = AzureChatOpenAI(
            azure_endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
            api_key=os.getenv('AZURE_OPENAI_KEY'),
            azure_deployment=os.getenv('AZURE_OPENAI_MODEL'),
            api_version=os.getenv('AZURE_OPENAI_API_VERSION')
        )
        
        # Test multiple calls
        latencies = []
        for i in range(3):
            start = time.time()
            await llm.ainvoke(f"Test call {i}")
            latencies.append(time.time() - start)
        
        avg_latency = sum(latencies) / len(latencies)
        print(f"   Average latency: {avg_latency:.2f}s")
        print(f"   Min/Max: {min(latencies):.2f}s / {max(latencies):.2f}s")
        
        if avg_latency > 5:
            print("   ⚠️  High Azure OpenAI latency")
            print("   💡 Suggestions:")
            print("      - Check Azure region (closer = faster)")
            print("      - Verify network connectivity")
            print("      - Consider increasing timeout")
    
    except Exception as e:
        print(f"   ❌ Azure OpenAI test failed: {e}")
    
    # Performance recommendations
    print("\\n📊 Performance Recommendations:")
    
    # Based on system resources
    if memory.available > 4 * 1024**3:  # More than 4GB
        print("   ✅ System has sufficient memory")
        print("   💡 You can use MAX_CONCURRENT_SCANS=5")
    else:
        print("   ⚠️  Limited memory detected")
        print("   💡 Recommended: MAX_CONCURRENT_SCANS=2")
    
    # Based on network
    if 'latency' in locals() and latency < 1:
        print("   ✅ Good network performance")
    else:
        print("   💡 Consider enabling Redis caching for better performance")
    
    print("\\n🔧 Optimization Commands:")
    print("   # Conservative settings")
    print("   export MAX_CONCURRENT_SCANS=2")
    print("   export REQUEST_TIMEOUT=60")
    print("   ")
    print("   # Enable caching")
    print("   docker run -d -p 6379:6379 redis:latest")
    print("   export REDIS_ENABLED=true")

if __name__ == "__main__":
    asyncio.run(performance_diagnostic())
```

## 📊 **Monitoring & Debugging**

### **Enable Debug Mode**
```bash
# Set debug environment
export LOG_LEVEL=DEBUG
export DEBUG_MODE=true

# Run with verbose output
python production_monitor.py
```

### **View Logs**
```bash
# Real-time log monitoring
tail -f logs/ihacpa_automation_*.log

# Error logs only
tail -f logs/ihacpa_automation_errors_*.log

# Search logs for specific issues
grep -i "error\\|failed\\|timeout" logs/ihacpa_automation_*.log
```

### **Performance Metrics**
```bash
# View current metrics
cat production_metrics.json | jq '.'

# Monitor in real-time
watch -n 5 "cat production_metrics.json | jq '.metrics'"
```

## 🆘 **Emergency Recovery**

### **System Not Responding**
```bash
# Kill all Python processes (if hung)
pkill -f python

# Restart with minimal configuration
export MAX_CONCURRENT_SCANS=1
export REDIS_ENABLED=false
python simple_azure_test.py
```

### **Complete Reset**
```bash
# Clear all cache and temporary files
rm -f production_metrics.json
rm -f logs/*.log

# Reset to default configuration
unset REDIS_URL
unset MAX_CONCURRENT_SCANS
export REDIS_ENABLED=false

# Test basic functionality
python simple_azure_test.py
```

### **Rollback to v1.0 (Emergency Only)**
```bash
# Only if v2.0 is completely broken
cp -r legacy/v1.0/backup_*/src ../src
cp legacy/v1.0/backup_*/requirements.txt ../requirements.txt

echo "⚠️  Rolled back to v1.0 - investigate v2.0 issues"
```

## 📞 **Getting Help**

### **Self-Diagnostic Checklist**
1. ✅ Run `python simple_azure_test.py`
2. ✅ Check `python production_monitor.py`
3. ✅ Verify environment variables are set
4. ✅ Confirm dependencies are installed
5. ✅ Check logs for specific error messages

### **Information to Collect**
When reporting issues, include:
- Output of `python simple_azure_test.py`
- Recent log entries from `logs/`
- Environment variable status (without API keys)
- System specifications (RAM, OS, Python version)
- Error messages with full stack traces

---

**Most issues can be resolved by following the solutions above. For persistent problems, use the diagnostic scripts to gather detailed information.**