# 🧪 IHACPA v2.0 Test Cases

**Comprehensive testing suite for AI-enhanced vulnerability scanning system**

## 📁 **Directory Structure**

```
testcases/
├── README.md                    # This file
├── unit/                        # Unit tests for individual components
├── integration/                 # Integration tests for system workflows
├── performance/                 # Performance and load testing
├── data/                        # Test data and sample files
├── results/                     # Test execution results (gitignored)
├── output/                      # Test output files (gitignored)
├── test_real_packages.py        # Production package testing
├── test_ai_enabled.py           # AI features demonstration
├── test_excel_packages.py       # Excel file integration testing
└── examine_excel.py             # Excel file analysis utility
```

## 🚀 **Quick Start**

### **Run Basic Package Testing**
```bash
cd testcases
python test_real_packages.py
```

### **Demonstrate AI Features**
```bash
python test_ai_enabled.py
```

### **Analyze Excel Data**
```bash
python examine_excel.py
```

## 📊 **Test Categories**

### **1. Unit Tests (`unit/`)**
Tests for individual components and functions:
- `test_sandbox_manager.py` - Core orchestration testing
- `test_ai_agents.py` - AI agent functionality
- `test_correlation_analyzer.py` - Cross-database correlation
- `test_risk_assessor.py` - Risk assessment engine
- `test_base_scanner.py` - Base scanner functionality

### **2. Integration Tests (`integration/`)**
End-to-end workflow testing:
- `test_full_scan_workflow.py` - Complete scanning process
- `test_ai_enhanced_scanning.py` - AI-enhanced scanning
- `test_multi_package_scanning.py` - Batch processing
- `test_error_handling.py` - Error recovery scenarios

### **3. Performance Tests (`performance/`)**
Performance and scalability testing:
- `test_scan_performance.py` - Scanning speed benchmarks
- `test_memory_usage.py` - Memory utilization analysis
- `test_concurrent_scans.py` - Parallel processing testing
- `test_cache_performance.py` - Caching efficiency

### **4. Test Data (`data/`)**
Sample data and configuration files:
- `sample_packages.json` - Test package definitions
- `test_vulnerabilities.json` - Mock vulnerability data
- `config_test.yaml` - Test configuration files
- `*.xlsx` - Excel test files (gitignored)

## 🧪 **Main Test Scripts**

### **test_real_packages.py**
**Purpose**: Test IHACPA v2.0 with real Python packages from Excel files
**Features**:
- Reads Excel package inventories
- Performs comprehensive vulnerability scanning
- Compares IHACPA recommendations with existing assessments
- Generates detailed performance metrics

**Usage**:
```bash
python test_real_packages.py
# Tests first 10 packages from Excel file
# Outputs: ihacpa_test_results_YYYYMMDD_HHMMSS.json
```

### **test_ai_enabled.py**
**Purpose**: Demonstrate AI-enhanced features with simulated analysis
**Features**:
- Shows cross-database correlation capabilities
- Demonstrates AI risk assessment
- Simulates business context integration
- Provides comprehensive feature overview

**Usage**:
```bash
python test_ai_enabled.py
# Demonstrates AI features with mock data
# Shows expected AI analysis outputs
```

### **test_excel_packages.py**
**Purpose**: Basic Excel integration testing
**Features**:
- Excel file parsing and validation
- Package extraction and processing
- Basic scanning workflow testing

### **examine_excel.py**
**Purpose**: Analyze Excel file structure and content
**Features**:
- Displays Excel file structure
- Identifies package names and versions
- Shows security annotations and recommendations
- Helps understand data layout

## ⚙️ **Configuration**

### **Environment Variables**
```bash
# Required for AI features
export AZURE_OPENAI_ENDPOINT="your-endpoint"
export AZURE_OPENAI_KEY="your-api-key"
export AZURE_OPENAI_MODEL="gpt-4"
export AZURE_OPENAI_API_VERSION="2024-02-01"

# Optional performance tuning
export MAX_CONCURRENT_SCANS="3"
export REQUEST_TIMEOUT="45"
export REDIS_ENABLED="false"  # For testing
```

### **Test Configuration**
Create `testcases/config_test.yaml`:
```yaml
ai:
  enabled: true
  provider: "azure"
  model: "gpt-4"
  temperature: 0.1

performance:
  max_concurrent_scans: 2
  request_timeout: 45

redis:
  enabled: false  # Disable for testing

logging:
  level: "INFO"
```

## 📈 **Test Execution**

### **Running All Tests**
```bash
# Run unit tests
python -m pytest unit/

# Run integration tests  
python -m pytest integration/

# Run performance tests
python -m pytest performance/

# Run main test scripts
python test_real_packages.py
python test_ai_enabled.py
```

### **Custom Test Execution**
```bash
# Test specific number of packages
python test_real_packages.py --limit 20

# Test with specific Excel file
python test_real_packages.py --file "custom_packages.xlsx"

# Test with AI disabled
python test_real_packages.py --no-ai
```

## 📊 **Test Results**

### **Output Files**
- `ihacpa_test_results_*.json` - Detailed test results
- `test_performance_*.json` - Performance metrics
- `test_summary_*.md` - Human-readable summaries

### **Result Structure**
```json
{
  "test_metadata": {
    "test_date": "2025-07-25T14:18:02.886137",
    "packages_tested": 10,
    "total_time": 1.68,
    "ai_enabled": true,
    "ihacpa_version": "2.0"
  },
  "summary": {
    "success_rate": 100.0,
    "total_vulnerabilities": 15,
    "unique_vulnerabilities": 12,
    "agreement_rate": 85.0
  },
  "detailed_results": [...]
}
```

## 🎯 **Test Scenarios**

### **Basic Functionality**
- ✅ Package scanning across multiple databases
- ✅ Vulnerability detection and aggregation
- ✅ Error handling and recovery
- ✅ Configuration loading and validation

### **AI Features** 
- ✅ Cross-database correlation analysis
- ✅ AI-powered risk assessment
- ✅ Business context integration
- ✅ Enhanced CVE analysis

### **Performance**
- ✅ Scan speed optimization
- ✅ Memory usage efficiency
- ✅ Concurrent processing
- ✅ Caching effectiveness

### **Integration**
- ✅ Excel file processing
- ✅ Batch package analysis
- ✅ Report generation
- ✅ API compatibility

## 🔧 **Debugging Tests**

### **Enable Debug Mode**
```bash
export LOG_LEVEL="DEBUG"
export DEBUG_MODE="true"
python test_real_packages.py
```

### **View Test Logs**
```bash
# Real-time monitoring
tail -f ../logs/ihacpa_automation_*.log

# Error analysis
grep -i "error\|failed" ../logs/ihacpa_automation_*.log
```

### **Performance Profiling**
```bash
# Profile memory usage
python -m memory_profiler test_real_packages.py

# Profile execution time
python -m cProfile test_real_packages.py
```

## 📋 **Test Checklist**

### **Before Running Tests**
- [ ] Excel test data available
- [ ] Azure OpenAI credentials configured (for AI tests)
- [ ] Python dependencies installed
- [ ] Redis available (optional)
- [ ] Sufficient disk space for results

### **Validation Points**
- [ ] All sandboxes initialize successfully
- [ ] Package scanning completes without errors
- [ ] AI analysis provides meaningful insights
- [ ] Performance meets benchmarks
- [ ] Results are properly formatted

## 🚀 **Continuous Integration**

### **Automated Testing**
```bash
# Add to CI/CD pipeline
#!/bin/bash
cd testcases
python -m pytest unit/ --verbose
python -m pytest integration/ --verbose
python test_real_packages.py --limit 5
```

### **Performance Regression Testing**
```bash
# Benchmark comparison
python performance/test_scan_performance.py --baseline
python performance/compare_performance.py
```

## 📚 **Additional Resources**

- [Main Documentation](../README.md)
- [API Reference](../API_REFERENCE.md)
- [User Guide](../USER_GUIDE.md)
- [Troubleshooting](../TROUBLESHOOTING.md)
- [AI Features](../AI_FEATURES.md)

---

**The testcases directory provides comprehensive validation of IHACPA v2.0 functionality, ensuring reliable operation across diverse environments and use cases.**