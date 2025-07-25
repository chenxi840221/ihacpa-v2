#!/usr/bin/env python3
"""
Quick Azure OpenAI Integration Test for IHACPA v2.0
"""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

async def test_azure_openai():
    """Test Azure OpenAI integration"""
    print("🔷 Testing Azure OpenAI Integration")
    print("=" * 40)
    
    # Check environment variables
    required_vars = [
        'AZURE_OPENAI_ENDPOINT',
        'AZURE_OPENAI_KEY', 
        'AZURE_OPENAI_MODEL',
        'AZURE_OPENAI_API_VERSION'
    ]
    
    print("📋 Environment Variables:")
    for var in required_vars:
        value = os.getenv(var)
        if value:
            if 'KEY' in var:
                display_value = f"{value[:8]}..." if len(value) > 8 else "***"
            else:
                display_value = value
            print(f"   ✅ {var}={display_value}")
        else:
            print(f"   ❌ {var}=<not set>")
            return False
    
    # Test AI factory
    print("\n🤖 Testing AI Factory:")
    try:
        from ai_layer.chain_factory import AIChainFactory
        
        factory = AIChainFactory({
            "provider": "azure",
            "model": os.getenv('AZURE_OPENAI_MODEL', 'gpt-4.1'),
            "temperature": 0.1
        })
        
        # Get provider info
        info = factory.get_provider_info()
        print(f"   Provider: {info['provider']}")
        print(f"   Model: {info['model']}")
        print(f"   Has API Key: {info['has_api_key']}")
        print(f"   Is Mock: {info['is_mock']}")
        
        # Test connection
        print("\n🔗 Testing Connection:")
        if factory.test_connection():
            print("   ✅ Azure OpenAI connection successful!")
        else:
            print("   ❌ Azure OpenAI connection failed")
            return False
            
    except Exception as e:
        print(f"   ❌ AI Factory error: {e}")
        return False
    
    # Test CVE Analyzer
    print("\n🔍 Testing CVE Analyzer:")
    try:
        from ai_layer.agents.cve_analyzer import CVEAnalyzer
        
        analyzer = CVEAnalyzer(factory)
        
        # Test with a simple CVE analysis
        result = await analyzer.analyze_cve(
            cve_id="CVE-2023-TEST",
            cve_description="Test vulnerability in Python requests library affecting version 2.30.0",
            package_name="requests",
            current_version="2.30.0"
        )
        
        print(f"   ✅ CVE Analysis completed:")
        print(f"      Affected: {result.is_affected}")
        print(f"      Confidence: {result.confidence:.1%}")
        print(f"      Severity: {result.severity.value}")
        print(f"      Recommendation: {result.recommendation[:50]}...")
        
    except Exception as e:
        print(f"   ❌ CVE Analyzer error: {e}")
        return False
    
    print("\n🎉 Azure OpenAI integration test successful!")
    return True

async def test_full_pipeline():
    """Test the full scanning pipeline with Azure OpenAI"""
    print("\n🚀 Testing Full Pipeline with Azure OpenAI")
    print("=" * 50)
    
    try:
        from core.sandbox_manager import SandboxManager
        
        # Initialize with Azure configuration
        manager = SandboxManager({
            "redis": {
                "enabled": False  # Skip Redis for quick test
            },
            "ai": {
                "enabled": True,
                "provider": "azure",
                "model": os.getenv('AZURE_OPENAI_MODEL', 'gpt-4.1'),
                "temperature": 0.1,
                "timeout": 45
            }
        })
        
        print("🚀 Initializing sandbox manager...")
        await manager.initialize()
        print(f"✅ Initialized with {len(manager)} sandboxes")
        
        # Test package scan with AI
        package_name = "requests"
        current_version = "2.30.0"
        
        print(f"\n📦 Scanning {package_name} v{current_version} with AI...")
        results = await manager.scan_package(
            package_name=package_name,
            current_version=current_version
        )
        
        print(f"✅ Scan completed! Results from {len(results)} sources:")
        
        for source, result in results.items():
            print(f"\n📊 {source.upper()}:")
            print(f"   Success: {'✅' if result.success else '❌'}")
            print(f"   AI Enhanced: {'🤖' if result.ai_enhanced else '📊'}")
            print(f"   Vulnerabilities: {len(result.vulnerabilities)}")
            
            if result.vulnerabilities:
                for vuln in result.vulnerabilities[:2]:  # Show first 2
                    print(f"      • {vuln.title}")
                    if vuln.cve_id:
                        print(f"        CVE: {vuln.cve_id}")
                    print(f"        Severity: {vuln.severity.value}")
        
        await manager.cleanup()
        return True
        
    except Exception as e:
        print(f"❌ Pipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Run all tests"""
    print("🔷 IHACPA v2.0 Azure OpenAI Integration Test")
    print("=" * 60)
    
    # Test Azure OpenAI integration
    azure_test = await test_azure_openai()
    
    if azure_test:
        # Test full pipeline
        pipeline_test = await test_full_pipeline()
        
        if pipeline_test:
            print("\n🎉 All tests passed! Azure OpenAI integration is working.")
            print("\n📋 Next steps:")
            print("   1. Run full demo: python demo.py")
            print("   2. Test with your package lists")
            print("   3. Monitor Azure OpenAI usage in Azure portal")
        else:
            print("\n❌ Pipeline test failed, but Azure OpenAI is working")
    else:
        print("\n❌ Azure OpenAI integration test failed")
        print("   Check your API key and endpoint configuration")

if __name__ == "__main__":
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    asyncio.run(main())