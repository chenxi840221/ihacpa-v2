#!/usr/bin/env python3
"""
Azure OpenAI Environment Setup Script

Sets up environment variables for Azure OpenAI integration in IHACPA v2.0
"""

import os
import sys
import yaml
from pathlib import Path


def load_azure_settings():
    """Load Azure settings from the original project"""
    # Look for azure_settings.yaml in the parent directory
    azure_settings_path = Path(__file__).parent.parent.parent.parent / "azure_settings.yaml"
    
    if azure_settings_path.exists():
        with open(azure_settings_path, 'r') as f:
            settings = yaml.safe_load(f)
        return settings.get('azure_openai', {})
    
    return {}


def create_env_file(azure_settings):
    """Create .env file with Azure OpenAI configuration"""
    env_path = Path(__file__).parent.parent.parent / ".env"
    
    # Default values from azure_settings.yaml
    endpoint = azure_settings.get('endpoint', 'https://automation-seanchen.openai.azure.com/')
    deployment_name = azure_settings.get('deployment_name', 'gpt-4.1')
    api_version = azure_settings.get('api_version', '2025-01-01-preview')
    
    env_content = f"""# IHACPA v2.0 Azure OpenAI Configuration
# Auto-generated from azure_settings.yaml

# Azure OpenAI Configuration
AZURE_OPENAI_ENDPOINT={endpoint}
AZURE_OPENAI_KEY=your-azure-openai-key-here
AZURE_OPENAI_MODEL={deployment_name}
AZURE_OPENAI_API_VERSION={api_version}

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_DB=0

# Application Settings
ENVIRONMENT=development
DEBUG=false
LOG_LEVEL=INFO

# Performance Settings (optimized for Azure)
MAX_CONCURRENT_SCANS=2
REQUEST_TIMEOUT=45
CACHE_TTL=3600
"""
    
    with open(env_path, 'w') as f:
        f.write(env_content)
    
    print(f"✅ Created .env file at {env_path}")
    return env_path


def check_current_env():
    """Check current environment variables"""
    azure_vars = [
        'AZURE_OPENAI_ENDPOINT',
        'AZURE_OPENAI_KEY', 
        'AZURE_OPENAI_MODEL',
        'AZURE_OPENAI_API_VERSION'
    ]
    
    print("🔍 Current Azure OpenAI Environment Variables:")
    found_vars = {}
    
    for var in azure_vars:
        value = os.getenv(var)
        if value:
            # Hide the API key for security
            if 'KEY' in var:
                display_value = f"{value[:8]}..." if len(value) > 8 else "***"
            else:
                display_value = value
            print(f"   ✅ {var}={display_value}")
            found_vars[var] = value
        else:
            print(f"   ❌ {var}=<not set>")
    
    return found_vars


def setup_environment():
    """Main setup function"""
    print("🚀 Setting up Azure OpenAI Environment for IHACPA v2.0")
    print("=" * 60)
    
    # Check current environment
    current_env = check_current_env()
    
    # Load settings from azure_settings.yaml
    print("\n📁 Loading Azure settings from azure_settings.yaml...")
    azure_settings = load_azure_settings()
    
    if azure_settings:
        print("✅ Found Azure settings:")
        for key, value in azure_settings.items():
            print(f"   {key}: {value}")
    else:
        print("⚠️  No azure_settings.yaml found, using defaults")
    
    # Create .env file
    print("\n📝 Creating .env file...")
    env_path = create_env_file(azure_settings)
    
    # Instructions
    print("\n📋 Setup Instructions:")
    print("=" * 40)
    print("1. Update the .env file with your actual Azure OpenAI API key:")
    print(f"   nano {env_path}")
    print()
    print("2. Or set environment variables directly:")
    
    endpoint = azure_settings.get('endpoint', 'https://automation-seanchen.openai.azure.com/')
    deployment = azure_settings.get('deployment_name', 'gpt-4.1')
    api_version = azure_settings.get('api_version', '2025-01-01-preview')
    
    print(f'   export AZURE_OPENAI_ENDPOINT="{endpoint}"')
    print('   export AZURE_OPENAI_KEY="your-actual-api-key"')
    print(f'   export AZURE_OPENAI_MODEL="{deployment}"')
    print(f'   export AZURE_OPENAI_API_VERSION="{api_version}"')
    print()
    print("3. Test the setup:")
    print("   python demo.py")
    print()
    
    # Test connection if key is available
    if current_env.get('AZURE_OPENAI_KEY') and current_env.get('AZURE_OPENAI_ENDPOINT'):
        print("🧪 Testing Azure OpenAI connection...")
        try:
            from src.ai_layer.chain_factory import AIChainFactory
            
            factory = AIChainFactory({
                "provider": "azure",
                "model": deployment,
                "temperature": 0.1
            })
            
            if factory.test_connection():
                print("✅ Azure OpenAI connection successful!")
            else:
                print("❌ Azure OpenAI connection failed")
                
        except Exception as e:
            print(f"⚠️  Connection test failed: {e}")
    else:
        print("⚠️  Cannot test connection - API key not set")
    
    print("\n🎉 Azure OpenAI setup complete!")


if __name__ == "__main__":
    setup_environment()