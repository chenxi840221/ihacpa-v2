"""
AI Chain Factory

Central factory for creating and managing LangChain-based AI agents.
"""

import os
from typing import Dict, Any, Optional, Union
from langchain.llms.base import LLM
from langchain_openai import ChatOpenAI, OpenAI
from langchain.schema import BaseMessage
from langchain.callbacks.manager import CallbackManagerForLLMRun

try:
    from langchain_anthropic import ChatAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from langchain_openai import AzureChatOpenAI
    AZURE_OPENAI_AVAILABLE = True
except ImportError:
    AZURE_OPENAI_AVAILABLE = False


class MockLLM(LLM):
    """Mock LLM for testing when no API keys are available"""
    
    @property
    def _llm_type(self) -> str:
        return "mock"
    
    def _call(
        self,
        prompt: str,
        stop: Optional[list] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> str:
        """Mock response for testing"""
        if "cve" in prompt.lower():
            return """
            Based on the CVE information provided:
            
            **Risk Assessment**: MEDIUM
            **Confidence**: 85%
            **Recommendation**: Update to the latest version if available
            **Reasoning**: This appears to be a legitimate security vulnerability that should be addressed.
            """
        elif "version" in prompt.lower():
            return """
            **Version Analysis**: The specified version appears to be affected by this vulnerability.
            **Confidence**: 90%
            **Recommendation**: Upgrade to a patched version
            """
        else:
            return "Mock AI response for testing purposes."


class AIChainFactory:
    """
    Factory for creating AI chains and agents.
    
    Handles different AI providers (OpenAI, Anthropic, Azure) and provides
    fallback options when API keys are not available.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.provider = self.config.get("provider", "openai")
        self.model = self.config.get("model", "gpt-4")
        self.temperature = self.config.get("temperature", 0.1)
        self.max_tokens = self.config.get("max_tokens", 1000)
        self.timeout = self.config.get("timeout", 30)
        
        self._llm: Optional[LLM] = None
        self._chat_llm: Optional[Union[ChatOpenAI, Any]] = None
    
    def get_llm(self, force_mock: bool = False) -> LLM:
        """
        Get LLM instance for completion tasks.
        
        Args:
            force_mock: Force use of mock LLM for testing
            
        Returns:
            LLM instance
        """
        if self._llm and not force_mock:
            return self._llm
        
        if force_mock or not self._has_api_keys():
            print("⚠️  No API keys found, using mock LLM for testing")
            self._llm = MockLLM()
            return self._llm
        
        try:
            if self.provider == "openai":
                self._llm = OpenAI(
                    model=self.model if "gpt-" not in self.model else "gpt-3.5-turbo-instruct",
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.timeout
                )
            else:
                # Fallback to mock for unsupported providers
                print(f"⚠️  Provider '{self.provider}' not fully implemented, using mock")
                self._llm = MockLLM()
            
            return self._llm
            
        except Exception as e:
            print(f"⚠️  Failed to initialize {self.provider} LLM: {e}")
            print("   Falling back to mock LLM")
            self._llm = MockLLM()
            return self._llm
    
    def get_chat_llm(self, force_mock: bool = False) -> Union[ChatOpenAI, MockLLM, Any]:
        """
        Get Chat LLM instance for conversational tasks.
        
        Args:
            force_mock: Force use of mock LLM for testing
            
        Returns:
            Chat LLM instance
        """
        if self._chat_llm and not force_mock:
            return self._chat_llm
        
        if force_mock or not self._has_api_keys():
            print("⚠️  No API keys found, using mock chat LLM for testing")
            self._chat_llm = MockLLM()
            return self._chat_llm
        
        try:
            if self.provider == "openai":
                self._chat_llm = ChatOpenAI(
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.timeout
                )
            elif self.provider == "azure" and AZURE_OPENAI_AVAILABLE:
                # Azure OpenAI configuration
                azure_endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
                azure_api_key = os.getenv('AZURE_OPENAI_KEY')
                azure_deployment = os.getenv('AZURE_OPENAI_MODEL') or self.model
                azure_api_version = os.getenv('AZURE_OPENAI_API_VERSION', '2024-02-15-preview')
                
                if not azure_endpoint or not azure_api_key:
                    raise ValueError("Azure OpenAI requires AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_KEY")
                
                self._chat_llm = AzureChatOpenAI(
                    azure_endpoint=azure_endpoint,
                    api_key=azure_api_key,
                    azure_deployment=azure_deployment,
                    api_version=azure_api_version,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                    timeout=self.timeout
                )
                print(f"✅ Azure OpenAI initialized: {azure_deployment} at {azure_endpoint}")
                
            elif self.provider == "anthropic" and ANTHROPIC_AVAILABLE:
                self._chat_llm = ChatAnthropic(
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens_to_sample=self.max_tokens,
                    timeout=self.timeout
                )
            else:
                print(f"⚠️  Provider '{self.provider}' not available, using mock")
                self._chat_llm = MockLLM()
            
            return self._chat_llm
            
        except Exception as e:
            print(f"⚠️  Failed to initialize {self.provider} chat LLM: {e}")
            print("   Falling back to mock LLM")
            self._chat_llm = MockLLM()
            return self._chat_llm
    
    def _has_api_keys(self) -> bool:
        """Check if required API keys are available"""
        if self.provider == "openai":
            return bool(os.getenv("OPENAI_API_KEY"))
        elif self.provider == "anthropic":
            return bool(os.getenv("ANTHROPIC_API_KEY"))
        elif self.provider == "azure":
            return bool(os.getenv("AZURE_OPENAI_KEY") and os.getenv("AZURE_OPENAI_ENDPOINT"))
        return False
    
    def test_connection(self) -> bool:
        """Test if AI connection is working"""
        try:
            llm = self.get_llm()
            response = llm.invoke("Test connection")
            return bool(response and len(response) > 0)
        except Exception as e:
            print(f"AI connection test failed: {e}")
            return False
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get information about the current AI provider setup"""
        return {
            "provider": self.provider,
            "model": self.model,
            "has_api_key": self._has_api_keys(),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "is_mock": isinstance(self._llm, MockLLM) if self._llm else not self._has_api_keys()
        }


# Global factory instance
_ai_factory: Optional[AIChainFactory] = None


def get_ai_factory(config: Optional[Dict[str, Any]] = None) -> AIChainFactory:
    """Get global AI factory instance"""
    global _ai_factory
    
    if _ai_factory is None or config is not None:
        _ai_factory = AIChainFactory(config)
    
    return _ai_factory


def initialize_ai_layer(config: Dict[str, Any]) -> AIChainFactory:
    """Initialize the AI layer with configuration"""
    factory = AIChainFactory(config)
    
    # Test connection
    if factory.test_connection():
        print("✅ AI layer initialized successfully")
    else:
        print("⚠️  AI layer initialized with mock backend")
    
    return factory