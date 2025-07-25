"""
AI Layer for IHACPA v2.0

LangChain-based AI integration for intelligent vulnerability analysis.
"""

from .chain_factory import AIChainFactory
from .agents.cve_analyzer import CVEAnalyzer
from .agents.version_matcher import VersionMatcher

__all__ = ["AIChainFactory", "CVEAnalyzer", "VersionMatcher"]