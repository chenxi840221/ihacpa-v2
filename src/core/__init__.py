"""
IHACPA v2.0 Core Framework

This module provides the foundational classes and utilities for the
modular vulnerability scanning system.
"""

from .base_scanner import BaseSandbox, ScanResult
from .sandbox_manager import SandboxManager
from .cache_manager import CacheManager
from .rate_limiter import RateLimiter

__all__ = [
    "BaseSandbox",
    "ScanResult", 
    "SandboxManager",
    "CacheManager",
    "RateLimiter",
]