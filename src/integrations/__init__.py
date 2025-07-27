"""
External Service Integrations for IHACPA v2.0

This module provides integration with external services like PyPI,
GitHub, and other package repositories.
"""

from .pypi_client import PyPIClient

__all__ = [
    'PyPIClient'
]