"""
Command Line Interface for IHACPA v2.0

This module provides CLI components for the application.
"""

from .parser import create_argument_parser, parse_arguments

__all__ = [
    'create_argument_parser',
    'parse_arguments'
]