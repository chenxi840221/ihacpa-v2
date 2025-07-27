"""
Enhanced Column Processing System for IHACPA v2.0

Comprehensive column processing based on retired version analysis.
Supports all columns A-W with specialized processors.
"""

from .pypi_data import *
from .github_data import *
from .vulnerability_dbs import *
from .recommendations import *

__all__ = [
    # PyPI Data Processors (E-J)
    'DatePublishedProcessor',
    'LatestVersionProcessor', 
    'LatestReleaseDateProcessor',
    'RequirementsProcessor',
    'DevelopmentStatusProcessor',
    
    # GitHub Data Processors (K-M)
    'GitHubURLProcessor',
    'GitHubSecurityURLProcessor',
    'GitHubSecurityResultProcessor',
    
    # Vulnerability Database Processors (O-V)
    'NISTNVDProcessor',
    'MITRECVEProcessor',
    'SNYKProcessor',
    'ExploitDBProcessor',
    
    # Recommendation Processor (W)
    'RecommendationProcessor'
]