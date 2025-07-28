"""
IHACPA Python Package Review Automation
Automates cybersecurity vulnerability review for Python packages
"""

__version__ = "2.9.3"
__author__ = "IHACPA Development Team"
__email__ = "development@ihacpa.gov.au"
__description__ = "Automated Python package vulnerability assessment tool"

# Import main classes for easy access
try:
    from .excel_handler import ExcelHandler
    from .pypi_client import PyPIClient
    from .vulnerability_scanner import VulnerabilityScanner
    from .analyzer import RiskAnalyzer
except ImportError:
    # Modules not yet implemented
    pass
