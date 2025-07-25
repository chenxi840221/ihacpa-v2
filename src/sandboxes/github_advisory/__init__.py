"""
GitHub Security Advisory Database Sandbox

Provides access to GitHub's security advisory database with AI-enhanced
analysis for package vulnerability intelligence.
"""

from .scanner import GitHubAdvisorySandbox
from .models import GitHubAdvisory, GitHubVulnerability

__all__ = ['GitHubAdvisorySandbox', 'GitHubAdvisory', 'GitHubVulnerability']