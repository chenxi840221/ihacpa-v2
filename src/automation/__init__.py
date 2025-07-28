"""
Browser Automation Framework

Playwright-based web scraping and browser automation for vulnerability scanning.
"""

from .playwright_manager import PlaywrightManager
from .scraper_factory import ScraperFactory
from .web_scraper import SecurityDatabaseScraper, PackageInfoScraper, WebScrapingOrchestrator

__all__ = [
    "PlaywrightManager", 
    "ScraperFactory",
    "SecurityDatabaseScraper",
    "PackageInfoScraper", 
    "WebScrapingOrchestrator"
]