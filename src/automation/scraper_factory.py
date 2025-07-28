"""
Scraper Factory for IHACPA v2.0

Provides web scraping capabilities for vulnerability data collection.
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Type
import logging
from abc import ABC, abstractmethod


class BaseScraper(ABC):
    """Base class for web scrapers"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()
    
    async def initialize(self):
        """Initialize the scraper"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.config.get('timeout', 30))
            self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def cleanup(self):
        """Clean up resources"""
        if self.session:
            await self.session.close()
            self.session = None
    
    @abstractmethod
    async def scrape(self, url: str, **kwargs) -> Dict[str, Any]:
        """Scrape data from URL"""
        pass


class SNYKScraper(BaseScraper):
    """SNYK vulnerability database scraper"""
    
    async def scrape(self, url: str, package_name: str = None, **kwargs) -> Dict[str, Any]:
        """
        Scrape SNYK vulnerability data.
        
        Args:
            url: SNYK URL to scrape
            package_name: Package name for context
            **kwargs: Additional parameters
            
        Returns:
            Scraped vulnerability data
        """
        try:
            await self.initialize()
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Simple parsing for demonstration
                    vulnerabilities = []
                    if 'vulnerability' in content.lower():
                        vulnerabilities.append({
                            'id': f"SNYK-{package_name or 'UNKNOWN'}",
                            'title': 'Vulnerability found via scraping',
                            'severity': 'MEDIUM',
                            'source': 'SNYK',
                            'url': url
                        })
                    
                    return {
                        'source': 'SNYK',
                        'url': url,
                        'status': 'success',
                        'vulnerabilities': vulnerabilities,
                        'total_found': len(vulnerabilities)
                    }
                else:
                    return {
                        'source': 'SNYK',
                        'url': url,
                        'status': 'error',
                        'error': f"HTTP {response.status}",
                        'vulnerabilities': [],
                        'total_found': 0
                    }
                    
        except Exception as e:
            self.logger.error(f"SNYK scraping failed for {url}: {e}")
            return {
                'source': 'SNYK',
                'url': url,
                'status': 'error',
                'error': str(e),
                'vulnerabilities': [],
                'total_found': 0
            }


class NVDScraper(BaseScraper):
    """NVD (National Vulnerability Database) scraper"""
    
    async def scrape(self, url: str, package_name: str = None, **kwargs) -> Dict[str, Any]:
        """
        Scrape NVD vulnerability data.
        
        Args:
            url: NVD URL to scrape
            package_name: Package name for context
            **kwargs: Additional parameters
            
        Returns:
            Scraped vulnerability data
        """
        try:
            await self.initialize()
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    vulnerabilities = []
                    if 'vulnerabilities' in data:
                        for vuln in data['vulnerabilities']:
                            cve_data = vuln.get('cve', {})
                            vulnerabilities.append({
                                'id': cve_data.get('id', 'UNKNOWN'),
                                'description': cve_data.get('descriptions', [{}])[0].get('value', ''),
                                'severity': self._extract_severity(vuln),
                                'source': 'NVD',
                                'published': cve_data.get('published', ''),
                                'modified': cve_data.get('lastModified', '')
                            })
                    
                    return {
                        'source': 'NVD',
                        'url': url,
                        'status': 'success',
                        'vulnerabilities': vulnerabilities,
                        'total_found': len(vulnerabilities)
                    }
                else:
                    return {
                        'source': 'NVD',
                        'url': url,
                        'status': 'error',
                        'error': f"HTTP {response.status}",
                        'vulnerabilities': [],
                        'total_found': 0
                    }
                    
        except Exception as e:
            self.logger.error(f"NVD scraping failed for {url}: {e}")
            return {
                'source': 'NVD',
                'url': url,
                'status': 'error',
                'error': str(e),
                'vulnerabilities': [],
                'total_found': 0
            }
    
    def _extract_severity(self, vulnerability: Dict[str, Any]) -> str:
        """Extract severity from NVD vulnerability data"""
        try:
            metrics = vulnerability.get('cve', {}).get('metrics', {})
            if 'cvssMetricV31' in metrics:
                return metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV30' in metrics:
                return metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV2' in metrics:
                return metrics['cvssMetricV2'][0]['baseSeverity']
            return 'UNKNOWN'
        except (KeyError, IndexError):
            return 'UNKNOWN'


class ExploitDBScraper(BaseScraper):
    """Exploit Database scraper"""
    
    async def scrape(self, url: str, package_name: str = None, **kwargs) -> Dict[str, Any]:
        """
        Scrape Exploit Database data.
        
        Args:
            url: Exploit DB URL to scrape
            package_name: Package name for context
            **kwargs: Additional parameters
            
        Returns:
            Scraped exploit data
        """
        try:
            await self.initialize()
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Simple parsing for demonstration
                    exploits = []
                    if package_name and package_name.lower() in content.lower():
                        exploits.append({
                            'id': f"EDB-{package_name}",
                            'title': f'Potential exploit for {package_name}',
                            'type': 'web',
                            'source': 'ExploitDB',
                            'url': url
                        })
                    
                    return {
                        'source': 'ExploitDB',
                        'url': url,
                        'status': 'success',
                        'exploits': exploits,
                        'total_found': len(exploits)
                    }
                else:
                    return {
                        'source': 'ExploitDB',
                        'url': url,
                        'status': 'error',
                        'error': f"HTTP {response.status}",
                        'exploits': [],
                        'total_found': 0
                    }
                    
        except Exception as e:
            self.logger.error(f"ExploitDB scraping failed for {url}: {e}")
            return {
                'source': 'ExploitDB',
                'url': url,
                'status': 'error',
                'error': str(e),
                'exploits': [],
                'total_found': 0
            }


class ScraperFactory:
    """Factory for creating vulnerability scrapers"""
    
    _scrapers: Dict[str, Type[BaseScraper]] = {
        'snyk': SNYKScraper,
        'nvd': NVDScraper,
        'exploitdb': ExploitDBScraper
    }
    
    @classmethod
    def create_scraper(cls, scraper_type: str, config: Optional[Dict[str, Any]] = None) -> BaseScraper:
        """
        Create a scraper instance.
        
        Args:
            scraper_type: Type of scraper ('snyk', 'nvd', 'exploitdb')
            config: Configuration for the scraper
            
        Returns:
            Scraper instance
            
        Raises:
            ValueError: If scraper type is not supported
        """
        if scraper_type.lower() not in cls._scrapers:
            raise ValueError(f"Unsupported scraper type: {scraper_type}")
        
        scraper_class = cls._scrapers[scraper_type.lower()]
        return scraper_class(config)
    
    @classmethod
    def get_available_scrapers(cls) -> List[str]:
        """Get list of available scraper types"""
        return list(cls._scrapers.keys())
    
    @classmethod
    def register_scraper(cls, name: str, scraper_class: Type[BaseScraper]):
        """Register a new scraper type"""
        cls._scrapers[name.lower()] = scraper_class


# Convenience functions
async def scrape_snyk(url: str, package_name: str = None, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Scrape SNYK vulnerability data"""
    async with ScraperFactory.create_scraper('snyk', config) as scraper:
        return await scraper.scrape(url, package_name=package_name)


async def scrape_nvd(url: str, package_name: str = None, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Scrape NVD vulnerability data"""
    async with ScraperFactory.create_scraper('nvd', config) as scraper:
        return await scraper.scrape(url, package_name=package_name)


async def scrape_exploitdb(url: str, package_name: str = None, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Scrape ExploitDB data"""
    async with ScraperFactory.create_scraper('exploitdb', config) as scraper:
        return await scraper.scrape(url, package_name=package_name)