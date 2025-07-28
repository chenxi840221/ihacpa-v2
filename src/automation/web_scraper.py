"""
Advanced Web Scraper for IHACPA v2.0

Specialized web scraping functionality for security databases and package information.
Built on top of PlaywrightManager for enhanced automation capabilities.
"""

import asyncio
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from urllib.parse import urljoin, urlparse
import logging

from .playwright_manager import PlaywrightManager


class SecurityDatabaseScraper:
    """Specialized scraper for security vulnerability databases"""
    
    def __init__(self, playwright_manager: PlaywrightManager):
        self.browser_manager = playwright_manager
        self.logger = logging.getLogger(__name__)
        
        # Common patterns for vulnerability information
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}')
        self.severity_patterns = {
            'critical': re.compile(r'\b(critical|severe)\b', re.IGNORECASE),
            'high': re.compile(r'\bhigh\b', re.IGNORECASE),
            'medium': re.compile(r'\b(medium|moderate)\b', re.IGNORECASE),
            'low': re.compile(r'\blow\b', re.IGNORECASE)
        }
        
        # Database-specific configurations
        self.db_configs = {
            'nvd': {
                'search_url': 'https://nvd.nist.gov/vuln/search',
                'selectors': {
                    'results': '[data-testid="vuln-results-table"] tbody tr',
                    'cve_id': 'td:first-child a',
                    'summary': 'td:nth-child(2)',
                    'severity': '[data-testid="vuln-cvss3-score"]'
                }
            },
            'mitre': {
                'search_url': 'https://cve.mitre.org/cgi-bin/cvekey.cgi',
                'selectors': {
                    'results': '#TableWithRules tr',
                    'cve_id': 'td:first-child a',
                    'description': 'td:nth-child(2)'
                }
            },
            'snyk': {
                'search_url': 'https://security.snyk.io/vuln',
                'selectors': {
                    'results': '.vue--table__row',
                    'title': '.vue--table__cell--title a',
                    'severity': '.severity-badge'
                }
            }
        }
    
    async def search_package_vulnerabilities(self, package_name: str, database: str = 'nvd') -> Dict[str, Any]:
        """
        Search for vulnerabilities in a specific database.
        
        Args:
            package_name: Name of the package to search
            database: Database to search ('nvd', 'mitre', 'snyk')
            
        Returns:
            Dictionary with search results
        """
        if database not in self.db_configs:
            raise ValueError(f"Unsupported database: {database}")
        
        config = self.db_configs[database]
        page = None
        
        try:
            page = await self.browser_manager.get_page(context_id=f"security_{database}")
            
            # Navigate to search page
            search_success = await self.browser_manager.navigate_with_retry(
                page, config['search_url']
            )
            
            if not search_success:
                return {'success': False, 'error': f'Failed to load {database} search page'}
            
            # Perform database-specific search
            if database == 'nvd':
                results = await self._search_nvd(page, package_name, config)
            elif database == 'mitre':
                results = await self._search_mitre(page, package_name, config)
            elif database == 'snyk':
                results = await self._search_snyk(page, package_name, config)
            else:
                results = {'success': False, 'error': f'No handler for {database}'}
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error searching {database} for {package_name}: {e}")
            return {'success': False, 'error': str(e)}
        
        finally:
            if page:
                await self.browser_manager.return_page(page)
    
    async def _search_nvd(self, page, package_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Search NVD database"""
        try:
            # Fill search form
            search_field = 'input[name="cpe_product"]'
            await self.browser_manager.fill_form_field(page, search_field, package_name)
            
            # Submit search
            submit_success = await self.browser_manager.click_and_wait(
                page, 'button[type="submit"]', wait_for=config['selectors']['results']
            )
            
            if not submit_success:
                return {'success': False, 'error': 'Search submission failed'}
            
            # Extract results
            vulnerabilities = []
            result_elements = await page.query_selector_all(config['selectors']['results'])
            
            for element in result_elements[:20]:  # Limit to first 20 results
                try:
                    cve_element = await element.query_selector(config['selectors']['cve_id'])
                    summary_element = await element.query_selector(config['selectors']['summary'])
                    severity_element = await element.query_selector(config['selectors']['severity'])
                    
                    cve_id = await cve_element.text_content() if cve_element else 'Unknown'
                    summary = await summary_element.text_content() if summary_element else 'No summary'
                    severity = await severity_element.text_content() if severity_element else 'Unknown'
                    
                    vulnerabilities.append({
                        'cve_id': cve_id.strip(),
                        'summary': summary.strip(),
                        'severity': severity.strip(),
                        'source': 'NVD'
                    })
                    
                except Exception as e:
                    self.logger.debug(f"Error extracting vulnerability data: {e}")
            
            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'total_found': len(vulnerabilities),
                'database': 'NVD'
            }
            
        except Exception as e:
            return {'success': False, 'error': f'NVD search error: {e}'}
    
    async def _search_mitre(self, page, package_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Search MITRE database"""
        try:
            # Fill search form
            search_field = 'input[name="keyword"]'
            await self.browser_manager.fill_form_field(page, search_field, package_name)
            
            # Submit search
            submit_success = await self.browser_manager.click_and_wait(
                page, 'input[type="submit"]', wait_for=config['selectors']['results']
            )
            
            if not submit_success:
                return {'success': False, 'error': 'Search submission failed'}
            
            # Extract results
            vulnerabilities = []
            result_elements = await page.query_selector_all(config['selectors']['results'])
            
            for element in result_elements[1:21]:  # Skip header, limit to 20
                try:
                    cve_element = await element.query_selector(config['selectors']['cve_id'])
                    desc_element = await element.query_selector(config['selectors']['description'])
                    
                    cve_id = await cve_element.text_content() if cve_element else 'Unknown'
                    description = await desc_element.text_content() if desc_element else 'No description'
                    
                    vulnerabilities.append({
                        'cve_id': cve_id.strip(),
                        'description': description.strip(),
                        'severity': self._extract_severity_from_text(description),
                        'source': 'MITRE'
                    })
                    
                except Exception as e:
                    self.logger.debug(f"Error extracting MITRE data: {e}")
            
            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'total_found': len(vulnerabilities),
                'database': 'MITRE'
            }
            
        except Exception as e:
            return {'success': False, 'error': f'MITRE search error: {e}'}
    
    async def _search_snyk(self, page, package_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Search Snyk database"""
        try:
            # Navigate to package-specific search
            search_url = f"{config['search_url']}/npm/{package_name}"
            
            navigate_success = await self.browser_manager.navigate_with_retry(page, search_url)
            if not navigate_success:
                return {'success': False, 'error': 'Failed to navigate to Snyk package page'}
            
            # Extract vulnerabilities
            vulnerabilities = []
            result_elements = await page.query_selector_all(config['selectors']['results'])
            
            for element in result_elements[:20]:  # Limit to first 20
                try:
                    title_element = await element.query_selector(config['selectors']['title'])
                    severity_element = await element.query_selector(config['selectors']['severity'])
                    
                    title = await title_element.text_content() if title_element else 'Unknown'
                    severity = await severity_element.text_content() if severity_element else 'Unknown'
                    
                    vulnerabilities.append({
                        'title': title.strip(),
                        'severity': severity.strip(),
                        'source': 'Snyk'
                    })
                    
                except Exception as e:
                    self.logger.debug(f"Error extracting Snyk data: {e}")
            
            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'total_found': len(vulnerabilities),
                'database': 'Snyk'
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Snyk search error: {e}'}
    
    def _extract_severity_from_text(self, text: str) -> str:
        """Extract severity level from text using patterns"""
        text_lower = text.lower()
        
        for severity, pattern in self.severity_patterns.items():
            if pattern.search(text_lower):
                return severity.upper()
        
        return 'UNKNOWN'
    
    async def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific CVE.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2023-1234)
            
        Returns:
            Detailed CVE information
        """
        page = None
        
        try:
            page = await self.browser_manager.get_page(context_id="cve_details")
            
            # Navigate to CVE details page
            cve_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            navigate_success = await self.browser_manager.navigate_with_retry(page, cve_url)
            
            if not navigate_success:
                return {'success': False, 'error': f'Failed to load CVE details for {cve_id}'}
            
            # Extract detailed information
            details = {}
            
            # Basic information
            details['cve_id'] = cve_id
            details['summary'] = await self.browser_manager.extract_text(
                page, '[data-testid="vuln-description"]'
            )
            
            # CVSS scores
            cvss3_score = await self.browser_manager.extract_text(
                page, '[data-testid="vuln-cvss3-score"]'
            )
            details['cvss3_score'] = cvss3_score
            
            # Affected configurations
            configurations = await self.browser_manager.extract_multiple_texts(
                page, '[data-testid="vuln-cpe"] code'
            )
            details['affected_configurations'] = configurations
            
            # References
            references = []
            ref_elements = await page.query_selector_all('[data-testid="vuln-references"] a')
            for ref_element in ref_elements:
                href = await ref_element.get_attribute('href')
                text = await ref_element.text_content()
                if href and text:
                    references.append({'url': href, 'text': text.strip()})
            
            details['references'] = references
            
            return {
                'success': True,
                'details': details
            }
            
        except Exception as e:
            self.logger.error(f"Error getting CVE details for {cve_id}: {e}")
            return {'success': False, 'error': str(e)}
        
        finally:
            if page:
                await self.browser_manager.return_page(page)


class PackageInfoScraper:
    """Scraper for package repository information"""
    
    def __init__(self, playwright_manager: PlaywrightManager):
        self.browser_manager = playwright_manager
        self.logger = logging.getLogger(__name__)
    
    async def get_github_repository_info(self, github_url: str) -> Dict[str, Any]:
        """
        Scrape GitHub repository information.
        
        Args:
            github_url: GitHub repository URL
            
        Returns:
            Repository information dictionary
        """
        page = None
        
        try:
            page = await self.browser_manager.get_page(context_id="github")
            
            # Navigate to repository
            navigate_success = await self.browser_manager.navigate_with_retry(page, github_url)
            if not navigate_success:
                return {'success': False, 'error': f'Failed to load GitHub page: {github_url}'}
            
            # Extract repository information
            repo_info = {}
            
            # Basic information
            repo_info['url'] = github_url
            repo_info['name'] = await self.browser_manager.extract_text(
                page, '[data-testid="repository-name"]'
            )
            repo_info['description'] = await self.browser_manager.extract_text(
                page, '[data-testid="repository-description"]'
            )
            
            # Statistics
            repo_info['stars'] = await self.browser_manager.extract_text(
                page, '#repo-stars-counter-star'
            )
            repo_info['forks'] = await self.browser_manager.extract_text(
                page, '#repo-network-counter'
            )
            repo_info['watchers'] = await self.browser_manager.extract_text(
                page, '#repo-notifications-counter'
            )
            
            # Latest release information
            try:
                release_link = await page.query_selector('[data-testid="latest-release-link"]')
                if release_link:
                    release_text = await release_link.text_content()
                    repo_info['latest_release'] = release_text.strip()
            except:
                repo_info['latest_release'] = None
            
            # Contributors count (approximate)
            try:
                contributors_link = await page.query_selector('a[href*="/graphs/contributors"]')
                if contributors_link:
                    contributors_text = await contributors_link.text_content()
                    # Extract number from text like "Contributors 45"
                    contributors_match = re.search(r'(\d+)', contributors_text)
                    repo_info['contributors'] = contributors_match.group(1) if contributors_match else None
            except:
                repo_info['contributors'] = None
            
            # Language information
            languages = await self.browser_manager.extract_multiple_texts(
                page, '[data-testid="repository-language-stats"] .d-inline span'
            )
            repo_info['languages'] = languages
            
            # Last commit information
            try:
                last_commit = await self.browser_manager.extract_text(
                    page, '[data-testid="latest-commit-details"] relative-time'
                )
                repo_info['last_commit'] = last_commit
            except:
                repo_info['last_commit'] = None
            
            return {
                'success': True,
                'repository_info': repo_info
            }
            
        except Exception as e:
            self.logger.error(f"Error scraping GitHub repository {github_url}: {e}")
            return {'success': False, 'error': str(e)}
        
        finally:
            if page:
                await self.browser_manager.return_page(page)
    
    async def get_pypi_package_page_info(self, package_name: str) -> Dict[str, Any]:
        """
        Scrape additional information from PyPI package page.
        
        Args:
            package_name: Name of the Python package
            
        Returns:
            Package page information
        """
        page = None
        
        try:
            page = await self.browser_manager.get_page(context_id="pypi")
            
            # Navigate to PyPI package page
            pypi_url = f"https://pypi.org/project/{package_name}/"
            navigate_success = await self.browser_manager.navigate_with_retry(page, pypi_url)
            
            if not navigate_success:
                return {'success': False, 'error': f'Failed to load PyPI page for {package_name}'}
            
            # Extract package information
            package_info = {}
            
            # Basic information
            package_info['name'] = package_name
            package_info['url'] = pypi_url
            
            # Description
            package_info['description'] = await self.browser_manager.extract_text(
                page, '.package-description p'
            )
            
            # Statistics
            download_stats = await self.browser_manager.extract_text(
                page, '.package-stats .package-downloads'
            )
            package_info['downloads'] = download_stats
            
            # Version information
            version = await self.browser_manager.extract_text(
                page, '.package-header h1 .package-version'
            )
            package_info['version'] = version
            
            # Release date
            release_date = await self.browser_manager.extract_text(
                page, '.package-header time'
            )
            package_info['release_date'] = release_date
            
            # Project links
            project_links = {}
            link_elements = await page.query_selector_all('.vertical-tabs a')
            for link_element in link_elements:
                href = await link_element.get_attribute('href')
                text = await link_element.text_content()
                if href and text:
                    project_links[text.strip()] = href
            
            package_info['project_links'] = project_links
            
            # Maintainers
            maintainers = await self.browser_manager.extract_multiple_texts(
                page, '.package-sidebar .author a'
            )
            package_info['maintainers'] = maintainers
            
            # Keywords/Tags
            keywords = await self.browser_manager.extract_multiple_texts(
                page, '.package-keywords a'
            )
            package_info['keywords'] = keywords
            
            return {
                'success': True,
                'package_info': package_info
            }
            
        except Exception as e:
            self.logger.error(f"Error scraping PyPI page for {package_name}: {e}")
            return {'success': False, 'error': str(e)}
        
        finally:
            if page:
                await self.browser_manager.return_page(page)


class WebScrapingOrchestrator:
    """High-level orchestrator for web scraping operations"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.browser_manager = None
        self.security_scraper = None
        self.package_scraper = None
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize all components"""
        try:
            # Initialize browser manager
            browser_config = self.config.get('browser', {})
            self.browser_manager = PlaywrightManager(browser_config)
            await self.browser_manager.initialize()
            
            # Initialize scrapers
            self.security_scraper = SecurityDatabaseScraper(self.browser_manager)
            self.package_scraper = PackageInfoScraper(self.browser_manager)
            
            self.logger.info("Web scraping orchestrator initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize web scraping orchestrator: {e}")
            raise
    
    async def comprehensive_package_analysis(self, package_name: str, github_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive web-based analysis of a package.
        
        Args:
            package_name: Name of the package
            github_url: Optional GitHub repository URL
            
        Returns:
            Comprehensive analysis results
        """
        results = {
            'package_name': package_name,
            'analysis_date': datetime.now().isoformat(),
            'vulnerability_data': {},
            'package_info': {},
            'repository_info': {},
            'errors': []
        }
        
        try:
            # Search multiple vulnerability databases
            databases = ['nvd', 'mitre', 'snyk']
            for database in databases:
                try:
                    vuln_results = await self.security_scraper.search_package_vulnerabilities(
                        package_name, database
                    )
                    results['vulnerability_data'][database] = vuln_results
                except Exception as e:
                    error_msg = f"Error searching {database}: {e}"
                    results['errors'].append(error_msg)
                    self.logger.error(error_msg)
            
            # Get PyPI package information
            try:
                pypi_results = await self.package_scraper.get_pypi_package_page_info(package_name)
                results['package_info']['pypi'] = pypi_results
            except Exception as e:
                error_msg = f"Error getting PyPI info: {e}"
                results['errors'].append(error_msg)
                self.logger.error(error_msg)
            
            # Get GitHub repository information if URL provided
            if github_url:
                try:
                    github_results = await self.package_scraper.get_github_repository_info(github_url)
                    results['repository_info']['github'] = github_results
                except Exception as e:
                    error_msg = f"Error getting GitHub info: {e}"
                    results['errors'].append(error_msg)
                    self.logger.error(error_msg)
            
            # Calculate summary statistics
            total_vulnerabilities = 0
            for db_results in results['vulnerability_data'].values():
                if db_results.get('success'):
                    total_vulnerabilities += db_results.get('total_found', 0)
            
            results['summary'] = {
                'total_vulnerabilities_found': total_vulnerabilities,
                'databases_searched': len(databases),
                'successful_searches': sum(1 for r in results['vulnerability_data'].values() if r.get('success')),
                'has_github_info': github_url is not None and results['repository_info'].get('github', {}).get('success', False),
                'has_pypi_info': results['package_info'].get('pypi', {}).get('success', False)
            }
            
            return results
            
        except Exception as e:
            error_msg = f"Error in comprehensive analysis: {e}"
            results['errors'].append(error_msg)
            self.logger.error(error_msg)
            return results
    
    async def cleanup(self):
        """Clean up resources"""
        if self.browser_manager:
            await self.browser_manager.cleanup()
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()