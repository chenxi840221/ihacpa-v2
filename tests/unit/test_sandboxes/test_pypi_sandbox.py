"""
Unit tests for PyPI Sandbox
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import aiohttp

from src.core.base_scanner import ScanResult, VulnerabilityInfo, SeverityLevel
from src.sandboxes.pypi import PyPISandbox, PyPIPackageInfo


class TestPyPISandbox:
    """Test suite for PyPI Sandbox functionality"""
    
    @pytest.fixture
    def sandbox_config(self):
        """Basic configuration for testing"""
        return {
            "base_url": "https://pypi.org/pypi",
            "timeout": 30
        }
    
    @pytest.fixture
    def pypi_sandbox(self, sandbox_config):
        """Create PyPI sandbox instance for testing"""
        sandbox = PyPISandbox(sandbox_config)
        # Mock dependencies
        sandbox.cache_manager = Mock()
        sandbox.rate_limiter = Mock()
        sandbox.ai_layer = Mock()
        return sandbox
    
    @pytest.fixture
    def sample_pypi_response(self):
        """Sample PyPI API response for testing"""
        return {
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "summary": "Python HTTP for Humans.",
                "description": "Requests is a simple, yet elegant HTTP library.",
                "home_page": "https://requests.readthedocs.io",
                "author": "Kenneth Reitz",
                "author_email": "me@kennethreitz.org",
                "license": "Apache 2.0",
                "keywords": "http,requests,web",
                "classifiers": [
                    "Development Status :: 5 - Production/Stable",
                    "Intended Audience :: Developers"
                ],
                "requires_dist": [
                    "urllib3 (<3,>=1.21.1)",
                    "certifi (>=2017.4.17)"
                ],
                "requires_python": ">=3.7",
                "project_urls": {
                    "Homepage": "https://requests.readthedocs.io",
                    "Source": "https://github.com/psf/requests"
                }
            },
            "releases": {
                "2.31.0": [
                    {
                        "upload_time_iso_8601": "2023-05-22T14:56:11.073016Z",
                        "python_version": "py3",
                        "size": 102345,
                        "url": "https://files.pythonhosted.org/packages/.../requests-2.31.0-py3-none-any.whl",
                        "filename": "requests-2.31.0-py3-none-any.whl",
                        "digests": {"sha256": "abc123..."}
                    }
                ],
                "2.30.0": [
                    {
                        "upload_time_iso_8601": "2023-03-15T10:30:25.123456Z",
                        "python_version": "py3",
                        "size": 101234,
                        "url": "https://files.pythonhosted.org/packages/.../requests-2.30.0-py3-none-any.whl",
                        "filename": "requests-2.30.0-py3-none-any.whl",
                        "digests": {"sha256": "def456..."}
                    }
                ]
            }
        }
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, pypi_sandbox):
        """Test successful health check"""
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await pypi_sandbox.health_check()
            assert result is True
    
    @pytest.mark.asyncio
    async def test_health_check_failure(self, pypi_sandbox):
        """Test failed health check"""
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.side_effect = aiohttp.ClientError("Connection failed")
            
            result = await pypi_sandbox.health_check()
            assert result is False
    
    @pytest.mark.asyncio
    async def test_scan_package_success(self, pypi_sandbox, sample_pypi_response):
        """Test successful package scan"""
        # Mock cache miss
        pypi_sandbox.cache_manager.get_scan_result = AsyncMock(return_value=None)
        pypi_sandbox.cache_manager.cache_scan_result = AsyncMock()
        
        # Mock rate limiting
        pypi_sandbox._apply_rate_limit = AsyncMock()
        
        # Mock HTTP response
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=sample_pypi_response)
            mock_response.headers = {}
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await pypi_sandbox.scan_package("requests", "2.30.0")
            
            assert isinstance(result, ScanResult)
            assert result.success is True
            assert result.package_name == "requests"
            assert result.source == "pypi"
            assert "latest_version" in result.metadata
            assert result.metadata["latest_version"] == "2.31.0"
            
            # Should detect version update
            assert len(result.vulnerabilities) >= 1
            update_vuln = next(
                (v for v in result.vulnerabilities if "Update Available" in v.title), 
                None
            )
            assert update_vuln is not None
            assert update_vuln.severity == SeverityLevel.INFO
    
    @pytest.mark.asyncio
    async def test_scan_package_not_found(self, pypi_sandbox):
        """Test scanning non-existent package"""
        # Mock cache miss
        pypi_sandbox.cache_manager.get_scan_result = AsyncMock(return_value=None)
        pypi_sandbox.cache_manager.cache_scan_result = AsyncMock()
        
        # Mock rate limiting
        pypi_sandbox._apply_rate_limit = AsyncMock()
        
        # Mock 404 response
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 404
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await pypi_sandbox.scan_package("nonexistent-package")
            
            assert isinstance(result, ScanResult)
            assert result.success is False
            assert "not found" in result.error_message.lower()
    
    @pytest.mark.asyncio
    async def test_scan_package_cache_hit(self, pypi_sandbox):
        """Test cache hit scenario"""
        # Mock cache hit
        cached_result = ScanResult(
            package_name="requests",
            source="pypi",
            scan_time=datetime.utcnow(),
            success=True,
            vulnerabilities=[],
            cache_hit=True
        )
        pypi_sandbox.cache_manager.get_scan_result = AsyncMock(return_value=cached_result)
        
        result = await pypi_sandbox.scan_package("requests")
        
        assert result is cached_result
        assert result.cache_hit is True
    
    @pytest.mark.asyncio
    async def test_scan_package_timeout(self, pypi_sandbox):
        """Test request timeout handling"""
        # Mock cache miss
        pypi_sandbox.cache_manager.get_scan_result = AsyncMock(return_value=None)
        
        # Mock rate limiting
        pypi_sandbox._apply_rate_limit = AsyncMock()
        
        # Mock timeout
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_get.side_effect = asyncio.TimeoutError()
            
            result = await pypi_sandbox.scan_package("requests")
            
            assert isinstance(result, ScanResult)
            assert result.success is False
            assert "timeout" in result.error_message.lower()
    
    def test_package_info_parsing(self, sample_pypi_response):
        """Test PyPI response parsing"""
        package_info = PyPIPackageInfo.from_pypi_response(sample_pypi_response)
        
        assert package_info.name == "requests"
        assert package_info.version == "2.31.0"
        assert package_info.summary == "Python HTTP for Humans."
        assert package_info.author == "Kenneth Reitz"
        assert package_info.license == "Apache 2.0"
        assert len(package_info.releases) == 2
        assert "2.31.0" in package_info.releases
        assert "2.30.0" in package_info.releases
        
        # Test GitHub URL extraction
        github_url = package_info.get_github_url()
        assert github_url == "https://github.com/psf/requests"
        
        # Test version availability
        assert package_info.is_version_available("2.31.0") is True
        assert package_info.is_version_available("1.0.0") is False
    
    @pytest.mark.asyncio
    async def test_analyze_package_missing_license(self, pypi_sandbox, sample_pypi_response):
        """Test analysis of package with missing license"""
        # Modify response to remove license
        sample_pypi_response["info"]["license"] = ""
        
        package_info = PyPIPackageInfo.from_pypi_response(sample_pypi_response)
        vulnerabilities = await pypi_sandbox._analyze_package(package_info, None)
        
        license_issue = next(
            (v for v in vulnerabilities if "License" in v.title), 
            None
        )
        assert license_issue is not None
        assert license_issue.severity == SeverityLevel.LOW
    
    @pytest.mark.asyncio
    async def test_analyze_package_old_package(self, pypi_sandbox, sample_pypi_response):
        """Test analysis of very old package"""
        # Modify response to have old release date
        old_date = "2020-01-01T00:00:00.000000Z"
        sample_pypi_response["releases"]["2.31.0"][0]["upload_time_iso_8601"] = old_date
        
        package_info = PyPIPackageInfo.from_pypi_response(sample_pypi_response)
        vulnerabilities = await pypi_sandbox._analyze_package(package_info, None)
        
        maintenance_issue = next(
            (v for v in vulnerabilities if "Unmaintained" in v.title), 
            None
        )
        assert maintenance_issue is not None
        assert maintenance_issue.severity == SeverityLevel.MEDIUM
    
    @pytest.mark.asyncio
    async def test_analyze_package_suspicious_content(self, pypi_sandbox, sample_pypi_response):
        """Test analysis of package with suspicious content"""
        # Add suspicious keywords to description
        sample_pypi_response["info"]["description"] = "Download free crack and keygen for this software"
        
        package_info = PyPIPackageInfo.from_pypi_response(sample_pypi_response)
        vulnerabilities = await pypi_sandbox._analyze_package(package_info, None)
        
        suspicious_issue = next(
            (v for v in vulnerabilities if "Suspicious" in v.title), 
            None
        )
        assert suspicious_issue is not None
        assert suspicious_issue.severity == SeverityLevel.HIGH
    
    @pytest.mark.asyncio
    async def test_get_package_info_success(self, pypi_sandbox, sample_pypi_response):
        """Test convenience method for getting package info"""
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=sample_pypi_response)
            mock_get.return_value.__aenter__.return_value = mock_response
            
            package_info = await pypi_sandbox.get_package_info("requests")
            
            assert isinstance(package_info, PyPIPackageInfo)
            assert package_info.name == "requests"
    
    @pytest.mark.asyncio
    async def test_get_package_info_not_found(self, pypi_sandbox):
        """Test convenience method with non-existent package"""
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 404
            mock_get.return_value.__aenter__.return_value = mock_response
            
            package_info = await pypi_sandbox.get_package_info("nonexistent")
            
            assert package_info is None
    
    @pytest.mark.asyncio
    async def test_session_management(self, pypi_sandbox):
        """Test HTTP session creation and cleanup"""
        # Session should be None initially
        assert pypi_sandbox.session is None
        
        # Ensure session creates session
        await pypi_sandbox._ensure_session()
        assert pypi_sandbox.session is not None
        assert isinstance(pypi_sandbox.session, aiohttp.ClientSession)
        
        # Close should clean up
        await pypi_sandbox.close()
        assert pypi_sandbox.session is None


if __name__ == "__main__":
    pytest.main([__file__])