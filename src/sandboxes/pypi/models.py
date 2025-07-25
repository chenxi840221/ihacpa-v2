"""
PyPI Data Models

Pydantic models for PyPI API responses and package information.
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any
from datetime import datetime


class PyPIRelease(BaseModel):
    """Individual release information from PyPI"""
    version: str
    upload_time: datetime
    python_version: str
    size: Optional[int] = None
    url: Optional[HttpUrl] = None
    filename: Optional[str] = None
    digests: Dict[str, str] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class PyPIPackageInfo(BaseModel):
    """Complete package information from PyPI API"""
    name: str
    version: str  # Latest version
    summary: Optional[str] = None
    description: Optional[str] = None
    description_content_type: Optional[str] = None
    
    # URLs and links
    home_page: Optional[HttpUrl] = None
    package_url: Optional[HttpUrl] = None
    project_url: Optional[HttpUrl] = None
    download_url: Optional[HttpUrl] = None
    
    # Metadata
    author: Optional[str] = None
    author_email: Optional[str] = None
    maintainer: Optional[str] = None
    maintainer_email: Optional[str] = None
    license: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    classifiers: List[str] = Field(default_factory=list)
    
    # Dependencies
    requires_dist: List[str] = Field(default_factory=list)
    requires_python: Optional[str] = None
    
    # Release information
    releases: Dict[str, List[PyPIRelease]] = Field(default_factory=dict)
    latest_release_date: Optional[datetime] = None
    
    # URLs and project info
    project_urls: Dict[str, HttpUrl] = Field(default_factory=dict)
    
    # Statistics (if available)
    download_count: Optional[int] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    @classmethod
    def from_pypi_response(cls, response_data: Dict[str, Any]) -> "PyPIPackageInfo":
        """
        Create PyPIPackageInfo from PyPI API response.
        
        Args:
            response_data: Raw response from PyPI API
            
        Returns:
            Parsed PyPIPackageInfo object
        """
        info = response_data.get("info", {})
        releases = response_data.get("releases", {})
        
        # Parse releases
        parsed_releases = {}
        latest_date = None
        
        for version, release_list in releases.items():
            parsed_release_list = []
            
            for release in release_list:
                try:
                    upload_time = datetime.fromisoformat(
                        release.get("upload_time_iso_8601", "").replace("Z", "+00:00")
                    )
                    
                    if not latest_date or upload_time > latest_date:
                        latest_date = upload_time
                        
                except (ValueError, TypeError):
                    upload_time = datetime.min
                
                parsed_release = PyPIRelease(
                    version=version,
                    upload_time=upload_time,
                    python_version=release.get("python_version", "source"),
                    size=release.get("size"),
                    url=release.get("url"),
                    filename=release.get("filename"),
                    digests=release.get("digests", {})
                )
                parsed_release_list.append(parsed_release)
            
            if parsed_release_list:
                parsed_releases[version] = parsed_release_list
        
        # Parse project URLs
        project_urls = {}
        if info.get("project_urls"):
            for key, url in info["project_urls"].items():
                if url:  # Only include non-empty URLs
                    try:
                        project_urls[key] = HttpUrl(url)
                    except Exception:
                        pass  # Skip invalid URLs
        
        # Parse keywords
        keywords = []
        if info.get("keywords"):
            if isinstance(info["keywords"], str):
                keywords = [k.strip() for k in info["keywords"].split(",") if k.strip()]
            elif isinstance(info["keywords"], list):
                keywords = info["keywords"]
        
        return cls(
            name=info.get("name", ""),
            version=info.get("version", ""),
            summary=info.get("summary"),
            description=info.get("description"),
            description_content_type=info.get("description_content_type"),
            
            home_page=info.get("home_page") if info.get("home_page") else None,
            package_url=info.get("package_url") if info.get("package_url") else None,
            project_url=info.get("project_url") if info.get("project_url") else None,
            download_url=info.get("download_url") if info.get("download_url") else None,
            
            author=info.get("author"),
            author_email=info.get("author_email"),
            maintainer=info.get("maintainer"),
            maintainer_email=info.get("maintainer_email"),
            license=info.get("license"),
            keywords=keywords,
            classifiers=info.get("classifiers", []),
            
            requires_dist=info.get("requires_dist", []),
            requires_python=info.get("requires_python"),
            
            releases=parsed_releases,
            latest_release_date=latest_date,
            project_urls=project_urls
        )
    
    def get_github_url(self) -> Optional[str]:
        """Extract GitHub URL if available"""
        # Check project URLs first
        for key, url in self.project_urls.items():
            if "github.com" in str(url).lower():
                return str(url)
        
        # Check home page
        if self.home_page and "github.com" in str(self.home_page).lower():
            return str(self.home_page)
        
        return None
    
    def get_all_versions(self) -> List[str]:
        """Get all available versions sorted by release date"""
        versions_with_dates = []
        
        for version, releases in self.releases.items():
            if releases:
                # Use the earliest upload time for this version
                earliest_date = min(release.upload_time for release in releases)
                versions_with_dates.append((version, earliest_date))
        
        # Sort by date (newest first)
        versions_with_dates.sort(key=lambda x: x[1], reverse=True)
        
        return [version for version, _ in versions_with_dates]
    
    def is_version_available(self, version: str) -> bool:
        """Check if a specific version is available"""
        return version in self.releases
    
    def get_version_release_date(self, version: str) -> Optional[datetime]:
        """Get release date for a specific version"""
        if version in self.releases and self.releases[version]:
            return min(release.upload_time for release in self.releases[version])
        return None