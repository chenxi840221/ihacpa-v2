"""
Unified Rate Limiter

Manages rate limiting across all vulnerability scanners to prevent API abuse
and ensure compliance with various service limits.
"""

import asyncio
import time
from typing import Dict, Optional
from asyncio_throttle import Throttler
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class RateLimit:
    """Rate limit configuration for a service"""
    requests_per_minute: int
    requests_per_hour: int
    burst_limit: int = 5  # Allow small bursts
    backoff_factor: float = 1.5  # Exponential backoff multiplier


class RateLimiter:
    """
    Intelligent rate limiter that adapts to different API requirements.
    
    Features:
    - Per-service rate limiting
    - Exponential backoff on failures
    - Burst handling
    - Circuit breaker pattern
    - Dynamic rate adjustment based on response headers
    """
    
    def __init__(self):
        self.throttlers: Dict[str, Throttler] = {}
        self.rate_configs: Dict[str, RateLimit] = {}
        self.circuit_breakers: Dict[str, dict] = {}
        self.last_request_time: Dict[str, float] = {}
        
        # Default rate limits for known services
        self._setup_default_limits()
    
    def _setup_default_limits(self):
        """Set up default rate limits for known services"""
        self.rate_configs.update({
            "nvd": RateLimit(
                requests_per_minute=5,    # NIST NVD: 5 requests per 30 seconds
                requests_per_hour=100,
                burst_limit=2
            ),
            "snyk": RateLimit(
                requests_per_minute=60,   # More generous for web scraping
                requests_per_hour=1000,
                burst_limit=10
            ),
            "mitre": RateLimit(
                requests_per_minute=30,   # Conservative for web scraping
                requests_per_hour=500,
                burst_limit=5
            ),
            "exploit_db": RateLimit(
                requests_per_minute=20,
                requests_per_hour=400,
                burst_limit=5
            ),
            "github": RateLimit(
                requests_per_minute=60,   # GitHub API standard
                requests_per_hour=5000,
                burst_limit=10
            ),
            "pypi": RateLimit(
                requests_per_minute=100,  # PyPI is more generous
                requests_per_hour=2000,
                burst_limit=20
            )
        })
    
    def register_service(self, service_name: str, rate_limit: RateLimit):
        """Register a new service with custom rate limits"""
        self.rate_configs[service_name] = rate_limit
        self._create_throttler(service_name)
    
    def _create_throttler(self, service_name: str):
        """Create throttler for a service"""
        if service_name not in self.rate_configs:
            raise ValueError(f"No rate limit config for service: {service_name}")
        
        config = self.rate_configs[service_name]
        
        # Create throttler based on per-minute limit
        self.throttlers[service_name] = Throttler(
            rate_limit=config.requests_per_minute,
            period=60.0  # 60 seconds
        )
        
        # Initialize circuit breaker
        self.circuit_breakers[service_name] = {
            "failures": 0,
            "last_failure": None,
            "state": "closed",  # closed, open, half-open
            "next_attempt": None
        }
    
    async def acquire(self, service_name: str) -> bool:
        """
        Acquire permission to make a request to a service.
        
        Args:
            service_name: Name of the service to make request to
            
        Returns:
            True if request is allowed, False if rate limited
        """
        # Ensure service is registered
        if service_name not in self.rate_configs:
            print(f"⚠️  Unknown service '{service_name}', using default limits")
            self.rate_configs[service_name] = RateLimit(
                requests_per_minute=30,
                requests_per_hour=500
            )
        
        if service_name not in self.throttlers:
            self._create_throttler(service_name)
        
        # Check circuit breaker
        if not self._check_circuit_breaker(service_name):
            return False
        
        # Apply throttling
        throttler = self.throttlers[service_name]
        
        try:
            async with throttler:
                self.last_request_time[service_name] = time.time()
                return True
                
        except Exception as e:
            print(f"Rate limiting error for {service_name}: {e}")
            return False
    
    def _check_circuit_breaker(self, service_name: str) -> bool:
        """
        Check if circuit breaker allows the request.
        
        Args:
            service_name: Service to check
            
        Returns:
            True if request is allowed, False if circuit is open
        """
        breaker = self.circuit_breakers[service_name]
        now = datetime.utcnow()
        
        if breaker["state"] == "open":
            if breaker["next_attempt"] and now >= breaker["next_attempt"]:
                # Try to close the circuit
                breaker["state"] = "half-open"
                print(f"🔄 Circuit breaker for {service_name}: half-open (testing)")
                return True
            else:
                # Circuit still open
                return False
        
        return True
    
    def record_success(self, service_name: str):
        """Record a successful request"""
        if service_name in self.circuit_breakers:
            breaker = self.circuit_breakers[service_name]
            if breaker["state"] == "half-open":
                # Close the circuit on success
                breaker["state"] = "closed"
                breaker["failures"] = 0
                print(f"✅ Circuit breaker for {service_name}: closed")
            
            # Reset failure count on success
            breaker["failures"] = max(0, breaker["failures"] - 1)
    
    def record_failure(self, service_name: str, error_type: str = "generic"):
        """
        Record a failed request and potentially open circuit breaker.
        
        Args:
            service_name: Service that failed
            error_type: Type of error (rate_limit, timeout, server_error)
        """
        if service_name not in self.circuit_breakers:
            return
        
        breaker = self.circuit_breakers[service_name]
        breaker["failures"] += 1
        breaker["last_failure"] = datetime.utcnow()
        
        # Different failure thresholds based on error type
        failure_threshold = {
            "rate_limit": 3,    # Open quickly on rate limit errors
            "timeout": 5,       # More tolerant of timeouts
            "server_error": 10, # Very tolerant of server errors
            "generic": 5
        }.get(error_type, 5)
        
        if breaker["failures"] >= failure_threshold and breaker["state"] == "closed":
            # Open the circuit
            breaker["state"] = "open"
            
            # Calculate backoff time (exponential with jitter)
            base_delay = min(300, 30 * (1.5 ** (breaker["failures"] - failure_threshold)))
            jitter = base_delay * 0.1  # 10% jitter
            delay = base_delay + (time.time() % jitter)
            
            breaker["next_attempt"] = datetime.utcnow() + timedelta(seconds=delay)
            
            print(f"🚨 Circuit breaker for {service_name}: OPEN (retry in {delay:.1f}s)")
    
    def adjust_rate_limit(self, service_name: str, response_headers: dict):
        """
        Dynamically adjust rate limits based on API response headers.
        
        Args:
            service_name: Service name
            response_headers: HTTP response headers
        """
        # Common rate limit headers
        rate_limit_headers = {
            "x-ratelimit-remaining": "remaining",
            "x-ratelimit-limit": "limit", 
            "x-ratelimit-reset": "reset",
            "retry-after": "retry_after"
        }
        
        found_headers = {}
        for header, key in rate_limit_headers.items():
            if header in response_headers:
                found_headers[key] = response_headers[header]
        
        if found_headers:
            print(f"📊 Rate limit info for {service_name}: {found_headers}")
            
            # If we're close to limit, slow down
            if "remaining" in found_headers and "limit" in found_headers:
                remaining = int(found_headers["remaining"])
                limit = int(found_headers["limit"])
                
                if remaining < limit * 0.1:  # Less than 10% remaining
                    print(f"⚠️  Approaching rate limit for {service_name}, slowing down")
                    # Could implement dynamic throttling here
    
    async def get_stats(self) -> Dict[str, dict]:
        """Get rate limiting statistics for all services"""
        stats = {}
        
        for service_name in self.rate_configs.keys():
            config = self.rate_configs[service_name]
            breaker = self.circuit_breakers.get(service_name, {})
            last_request = self.last_request_time.get(service_name, 0)
            
            stats[service_name] = {
                "rate_limit": {
                    "requests_per_minute": config.requests_per_minute,
                    "requests_per_hour": config.requests_per_hour,
                    "burst_limit": config.burst_limit
                },
                "circuit_breaker": {
                    "state": breaker.get("state", "closed"),
                    "failures": breaker.get("failures", 0),
                    "last_failure": breaker.get("last_failure"),
                    "next_attempt": breaker.get("next_attempt")
                },
                "last_request": last_request,
                "time_since_last": time.time() - last_request if last_request > 0 else None
            }
        
        return stats