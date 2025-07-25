"""
Redis Cache Manager

Handles caching of scan results to improve performance and reduce API calls.
"""

import json
import pickle
import hashlib
from typing import Any, Optional, Dict
from datetime import datetime, timedelta
import aioredis
from .base_scanner import ScanResult


class CacheManager:
    """
    Redis-based cache manager for vulnerability scan results.
    
    Features:
    - TTL-based expiration
    - Automatic serialization/deserialization
    - Key namespacing by scanner type
    - Cache statistics tracking
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379", default_ttl: int = 3600):
        self.redis_url = redis_url
        self.default_ttl = default_ttl  # 1 hour default
        self.redis: Optional[aioredis.Redis] = None
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "errors": 0
        }
    
    async def connect(self):
        """Establish Redis connection"""
        try:
            self.redis = aioredis.from_url(self.redis_url, decode_responses=False)
            # Test connection
            await self.redis.ping()
            print(f"✅ Connected to Redis at {self.redis_url}")
        except Exception as e:
            print(f"❌ Failed to connect to Redis: {e}")
            raise
    
    async def disconnect(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
    
    def _generate_cache_key(self, sandbox_name: str, package_name: str, **kwargs) -> str:
        """
        Generate a unique cache key for a scan request.
        
        Args:
            sandbox_name: Name of the scanner (pypi, nvd, etc.)
            package_name: Package being scanned
            **kwargs: Additional parameters that affect the scan
            
        Returns:
            Unique cache key
        """
        # Create a deterministic key based on all parameters
        key_data = {
            "sandbox": sandbox_name,
            "package": package_name.lower(),
            **kwargs
        }
        
        # Sort for consistency
        key_string = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.md5(key_string.encode()).hexdigest()[:12]
        
        return f"ihacpa:v2:{sandbox_name}:{package_name}:{key_hash}"
    
    async def get(self, cache_key: str) -> Optional[ScanResult]:
        """
        Retrieve a cached scan result.
        
        Args:
            cache_key: Cache key to look up
            
        Returns:
            ScanResult if found, None otherwise
        """
        if not self.redis:
            return None
            
        try:
            data = await self.redis.get(cache_key)
            if data:
                result = pickle.loads(data)
                result.cache_hit = True
                self._stats["hits"] += 1
                return result
            else:
                self._stats["misses"] += 1
                return None
                
        except Exception as e:
            self._stats["errors"] += 1
            print(f"Cache get error for key {cache_key}: {e}")
            return None
    
    async def set(self, cache_key: str, result: ScanResult, ttl: Optional[int] = None):
        """
        Cache a scan result.
        
        Args:
            cache_key: Cache key to store under
            result: ScanResult to cache
            ttl: Time to live in seconds (uses default if not specified)
        """
        if not self.redis:
            return
            
        try:
            ttl = ttl or self.default_ttl
            data = pickle.dumps(result)
            await self.redis.setex(cache_key, ttl, data)
            self._stats["sets"] += 1
            
        except Exception as e:
            self._stats["errors"] += 1
            print(f"Cache set error for key {cache_key}: {e}")
    
    async def get_scan_result(
        self, 
        sandbox_name: str, 
        package_name: str, 
        **kwargs
    ) -> Optional[ScanResult]:
        """
        High-level method to get cached scan result.
        
        Args:
            sandbox_name: Name of the scanner
            package_name: Package name
            **kwargs: Additional scan parameters
            
        Returns:
            Cached ScanResult if available
        """
        cache_key = self._generate_cache_key(sandbox_name, package_name, **kwargs)
        return await self.get(cache_key)
    
    async def cache_scan_result(
        self, 
        sandbox_name: str, 
        package_name: str, 
        result: ScanResult,
        **kwargs
    ):
        """
        High-level method to cache scan result.
        
        Args:
            sandbox_name: Name of the scanner
            package_name: Package name
            result: ScanResult to cache
            **kwargs: Additional scan parameters
        """
        cache_key = self._generate_cache_key(sandbox_name, package_name, **kwargs)
        
        # Determine TTL based on scan success and vulnerabilities found
        if result.success:
            if result.vulnerabilities:
                # Cache vulnerability findings for longer (6 hours)
                ttl = 6 * 3600
            else:
                # Cache clean results for shorter time (1 hour)
                ttl = 3600
        else:
            # Cache errors for very short time (5 minutes)
            ttl = 300
            
        await self.set(cache_key, result, ttl)
    
    async def invalidate_package(self, package_name: str):
        """
        Invalidate all cached results for a specific package.
        
        Args:
            package_name: Package to invalidate cache for
        """
        if not self.redis:
            return
            
        try:
            pattern = f"ihacpa:v2:*:{package_name}:*"
            keys = await self.redis.keys(pattern)
            if keys:
                await self.redis.delete(*keys)
                print(f"Invalidated {len(keys)} cache entries for {package_name}")
                
        except Exception as e:
            print(f"Cache invalidation error for {package_name}: {e}")
    
    async def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache performance metrics
        """
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        redis_info = {}
        if self.redis:
            try:
                info = await self.redis.info()
                redis_info = {
                    "connected_clients": info.get("connected_clients", 0),
                    "used_memory_human": info.get("used_memory_human", "0B"),
                    "keyspace_hits": info.get("keyspace_hits", 0),
                    "keyspace_misses": info.get("keyspace_misses", 0),
                }
            except Exception:
                pass
        
        return {
            "cache_stats": self._stats,
            "hit_rate_percent": round(hit_rate, 2),
            "total_requests": total_requests,
            "redis_info": redis_info,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def clear_all(self):
        """Clear all IHACPA cache entries (use with caution!)"""
        if not self.redis:
            return
            
        try:
            pattern = "ihacpa:v2:*"
            keys = await self.redis.keys(pattern)
            if keys:
                await self.redis.delete(*keys)
                print(f"Cleared {len(keys)} cache entries")
            else:
                print("No cache entries found to clear")
                
        except Exception as e:
            print(f"Cache clear error: {e}")