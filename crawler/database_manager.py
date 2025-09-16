"""
Enhanced Database Manager with IOC deduplication and relationship tracking
"""

import logging
import os
from typing import Dict, List, Set, Optional, Any
import redis
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class IOCDatabaseManager:
    """Manage IOC storage with deduplication and relationship tracking"""
    
    def __init__(self, redis_url: str = None):
        # Use environment variables if no URL provided
        if not redis_url:
            redis_password = os.getenv('REDIS_PASSWORD', '')
            redis_host = os.getenv('REDIS_HOST', 'redis')
            redis_port = os.getenv('REDIS_PORT', '6379')
            
            if redis_password:
                # Connect with authentication
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    password=redis_password,
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5
                )
            else:
                # Connect without authentication
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5
                )
        else:
            # Use provided URL
            self.redis_client = redis.Redis.from_url(
                redis_url, 
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
        
        self.duplicate_cache_ttl = 86400  # 24 hours
        
        # Test connection
        self._test_connection()
    
    def _test_connection(self):
        """Test Redis connection"""
        try:
            self.redis_client.ping()
            logger.info("✅ Redis connection successful")
        except redis.AuthenticationError:
            logger.error("❌ Redis authentication failed - check REDIS_PASSWORD")
            raise
        except redis.ConnectionError:
            logger.error("❌ Redis connection failed - check Redis server")
            raise
        except Exception as e:
            logger.error(f"❌ Redis connection error: {e}")
            raise
    
    def check_duplicate(self, content_hash: str) -> bool:
        """
        Check if IOC content hash already exists
        """
        try:
            key = f"ioc_hash:{content_hash}"
            return self.redis_client.exists(key) > 0
        except Exception as e:
            logger.error(f"Duplicate check failed: {e}")
            return False
    
    def track_ioc_hash(self, content_hash: str, ioc_data: Dict):
        """
        Track IOC hash to prevent duplicates
        """
        try:
            key = f"ioc_hash:{content_hash}"
            # Store with expiration to avoid infinite growth
            self.redis_client.setex(key, self.duplicate_cache_ttl, '1')
            
            # Also store relationship data if available
            if 'relationships' in ioc_data:
                self.store_relationships(content_hash, ioc_data['relationships'])
                
        except Exception as e:
            logger.error(f"Failed to track IOC hash: {e}")
    
    def store_relationships(self, content_hash: str, relationships: Dict):
        """
        Store IOC relationships for later analysis
        """
        try:
            rel_key = f"ioc_relationships:{content_hash}"
            # Store relationships with expiration
            self.redis_client.setex(
                rel_key, 
                self.duplicate_cache_ttl * 7,  # 7 days for relationships
                str(relationships)
            )
        except Exception as e:
            logger.error(f"Failed to store relationships: {e}")
    
    def get_related_iocs(self, content_hash: str) -> List[Dict]:
        """
        Get related IOCs for a given content hash
        """
        try:
            rel_key = f"ioc_relationships:{content_hash}"
            relationships = self.redis_client.get(rel_key)
            if relationships:
                return eval(relationships.decode())  # Safe for internal use
        except Exception as e:
            logger.error(f"Failed to get related IOCs: {e}")
        return []
    
    def bulk_check_duplicates(self, content_hashes: List[str]) -> Set[str]:
        """
        Bulk check for duplicates (optimized for performance)
        """
        duplicates = set()
        try:
            # Use pipeline for bulk operations
            pipe = self.redis_client.pipeline()
            for hash_val in content_hashes:
                pipe.exists(f"ioc_hash:{hash_val}")
            results = pipe.execute()
            
            for i, exists in enumerate(results):
                if exists:
                    duplicates.add(content_hashes[i])
                    
        except Exception as e:
            logger.error(f"Bulk duplicate check failed: {e}")
        
        return duplicates
    
    def bulk_track_hashes(self, hashes: List[tuple]):
        """Bulk track IOC hashes for performance"""
        if not hashes:
            return
            
        try:
            pipe = self.redis_client.pipeline()
            for content_hash, ioc_value, ioc_type, source in hashes:
                key = f"ioc_hash:{content_hash}"
                pipe.setex(key, self.duplicate_cache_ttl, '1')
            pipe.execute()
            logger.info(f"Bulk tracked {len(hashes)} IOC hashes")
        except Exception as e:
            logger.error(f"Bulk track failed: {e}")
    
    def cleanup_old_hashes(self, older_than_days: int = 30):
        """
        Clean up old IOC hashes to manage memory usage
        """
        try:
            # This is a simplified approach - in production, use Redis SCAN
            logger.info(f"Cleaning up IOC hashes older than {older_than_days} days")
            # Actual implementation would use Redis SCAN and TTL checks
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
