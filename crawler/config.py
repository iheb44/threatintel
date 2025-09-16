"""
Configuration classes for the threat intelligence crawler
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

@dataclass
class EnhancedCrawlerConfig:
    """Enhanced crawler configuration with validation"""
    elasticsearch_hosts: List[str] = field(default_factory=lambda: ["http://elasticsearch:9200"])
    postgres_dsn: Optional[str] = None
    redis_url: Optional[str] = None
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    use_tor: bool = False
    tor_proxy: str = "socks5h://tor:9050"
    request_timeout: int = 30
    max_retries: int = 5
    concurrent_requests: int = 3
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) ThreatIntelCrawler/2.0"
    rate_limit_delay: float = 2.0
    crawl_interval: int = 1800
    max_failures_before_skip: int = 3
    failure_cooldown: int = 3600
    dynamic_rate_limiting: bool = True
    geoip_enabled: bool = True
    asn_enabled: bool = True
    enrichment_timeout: int = 5
    normalization_enabled: bool = True
    otx_api_key: Optional[str] = None
    vt_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    
    def __post_init__(self):
        """Initialize from environment variables with validation"""
        self.elasticsearch_hosts = os.getenv("ELASTICSEARCH_HOSTS", "").split(",") or self.elasticsearch_hosts
        self.postgres_dsn = os.getenv("POSTGRES_DSN", self.postgres_dsn)
        self.redis_url = os.getenv("REDIS_URL", self.redis_url)
        
        # Redis configuration
        self.redis_host = os.getenv("REDIS_HOST", self.redis_host)
        self.redis_port = int(os.getenv("REDIS_PORT", str(self.redis_port)))
        self.redis_db = int(os.getenv("REDIS_DB", str(self.redis_db)))
        self.redis_password = os.getenv("REDIS_PASSWORD", self.redis_password)
        
        # Set up Redis URL if not provided
        self._setup_redis_url()
        
        # Other configuration
        self.use_tor = os.getenv("USE_TOR", "false").lower() == "true"
        self.tor_proxy = os.getenv("TOR_PROXY", self.tor_proxy)
        self.request_timeout = int(os.getenv("REQUEST_TIMEOUT", str(self.request_timeout)))
        self.max_retries = int(os.getenv("MAX_RETRIES", str(self.max_retries)))
        self.concurrent_requests = int(os.getenv("CONCURRENT_REQUESTS", str(self.concurrent_requests)))
        self.user_agent = os.getenv("USER_AGENT", self.user_agent)
        self.rate_limit_delay = float(os.getenv("RATE_LIMIT_DELAY", str(self.rate_limit_delay)))
        self.crawl_interval = int(os.getenv("CRAWL_INTERVAL", str(self.crawl_interval)))
        self.max_failures_before_skip = int(os.getenv("MAX_FAILURES_BEFORE_SKIP", str(self.max_failures_before_skip)))
        self.failure_cooldown = int(os.getenv("FAILURE_COOLDOWN", str(self.failure_cooldown)))
        self.dynamic_rate_limiting = os.getenv("DYNAMIC_RATE_LIMITING", "true").lower() == "true"
        self.geoip_enabled = os.getenv("GEOIP_ENABLED", "true").lower() == "true"
        self.asn_enabled = os.getenv("ASN_ENABLED", "true").lower() == "true"
        self.enrichment_timeout = int(os.getenv("ENRICHMENT_TIMEOUT", str(self.enrichment_timeout)))
        self.normalization_enabled = os.getenv("NORMALIZATION_ENABLED", "true").lower() == "true"
        self.otx_api_key = os.getenv("OTX_API_KEY", self.otx_api_key)
        self.vt_api_key = os.getenv("VT_API_KEY", self.vt_api_key)
        self.shodan_api_key = os.getenv("SHODAN_API_KEY", self.shodan_api_key)
        
        # Validate configuration
        self._validate_config()
    
    def _setup_redis_url(self):
        """Configure Redis URL with proper authentication"""
        # If redis_url is already set, validate it
        if self.redis_url:
            try:
                parsed = urlparse(self.redis_url)
                if parsed.password:
                    self.redis_password = parsed.password
                return
            except Exception as e:
                logger.warning(f"Failed to parse existing Redis URL: {e}")
                # Fall through to construct new URL
        
        # Get Redis password from environment if not set
        if self.redis_password is None:
            self.redis_password = os.getenv('REDIS_PASSWORD', '')
        
        # Construct Redis URL
        if self.redis_password:
            self.redis_url = f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        else:
            self.redis_url = f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"
    
    def _validate_config(self):
        """Validate configuration values"""
        if not self.elasticsearch_hosts:
            raise ValueError("At least one Elasticsearch host must be configured")
        
        if self.concurrent_requests <= 0:
            raise ValueError("Concurrent requests must be greater than 0")
        
        if self.request_timeout <= 0:
            raise ValueError("Request timeout must be greater than 0")
        
        if not self.redis_url:
            raise ValueError("Redis URL must be configured")
        
        # Validate Redis URL format
        try:
            parsed = urlparse(self.redis_url)
            if parsed.scheme != 'redis':
                raise ValueError("Redis URL must use 'redis://' scheme")
        except Exception as e:
            raise ValueError(f"Invalid Redis URL format: {e}")

# Add logging for the config module
import logging
logger = logging.getLogger(__name__)
