"""
Enhanced Celery tasks for distributed threat intelligence feed processing
With reliability features, Tor support, and expanded feed sources
"""

import os
import time
import requests
import hashlib
import json
import csv
import re
from datetime import datetime, timedelta
from celery import Celery
import logging
from typing import Dict, List, Optional, Any
import backoff
from urllib.parse import urlparse
import redis

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/celery_tasks.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Celery with Docker defaults
app = Celery('crawler_tasks')

# Configuration from environment variables
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = os.getenv('REDIS_PORT', '6379')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', '')
REDIS_DB = os.getenv('REDIS_DB', '0')

# Construct Redis URL with password
if REDIS_PASSWORD:
    REDIS_URL = f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
else:
    REDIS_URL = f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"

app.conf.update(
    broker_url=os.getenv('CELERY_BROKER_URL', REDIS_URL),
    result_backend=os.getenv('CELERY_BACKEND', REDIS_URL),
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_queues={
        'critical_feeds': {
            'exchange': 'feeds',
            'routing_key': 'feed.critical'
        },
        'high_feeds': {
            'exchange': 'feeds',
            'routing_key': 'feed.high'
        },
        'medium_feeds': {
            'exchange': 'feeds',
            'routing_key': 'feed.medium'
        },
        'monitoring': {
            'exchange': 'monitoring',
            'routing_key': 'monitoring'
        }
    }
)

# Elasticsearch configuration
ES_HOST = os.getenv('ELASTIC_HOST', 'elasticsearch')
ES_PORT = os.getenv('ELASTIC_PORT', '9200')
ES_URL = f"http://{ES_HOST}:{ES_PORT}"
USE_TOR = os.getenv('USE_TOR', 'false').lower() == 'true'
TOR_PROXY = os.getenv('TOR_PROXY', 'socks5h://tor:9050')
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))
MAX_RETRIES = int(os.getenv('MAX_RETRIES', '5'))
BASE_DELAY = float(os.getenv('BASE_REQUEST_DELAY', '2.0'))

# Redis for failure tracking
try:
    if REDIS_PASSWORD:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            db=REDIS_DB,
            decode_responses=True
        )
    else:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True
        )
    # Test connection
    redis_client.ping()
    logger.info("Redis connection established successfully")
except redis.ConnectionError as e:
    logger.error(f"Failed to connect to Redis: {e}")
    redis_client = None
except Exception as e:
    logger.error(f"Redis initialization error: {e}")
    redis_client = None

# API Keys
API_KEYS = {
    'alienvault_otx': os.getenv('OTX_API_KEY'),
    'virustotal': os.getenv('VT_API_KEY'),
    'shodan': os.getenv('SHODAN_API_KEY')
}

class FeedFailureTracker:
    """Track feed failures using Redis"""
    
    @staticmethod
    def record_failure(feed_name: str):
        """Record a failure for a feed"""
        if not redis_client:
            return
            
        try:
            key = f"feed_failure:{feed_name}"
            # Increment failure count
            failure_count = redis_client.incr(key)
            # Set expiration if this is the first failure
            if failure_count == 1:
                redis_client.expire(key, 86400)  # 24 hours
            
            # Set cooldown if too many failures
            if failure_count >= 3:
                cooldown_key = f"feed_cooldown:{feed_name}"
                redis_client.setex(cooldown_key, 3600, 'true')  # 1 hour cooldown
                logger.warning(f"Feed {feed_name} entered cooldown due to {failure_count} failures")
                
        except Exception as e:
            logger.error(f"Failed to record failure for {feed_name}: {e}")
    
    @staticmethod
    def record_success(feed_name: str):
        """Record success and reset failure count"""
        if not redis_client:
            return
            
        try:
            redis_client.delete(f"feed_failure:{feed_name}")
            redis_client.delete(f"feed_cooldown:{feed_name}")
        except Exception as e:
            logger.error(f"Failed to record success for {feed_name}: {e}")
    
    @staticmethod
    def should_skip_feed(feed_name: str) -> bool:
        """Check if feed should be skipped due to failures"""
        if not redis_client:
            return False
            
        try:
            # Check cooldown
            if redis_client.exists(f"feed_cooldown:{feed_name}"):
                return True
            
            # Check if too many failures recently
            failure_count = redis_client.get(f"feed_failure:{feed_name}")
            if failure_count and int(failure_count) >= 3:
                return True
                
            return False
        except Exception as e:
            logger.error(f"Failed to check feed status for {feed_name}: {e}")
            return False

class EnhancedRequestSession:
    """Enhanced session with Tor support and retry logic"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) ThreatIntelCrawler/2.0',
            'Accept': 'text/plain,text/csv,application/json',
            'Accept-Encoding': 'gzip, deflate',
        })
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BASE_DELAY,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            respect_retry_after_header=True
        )
        
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Configure Tor if enabled
        if USE_TOR:
            self.session.proxies = {
                'http': TOR_PROXY,
                'https': TOR_PROXY
            }
            logger.info(f"Tor proxy configured: {TOR_PROXY}")
    
    @backoff.on_exception(backoff.expo, 
                         requests.RequestException, 
                         max_tries=3,
                         max_time=30)
    def get_with_backoff(self, url: str, headers: Optional[Dict] = None) -> Optional[requests.Response]:
        """Get request with exponential backoff"""
        try:
            response = self.session.get(
                url, 
                timeout=REQUEST_TIMEOUT,
                headers=headers or {}
            )
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logger.warning(f"Request failed for {url}: {e}")
            raise

def determine_ioc_type(value: str, feed_config: Dict) -> str:
    """Determine IOC type with enhanced detection"""
    value = value.strip()
    
    # IP detection with CIDR support
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', value):
        return 'ip'
        
    # Domain detection
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
        return 'domain'
        
    # URL detection
    if value.startswith(('http://', 'https://')):
        return 'url'
        
    # Hash detection
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'sha256'
    if re.match(r'^[a-fA-F0-9]{40}$', value):
        return 'sha1'
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'md5'
        
    # CVE detection
    if re.match(r'^CVE-\d{4}-\d+$', value, re.IGNORECASE):
        return 'cve'
        
    # Feed-specific type hints
    feed_type = feed_config.get('type', '')
    if any(t in feed_type for t in ['hash', 'malware']):
        return 'hash'
    if any(t in feed_type for t in ['domain', 'url', 'phishing']):
        return 'domain'
    if 'ip' in feed_type:
        return 'ip'
    if any(t in feed_type for t in ['vulnerability', 'cve']):
        return 'cve'
        
    return 'unknown'

def create_ioc_document(value: str, ioc_type: str, source: str, feed_url: str) -> Dict:
    """Create IOC document for Elasticsearch"""
    content_hash = hashlib.sha256(f"{value}:{ioc_type}:{source}".encode()).hexdigest()
    
    return {
        "ioc_value": value,
        "ioc_type": ioc_type,
        "source_feed": source,
        "feed_url": feed_url,
        "timestamp": datetime.utcnow().isoformat(),
        "content_hash": content_hash,
        "threat_types": ["ioc"],
        "entities": extract_entities_from_ioc(value, ioc_type),
        "metadata": {
            "processed_at": datetime.utcnow().isoformat(),
            "crawler_version": "2.0",
            "priority": "critical" if source in ['urlhaus_domain_feed', 'cisa_known_exploited_vulns'] else "high"
        }
    }

def extract_entities_from_ioc(value: str, ioc_type: str) -> Dict:
    """Extract entities from IOC value"""
    entities = {}
    
    if ioc_type == 'ip':
        entities['ips'] = [value]
    elif ioc_type == 'domain':
        entities['domains'] = [value]
    elif ioc_type == 'url':
        entities['urls'] = [value]
    elif ioc_type == 'cve':
        entities['cves'] = [value.upper()]
    elif ioc_type in ['sha256', 'sha1', 'md5']:
        entities['hashes'] = [value.lower()]
        
    return entities

def get_api_key_for_feed(feed_name: str) -> Optional[str]:
    """Get API key for a specific feed"""
    key_mapping = {
        'alienvault_otx_pulse': 'alienvault_otx',
        'virustotal_ip_reputation': 'virustotal',
        'virustotal_domain_reputation': 'virustotal'
    }
    return API_KEYS.get(key_mapping.get(feed_name, ''))

def parse_text_feed(content: str, feed_config: Dict, url: str) -> List[Dict]:
    """Parse text-based threat feeds with enhanced logic"""
    iocs = []
    feed_name = feed_config['name']
    skip_patterns = feed_config.get('parsing', {}).get('text', {}).get('skip_patterns', ["^#", "^//", "^;", "^$"])
    
    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
            
        # Skip comments and empty lines
        if any(re.match(pattern, line) for pattern in skip_patterns):
            continue
            
        # Extract IOC based on feed type
        ioc_value = extract_ioc_from_text(line, feed_config)
        if not ioc_value:
            continue
            
        ioc_type = determine_ioc_type(ioc_value, feed_config)
        
        if ioc_type != 'unknown':
            ioc_doc = create_ioc_document(ioc_value, ioc_type, feed_name, url)
            iocs.append(ioc_doc)
            
    return iocs

def extract_ioc_from_text(line: str, feed_config: Dict) -> Optional[str]:
    """Extract IOC value from text line"""
    feed_name = feed_config.get('name', '')
    
    # URLhaus specific format
    if feed_name == 'urlhaus_domain_feed' and '\t' in line:
        parts = line.split('\t')
        return parts[1].strip() if len(parts) >= 2 else line.strip()
    
    # Spamhaus DROP/EDROP format
    if feed_name in ['spamhaus_drop_list', 'spamhaus_edrop_list']:
        if ';' in line:  # Skip comment lines
            return None
        return line.strip()
    
    # Default: use the whole line
    return line.strip()

def parse_csv_feed(content: str, feed_config: Dict, url: str) -> List[Dict]:
    """Parse CSV-based threat feeds with field mapping"""
    iocs = []
    feed_name = feed_config['name']
    
    try:
        reader = csv.DictReader(content.splitlines())
        field_mappings = feed_config.get('parsing', {}).get('csv', {}).get('field_mappings', {})
        
        for row_num, row in enumerate(reader, 1):
            ioc_candidates = []
            
            # Use feed-specific field mapping
            if feed_name in field_mappings:
                for ioc_type, field_names in field_mappings[feed_name].items():
                    for field_name in field_names:
                        if field_name in row and row[field_name]:
                            value = row[field_name].strip()
                            if value:
                                ioc_candidates.append((value, ioc_type))
                                break
            
            # Fallback to automatic detection
            if not ioc_candidates:
                for key, value in row.items():
                    if value and isinstance(value, str) and value.strip():
                        candidate = value.strip()
                        detected_type = determine_ioc_type(candidate, feed_config)
                        if detected_type != 'unknown':
                            ioc_candidates.append((candidate, detected_type))
            
            # Create documents
            for ioc_value, ioc_type in ioc_candidates:
                ioc_doc = create_ioc_document(ioc_value, ioc_type, feed_name, url)
                iocs.append(ioc_doc)
                
    except Exception as e:
        logger.error(f"CSV parsing error for {feed_name}: {e}")
        
    return iocs

def parse_json_feed(content: str, feed_config: Dict, url: str) -> List[Dict]:
    """Parse JSON-based threat feeds"""
    iocs = []
    feed_name = feed_config['name']
    
    try:
        data = json.loads(content)
        
        # CISA Known Exploited Vulnerabilities
        if feed_name == 'cisa_known_exploited_vulns':
            for vuln in data.get('vulnerabilities', []):
                if 'cveID' in vuln:
                    ioc_doc = create_ioc_document(vuln['cveID'], 'cve', feed_name, url)
                    iocs.append(ioc_doc)
        
        # AlienVault OTX Pulse
        elif feed_name == 'alienvault_otx_pulse':
            for pulse in data.get('results', []):
                for indicator in pulse.get('indicators', []):
                    if 'indicator' in indicator:
                        ioc_value = indicator['indicator']
                        ioc_type = determine_ioc_type(ioc_value, feed_config)
                        if ioc_type != 'unknown':
                            ioc_doc = create_ioc_document(ioc_value, ioc_type, feed_name, url)
                            iocs.append(ioc_doc)
        
        # Generic JSON with IOCs array
        elif 'iocs' in data:
            for ioc in data['iocs']:
                if 'value' in ioc and 'type' in ioc:
                    ioc_doc = create_ioc_document(ioc['value'], ioc['type'], feed_name, url)
                    iocs.append(ioc_doc)
                    
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error for {feed_name}: {e}")
        
    return iocs

def index_ioc_to_es(doc: Dict) -> bool:
    """Index IOC document to Elasticsearch with retry logic"""
    try:
        es_url = f"{ES_URL}/iocs/_doc"
        
        @backoff.on_exception(backoff.expo, 
                             requests.RequestException, 
                             max_tries=3,
                             max_time=30)
        def _index_with_retry():
            response = requests.post(es_url, json=doc, timeout=10)
            response.raise_for_status()
            return True
        
        return _index_with_retry()
        
    except Exception as e:
        logger.error(f"Failed to index IOC {doc.get('ioc_value', 'unknown')}: {e}")
        return False

def calculate_retry_delay(retry_count: int) -> int:
    """Calculate exponential backoff delay for task retries"""
    return min(60 * (2 ** retry_count), 3600)  # Max 1 hour

@app.task(bind=True, max_retries=5)
def process_feed_task(self, feed_config: Dict):
    """
    Enhanced Celery task to process a single threat intelligence feed
    with reliability features and Tor support
    """
    feed_name = feed_config.get('name', 'unknown')
    feed_url = feed_config.get('url', '')
    
    logger.info(f"Starting processing for feed: {feed_name}")
    
    # Check if feed should be skipped due to failures
    if FeedFailureTracker.should_skip_feed(feed_name):
        logger.warning(f"Skipping feed {feed_name} due to previous failures")
        return {
            'success': False, 
            'skipped': True, 
            'feed': feed_name,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    # Check Tor requirements
    requires_tor = feed_config.get('requires_tor', False)
    if requires_tor and not USE_TOR:
        logger.warning(f"Skipping Tor-required feed {feed_name} (Tor not enabled)")
        return {
            'success': False, 
            'skipped': True, 
            'feed': feed_name,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    try:
        # Create enhanced session
        session = EnhancedRequestSession()
        
        # Add API key if required
        headers = {}
        if feed_config.get('requires_api_key', False):
            api_key = get_api_key_for_feed(feed_name)
            if api_key:
                auth_header = feed_config.get('auth_header', 'X-API-Key')
                headers[auth_header] = api_key
            else:
                logger.warning(f"No API key available for {feed_name}")
                FeedFailureTracker.record_failure(feed_name)
                return {
                    'success': False, 
                    'feed': feed_name, 
                    'error': 'Missing API key',
                    'timestamp': datetime.utcnow().isoformat()
                }
        
        # Fetch feed content with retry logic
        logger.debug(f"Fetching feed: {feed_url}")
        response = session.get_with_backoff(feed_url, headers=headers)
        
        if not response:
            FeedFailureTracker.record_failure(feed_name)
            raise Exception("Failed to fetch feed content")
        
        # Process content based on format
        content = response.text
        feed_format = feed_config.get('format', 'text').lower()
        
        logger.debug(f"Processing {feed_format} feed: {feed_name}")
        
        if feed_format == 'text':
            ioc_documents = parse_text_feed(content, feed_config, feed_url)
        elif feed_format == 'csv':
            ioc_documents = parse_csv_feed(content, feed_config, feed_url)
        elif feed_format == 'json':
            ioc_documents = parse_json_feed(content, feed_config, feed_url)
        else:
            logger.warning(f"Unknown feed format: {feed_format} for {feed_name}")
            ioc_documents = []
        
        # Index IOCs to Elasticsearch
        successful_indexes = 0
        for doc in ioc_documents:
            if index_ioc_to_es(doc):
                successful_indexes += 1
        
        # Record success and reset failure count
        FeedFailureTracker.record_success(feed_name)
        
        logger.info(f"Successfully processed {successful_indexes}/{len(ioc_documents)} IOCs from {feed_name}")
        
        return {
            'feed': feed_name,
            'iocs_processed': successful_indexes,
            'total_iocs': len(ioc_documents),
            'timestamp': datetime.utcnow().isoformat(),
            'success': True
        }
        
    except requests.HTTPError as e:
        if e.response.status_code == 429:  # Rate limited
            logger.warning(f"Rate limited for {feed_name}, will retry")
            FeedFailureTracker.record_failure(feed_name)
            # Use exponential backoff for rate limits
            raise self.retry(exc=e, countdown=calculate_retry_delay(self.request.retries))
        else:
            logger.error(f"HTTP error for {feed_name}: {e}")
            FeedFailureTracker.record_failure(feed_name)
            raise self.retry(exc=e, countdown=calculate_retry_delay(self.request.retries))
            
    except requests.RequestException as e:
        logger.error(f"Network error for {feed_name}: {e}")
        FeedFailureTracker.record_failure(feed_name)
        raise self.retry(exc=e, countdown=calculate_retry_delay(self.request.retries))
        
    except Exception as e:
        logger.error(f"Error processing feed {feed_name}: {e}")
        FeedFailureTracker.record_failure(feed_name)
        raise self.retry(exc=e, countdown=calculate_retry_delay(self.request.retries))
    
    finally:
        # Respect rate limiting between feeds
        time.sleep(BASE_DELAY)

@app.task
def process_feeds_batch(feeds_config: Dict):
    """
    Process a batch of feeds with priority-based routing
    """
    results = []
    
    for feed in feeds_config.get('targets', []):
        if not feed.get('enabled', True):
            continue
            
        feed_name = feed.get('name', 'unknown')
        feed_priority = feed.get('priority', 'medium').lower()
        
        # Route to appropriate queue based on priority
        queue_name = f"{feed_priority}_feeds"
        routing_key = f"feed.{feed_priority}"
        
        result = process_feed_task.apply_async(
            args=[feed],
            queue=queue_name,
            routing_key=routing_key
        )
        
        results.append({
            'feed': feed_name,
            'task_id': result.id,
            'priority': feed_priority,
            'queue': queue_name
        })
    
    return results

@app.task
def health_check():
    """
    Health check task with comprehensive monitoring
    """
    try:
        # Check Elasticsearch
        try:
            es_health = requests.get(f"{ES_URL}/_cluster/health", timeout=5)
            es_status = es_health.json().get('status', 'unknown')
        except Exception as e:
            es_status = 'unreachable'
            logger.error(f"Elasticsearch health check failed: {e}")
        
        # Check Redis
        redis_status = 'healthy'
        if redis_client:
            try:
                redis_client.ping()
            except Exception as e:
                redis_status = 'unhealthy'
                logger.error(f"Redis health check failed: {e}")
        else:
            redis_status = 'not_configured'
        
        # Check feed failure counts
        feed_stats = {}
        if redis_client:
            try:
                # Get all feed failure keys
                failure_keys = redis_client.keys('feed_failure:*')
                for key in failure_keys:
                    feed_name = key.split(':')[1]
                    failure_count = redis_client.get(key)
                    feed_stats[feed_name] = int(failure_count) if failure_count else 0
            except Exception as e:
                logger.error(f"Failed to get feed stats: {e}")
        
        status = 'healthy'
        if es_status not in ['green', 'yellow'] or redis_status != 'healthy':
            status = 'degraded'
        if es_status == 'unreachable' or redis_status == 'unhealthy':
            status = 'unhealthy'
        
        return {
            'status': status,
            'elasticsearch': es_status,
            'redis': redis_status,
            'feed_failures': feed_stats,
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'threat_intel_processor'
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

@app.task
def cleanup_old_failures():
    """
    Clean up old failure records periodically
    """
    try:
        if not redis_client:
            return {'cleaned': False, 'error': 'Redis not available'}
        
        # Cleanup keys older than 7 days
        old_keys = []
        try:
            # This is a simplified approach - in production use SCAN
            for key in redis_client.keys('feed_failure:*'):
                ttl = redis_client.ttl(key)
                if ttl == -1:  # No expiration set
                    redis_client.delete(key)
                    old_keys.append(key)
                elif ttl > 604800:  # More than 7 days old
                    redis_client.delete(key)
                    old_keys.append(key)
        except Exception as e:
            logger.error(f"Failed to cleanup old keys: {e}")
        
        logger.info(f"Cleaned up {len(old_keys)} old failure records")
        return {'cleaned': True, 'count': len(old_keys), 'timestamp': datetime.utcnow().isoformat()}
        
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        return {'cleaned': False, 'error': str(e)}

# Celery beat schedule
app.conf.beat_schedule = {
    'process-critical-feeds': {
        'task': 'crawler_tasks.process_feeds_batch',
        'schedule': 900.0,  # Every 15 minutes
        'args': ({'targets': []},),
    },
    'process-high-feeds': {
        'task': 'crawler_tasks.process_feeds_batch',
        'schedule': 1800.0,  # Every 30 minutes
        'args': ({'targets': []},),
    },
    'process-medium-feeds': {
        'task': 'crawler_tasks.process_feeds_batch',
        'schedule': 3600.0,  # Every hour
        'args': ({'targets': []},),
    },
    'health-check-5min': {
        'task': 'crawler_tasks.health_check',
        'schedule': 300.0,  # Every 5 minutes
    },
    'cleanup-failures-hourly': {
        'task': 'crawler_tasks.cleanup_old_failures',
        'schedule': 3600.0,  # Every hour
    },
}

if __name__ == '__main__':
    # For testing purposes
    app.start()
