"""
Enhanced main crawler with IOC standardization and enrichment
"""
import logging
import time
import json
import csv
import os
import sys
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re

# Add the current directory to Python path to handle imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/crawler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import enhanced modules with proper error handling
try:
    # First try absolute import (when running as module)
    from crawler.ioc_processor import IOCProcessor, normalize_timestamp, should_normalize_timestamp
    from crawler.database_manager import IOCDatabaseManager
    from crawler.config import EnhancedCrawlerConfig
except ImportError:
    try:
        # Fallback to direct import (when running as script)
        from ioc_processor import IOCProcessor, normalize_timestamp, should_normalize_timestamp
        from database_manager import IOCDatabaseManager
        from config import EnhancedCrawlerConfig
    except ImportError as e:
        logger.error(f"Failed to import required modules: {e}")
        logger.error("Please ensure all required files are in the same directory:")
        logger.error(" - ioc_processor.py")
        logger.error(" - database_manager.py") 
        logger.error(" - config.py")
        import traceback
        traceback.print_exc()
        sys.exit(1)

class EnhancedThreatIntelligenceCrawler:
    """Enhanced crawler with IOC processing capabilities"""
    
    def __init__(self, config: EnhancedCrawlerConfig):
        self.config = config
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'duplicates': 0,
            'enriched': 0,
            'api_calls': 0
        }
        
        # Initialize IOC processor with config
        self.ioc_processor = IOCProcessor({
            'geoip_enabled': getattr(config, 'geoip_enabled', True),
            'asn_enabled': getattr(config, 'asn_enabled', True),
            'enrichment_timeout': getattr(config, 'enrichment_timeout', 5),
            'normalization_enabled': getattr(config, 'normalization_enabled', True)
        })
        
        # Initialize database manager
        redis_url = getattr(config, 'redis_url', 'redis://redis:6379/0')
        self.db_manager = IOCDatabaseManager(redis_url)
        self.seen_hashes: Set[str] = set()  # In-memory cache for current session
        
        # Initialize session with enhanced configuration
        self.session = self._create_enhanced_session()
        
        # API keys for premium feeds
        self.api_keys = {
            'alienvault_otx': getattr(config, 'otx_api_key', None),
            'virustotal': getattr(config, 'vt_api_key', None),
            'shodan': getattr(config, 'shodan_api_key', None)
        }
        
        logger.info("Enhanced Threat Intelligence Crawler initialized")
    
    def _create_enhanced_session(self) -> requests.Session:
        """Create enhanced HTTP session with retry logic"""
        session = requests.Session()
        
        # Configure headers
        session.headers.update({
            'User-Agent': getattr(self.config, 'user_agent', 'ThreatIntelCrawler/2.0'),
            'Accept': 'text/plain,text/csv,application/json,application/xml',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=getattr(self.config, 'max_retries', 3),
            backoff_factor=getattr(self.config, 'rate_limit_delay', 2.0),
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
            respect_retry_after_header=True
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=getattr(self.config, 'concurrent_requests', 3),
            pool_maxsize=getattr(self.config, 'concurrent_requests', 3)
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure Tor if enabled
        if getattr(self.config, 'use_tor', False):
            tor_proxy = getattr(self.config, 'tor_proxy', 'socks5h://tor:9050')
            session.proxies = {
                'http': tor_proxy,
                'https': tor_proxy
            }
            logger.info(f"Tor proxy configured: {tor_proxy}")
        
        return session
    
    def fetch_feed_content(self, feed_config: Dict) -> Optional[str]:
        """Fetch feed content with authentication if needed"""
        feed_url = feed_config.get('url')
        feed_name = feed_config.get('name', 'unknown')
        
        if not feed_url:
            logger.error(f"No URL provided for feed: {feed_name}")
            return None
        
        try:
            headers = {}
            
            # Add API key if required
            if feed_config.get('requires_api_key', False):
                api_key = self.get_api_key_for_feed(feed_name)
                if api_key:
                    auth_header = feed_config.get('auth_header', 'X-API-Key')
                    headers[auth_header] = api_key
                else:
                    logger.warning(f"No API key available for {feed_name}")
                    return None
            
            # Add custom headers from config
            custom_headers = feed_config.get('headers', {})
            headers.update(custom_headers)
            
            logger.info(f"Fetching feed: {feed_name}")
            response = self.session.get(
                feed_url,
                headers=headers,
                timeout=getattr(self.config, 'request_timeout', 30)
            )
            response.raise_for_status()
            
            self.stats['api_calls'] += 1
            return response.text
            
        except requests.RequestException as e:
            logger.error(f"Failed to fetch feed {feed_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching {feed_name}: {e}")
            return None
    
    def get_api_key_for_feed(self, feed_name: str) -> Optional[str]:
        """Get API key for a specific feed"""
        key_mapping = {
            'alienvault_otx_pulse': 'alienvault_otx',
            'virustotal_ip_reputation': 'virustotal',
            'virustotal_domain_reputation': 'virustotal'
        }
        key_name = key_mapping.get(feed_name)
        return self.api_keys.get(key_name) if key_name else None
    
    def parse_raw_content(self, content: str, feed_config: Dict, url: str) -> List[Dict]:
        """
        Parse raw feed content into individual IOCs
        """
        raw_iocs = []
        feed_format = feed_config.get('format', 'text')
        feed_name = feed_config.get('name', 'unknown')
        
        try:
            if feed_format == 'text':
                raw_iocs = self._parse_text_feed(content, feed_config, url)
            elif feed_format == 'csv':
                raw_iocs = self._parse_csv_feed(content, feed_config, url)
            elif feed_format == 'json':
                raw_iocs = self._parse_json_feed(content, feed_config, url)
            else:
                logger.warning(f"Unknown format for {feed_name}: {feed_format}")
                
        except Exception as e:
            logger.error(f"Failed to parse {feed_name} content: {e}")
            
        return raw_iocs
    
    def _parse_text_feed(self, content: str, feed_config: Dict, url: str) -> List[Dict]:
        """Parse text-based feed content"""
        raw_iocs = []
        feed_name = feed_config['name']
        skip_patterns = feed_config.get('parsing', {}).get('text', {}).get('skip_patterns', ['#', '//', ';', '%'])
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or any(line.startswith(prefix) for prefix in skip_patterns):
                continue
                
            # Feed-specific parsing logic
            if feed_name == 'urlhaus_domain_feed' and '\t' in line:
                parts = line.split('\t')
                if len(parts) >= 2:
                    raw_iocs.append({
                        'value': parts[1].strip(),
                        'type': 'domain',
                        'raw_data': {'original_line': line, 'line_number': line_num}
                    })
            elif feed_name in ['spamhaus_drop_list', 'spamhaus_edrop_list'] and ';' in line:
                # Skip comment lines in Spamhaus feeds
                continue
            else:
                raw_iocs.append({
                    'value': line,
                    'type': 'auto',  # Let IOC processor determine type
                    'raw_data': {'original_line': line, 'line_number': line_num}
                })
                
        return raw_iocs
    
    def _parse_csv_feed(self, content: str, feed_config: Dict, url: str) -> List[Dict]:
        """Parse CSV-based feed content"""
        raw_iocs = []
        feed_name = feed_config['name']
        
        try:
            reader = csv.DictReader(content.splitlines())
            field_mappings = feed_config.get('parsing', {}).get('csv', {}).get('field_mappings', {})
            
            for row_num, row in enumerate(reader, 1):
                try:
                    # Feed-specific field mapping
                    if feed_name in field_mappings:
                        for ioc_type, field_names in field_mappings[feed_name].items():
                            for field_name in field_names:
                                if field_name in row and row[field_name]:
                                    value = row[field_name].strip()
                                    if value:
                                        raw_iocs.append({
                                            'value': value,
                                            'type': ioc_type,
                                            'raw_data': {'row': row, 'row_number': row_num}
                                        })
                                        break
                    else:
                        # Generic parsing - look for common IOC fields
                        for field_name, value in row.items():
                            if value and isinstance(value, str) and value.strip():
                                raw_iocs.append({
                                    'value': value.strip(),
                                    'type': 'auto',
                                    'raw_data': {'row': row, 'row_number': row_num, 'field': field_name}
                                })
                                
                except Exception as e:
                    logger.warning(f"Error parsing row {row_num} in {feed_name}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"CSV parsing failed for {feed_name}: {e}")
        
        return raw_iocs
    
    def _parse_json_feed(self, content: str, feed_config: Dict, url: str) -> List[Dict]:
        """Parse JSON-based feed content"""
        raw_iocs = []
        feed_name = feed_config['name']
        
        try:
            data = json.loads(content)
            
            # CISA Known Exploited Vulnerabilities
            if feed_name == 'cisa_known_exploited_vulns':
                for vuln in data.get('vulnerabilities', []):
                    if 'cveID' in vuln:
                        raw_iocs.append({
                            'value': vuln['cveID'],
                            'type': 'cve',
                            'raw_data': vuln
                        })
            
            # AlienVault OTX
            elif feed_name == 'alienvault_otx_pulse':
                for pulse in data.get('results', []):
                    for indicator in pulse.get('indicators', []):
                        if 'indicator' in indicator:
                            raw_iocs.append({
                                'value': indicator['indicator'],
                                'type': 'auto',
                                'raw_data': indicator
                            })
            
            # Generic JSON parsing
            else:
                # Try to extract IOCs from common structures
                def extract_values(obj, path=""):
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            yield from extract_values(value, f"{path}.{key}" if path else key)
                    elif isinstance(obj, list):
                        for item in obj:
                            yield from extract_values(item, path)
                    elif isinstance(obj, str) and obj.strip():
                        yield (obj.strip(), path)
                
                for value, path in extract_values(data):
                    raw_iocs.append({
                        'value': value,
                        'type': 'auto',
                        'raw_data': {'json_path': path, 'value': value}
                    })
                    
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {feed_name}: {e}")
        except Exception as e:
            logger.error(f"JSON parsing failed for {feed_name}: {e}")
        
        return raw_iocs
    
    def process_feed(self, feed_config: Dict) -> List[Dict]:
        """Complete feed processing: fetch, parse, process IOCs"""
        feed_name = feed_config.get('name', 'unknown')
        
        # Fetch content
        content = self.fetch_feed_content(feed_config)
        if not content:
            return []
        
        # Parse and process IOCs
        processed_iocs = self.process_feed_content(content, feed_config, feed_config.get('url'))
        
        # Index to Elasticsearch
        if processed_iocs:
            successful_indexes = self.bulk_index_iocs(processed_iocs, feed_name)
            logger.info(f"Successfully indexed {successful_indexes} IOCs from {feed_name}")
        
        return processed_iocs
    
    def process_feed_content(self, content: str, feed_config: Dict, url: str) -> List[Dict]:
        """Process feed content with enhanced IOC handling"""
        try:
            raw_iocs = self.parse_raw_content(content, feed_config, url)
            if not raw_iocs:
                logger.warning(f"No IOCs found in {feed_config['name']}")
                return []
            
            processed_iocs = []
            bulk_hashes = []
            
            for raw_ioc in raw_iocs:
                try:
                    # Process and enrich each IOC
                    processed_ioc = self.ioc_processor.process_ioc(
                        raw_ioc['value'],
                        raw_ioc.get('type', ''),
                        feed_config['name'],
                        url,
                        raw_ioc.get('raw_data', {})
                    )
                    
                    if processed_ioc:
                        # Check for duplicates
                        if not self.db_manager.check_duplicate(processed_ioc['content_hash']):
                            processed_iocs.append(processed_ioc)
                            bulk_hashes.append((
                                processed_ioc['content_hash'],
                                processed_ioc['ioc_value'],
                                processed_ioc['ioc_type'],
                                feed_config['name']
                            ))
                            self.seen_hashes.add(processed_ioc['content_hash'])
                            self.stats['processed'] += 1
                        else:
                            self.stats['duplicates'] += 1
                            
                except Exception as e:
                    logger.error(f"Failed to process IOC {raw_ioc.get('value')}: {e}")
                    self.stats['failed'] += 1
            
            # Bulk track hashes for performance
            if bulk_hashes and hasattr(self.db_manager, 'bulk_track_hashes'):
                self.db_manager.bulk_track_hashes(bulk_hashes)
            
            # Track relationships between IOCs
            if processed_iocs and hasattr(self.ioc_processor, 'track_ioc_relationships'):
                processed_iocs = self.ioc_processor.track_ioc_relationships(processed_iocs)
                self.stats['enriched'] += len(processed_iocs)
            
            logger.info(f"Processed {len(processed_iocs)} IOCs from {feed_config['name']}")
            return processed_iocs
            
        except Exception as e:
            logger.error(f"Failed to process feed content for {feed_config['name']}: {e}")
            return []
    
    def bulk_index_iocs(self, iocs: List[Dict], source: str) -> int:
        """Bulk index IOC documents to Elasticsearch for better performance"""
        if not iocs:
            return 0
        
        successful_indexes = 0
        
        try:
            # Prepare bulk operations
            bulk_operations = []
            for doc in iocs:
                # Normalize timestamps
                doc = self._normalize_document_timestamps(doc)
                
                # Add to bulk operations
                bulk_operations.append({'index': {'_index': 'iocs', '_id': doc['content_hash']}})
                bulk_operations.append(doc)
            
            # Execute bulk operation
            es_hosts = getattr(self.config, 'elasticsearch_hosts', ['http://elasticsearch:9200'])
            for es_host in es_hosts:
                try:
                    bulk_url = f"{es_host}/_bulk"
                    response = self.session.post(
                        bulk_url,
                        data='\n'.join([json.dumps(op) for op in bulk_operations]) + '\n',
                        headers={'Content-Type': 'application/x-ndjson'},
                        timeout=30
                    )
                    response.raise_for_status()
                    
                    # Check for errors in bulk response
                    bulk_result = response.json()
                    if bulk_result.get('errors'):
                        for item in bulk_result.get('items', []):
                            if 'error' in item.get('index', {}):
                                logger.warning(f"Bulk index error: {item['index']['error']}")
                    
                    successful_indexes = len([item for item in bulk_result.get('items', []) 
                                           if item.get('index', {}).get('result') == 'created'])
                    break
                    
                except requests.RequestException as e:
                    logger.warning(f"Bulk index failed on {es_host}: {e}")
                    continue
            
            self.stats['successful'] += successful_indexes
            logger.info(f"Bulk indexed {successful_indexes}/{len(iocs)} IOCs")
            
        except Exception as e:
            logger.error(f"Bulk indexing failed: {e}")
        
        return successful_indexes
    
    def _normalize_document_timestamps(self, doc: Dict) -> Dict:
        """Normalize all timestamps in the document"""
        normalized_doc = doc.copy()
        
        # Normalize main timestamp
        if 'timestamp' in normalized_doc and should_normalize_timestamp(normalized_doc['timestamp']):
            normalized_doc['timestamp'] = normalize_timestamp(normalized_doc['timestamp'])
        
        # Normalize metadata timestamps
        if 'metadata' in normalized_doc:
            for time_field in ['processed_at', 'enriched_at', 'created_at', 'updated_at']:
                if (time_field in normalized_doc['metadata'] and 
                    should_normalize_timestamp(normalized_doc['metadata'][time_field])):
                    normalized_doc['metadata'][time_field] = normalize_timestamp(
                        normalized_doc['metadata'][time_field]
                    )
        
        return normalized_doc
    
    def index_ioc_document(self, doc: Dict, source: str) -> bool:
        """Index single enriched IOC document to Elasticsearch"""
        try:
            # Normalize timestamps
            doc = self._normalize_document_timestamps(doc)
            
            # Index to Elasticsearch
            es_hosts = getattr(self.config, 'elasticsearch_hosts', ['http://elasticsearch:9200'])
            for es_host in es_hosts:
                try:
                    es_url = f"{es_host}/iocs/_doc/{doc['content_hash']}"
                    response = self.session.put(
                        es_url, 
                        json=doc, 
                        timeout=10,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response.status_code in [200, 201]:
                        logger.debug(f"Indexed IOC: {doc['ioc_type']}:{doc['ioc_value'][:50]}...")
                        self.stats['successful'] += 1
                        return True
                    elif response.status_code == 409:  # Conflict (duplicate)
                        self.stats['duplicates'] += 1
                        return False
                        
                except requests.RequestException as e:
                    logger.warning(f"Indexing failed on {es_host}: {e}")
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to index IOC: {e}")
            self.stats['failed'] += 1
            return False
    
    def get_stats(self) -> Dict:
        """Get current crawling statistics"""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics counters"""
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'duplicates': 0,
            'enriched': 0,
            'api_calls': 0
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.session.close()
        self.seen_hashes.clear()
        logger.info("Crawler cleanup completed")

# Utility function for the main execution
def should_normalize_timestamp(timestamp: str) -> bool:
    """
    Check if timestamp needs normalization
    Basic check for ISO format with timezone
    """
    import re
    if not isinstance(timestamp, str):
        return True
        
    iso_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'
    return not bool(re.match(iso_pattern, timestamp))

# Main execution for testing
if __name__ == "__main__":
    # Basic configuration for testing
    class TestConfig:
        redis_url = "redis://redis:6379/0"
        user_agent = "TestCrawler/1.0"
        max_retries = 3
        rate_limit_delay = 2.0
        concurrent_requests = 3
        use_tor = False
        geoip_enabled = True
        asn_enabled = True
        enrichment_timeout = 5
        normalization_enabled = True
        elasticsearch_hosts = ["http://localhost:9200"]
    
    config = TestConfig()
    crawler = EnhancedThreatIntelligenceCrawler(config)
    
    # Test with a simple feed
    test_feed = {
        'name': 'test_feed',
        'url': 'https://example.com/test.txt',
        'format': 'text',
        'enabled': True
    }
    
    # Simulate some content
    test_content = """# Comment line
127.0.0.1 example.com
8.8.8.8
https://malicious.com/path
CVE-2021-44228
"""
    
    processed = crawler.process_feed_content(test_content, test_feed, test_feed['url'])
    print(f"Processed {len(processed)} IOCs")
    print(f"Stats: {crawler.get_stats()}")
    
    crawler.cleanup()
