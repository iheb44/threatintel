# crawler/crawler.py
"""
Enhanced crawler with PostgreSQL support - COMBINED VERSION
Handles both HTML crawling (legacy) and threat intelligence feed processing
"""

import os
import yaml
import time
import requests
import json
import hashlib
import re
import csv
from datetime import datetime
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CFG_PATH = "config/config.yaml"
STATE_PATH = "state/crawler_state.json"

# ============================================
# Configuration
# ============================================

@dataclass
class CrawlerConfig:
    """Crawler configuration"""
    elasticsearch_hosts: List[str] = field(default_factory=lambda: ["elasticsearch:9200"])
    postgres_dsn: Optional[str] = None
    redis_url: Optional[str] = None
    elastic_host: str = "elasticsearch"
    elastic_port: str = "9200"
    use_tor: bool = False
    max_pages_per_seed: int = 20
    crawler_type: str = "feed"  # "feed" or "html"
    
    def __post_init__(self):
        """Initialize from environment variables"""
        self.elastic_host = os.getenv("ELASTIC_HOST", self.elastic_host)
        self.elastic_port = os.getenv("ELASTIC_PORT", self.elastic_port)
        self.postgres_dsn = os.getenv("POSTGRES_DSN", self.postgres_dsn)
        self.redis_url = os.getenv("REDIS_URL", self.redis_url)
        self.use_tor = os.getenv("USE_TOR", "false").lower() == "true"
        self.max_pages_per_seed = int(os.getenv("MAX_PAGES_PER_SEED", str(self.max_pages_per_seed)))
        self.crawler_type = os.getenv("CRAWLER_TYPE", "feed")

# ============================================
# Database Managers (UNCHANGED)
# ============================================

class DatabaseManager:
    """Abstract database manager"""
    def check_duplicate(self, content_hash: str) -> bool:
        raise NotImplementedError
    
    def add_content_hash(self, content_hash: str, url: str, title: str, source: str):
        raise NotImplementedError

class PostgreSQLManager(DatabaseManager):
    """PostgreSQL manager for centralized deduplication"""
    def __init__(self, dsn: str):
        self.dsn = dsn
        try:
            import psycopg2
            self.psycopg2 = psycopg2
            self.init_db()
        except ImportError:
            logger.warning("psycopg2 not installed, PostgreSQL features disabled")
            self.psycopg2 = None
    
    def init_db(self):
        """Initialize database schema"""
        if not self.psycopg2:
            return
            
        try:
            with self.psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS content_hashes (
                            hash VARCHAR(64) PRIMARY KEY,
                            url TEXT,
                            title TEXT,
                            source_site VARCHAR(100),
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL: {e}")
    
    def check_duplicate(self, content_hash: str) -> bool:
        """Check if content already exists"""
        if not self.psycopg2:
            return False
            
        try:
            with self.psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM content_hashes WHERE hash = %s", (content_hash,))
                    return cur.fetchone() is not None
        except Exception as e:
            logger.error(f"PostgreSQL check failed: {e}")
            return False
    
    def add_content_hash(self, content_hash: str, url: str, title: str, source: str):
        """Add new content hash"""
        if not self.psycopg2:
            return
            
        try:
            with self.psycopg2.connect(self.dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO content_hashes (hash, url, title, source_site)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (hash) DO NOTHING
                    """, (content_hash, url, title[:500], source))
                    conn.commit()
        except Exception as e:
            logger.error(f"PostgreSQL insert failed: {e}")

class FileBasedManager(DatabaseManager):
    """File-based manager for backward compatibility"""
    def __init__(self, state_path: str = STATE_PATH):
        self.state_path = state_path
        self.state = self.load_state()
    
    def load_state(self) -> Dict:
        """Load state from file"""
        try:
            with open(self.state_path, 'r') as f:
                state = json.load(f)
                if 'content_hashes' in state and isinstance(state['content_hashes'], list):
                    state['content_hashes'] = set(state['content_hashes'])
                return state
        except:
            return {"last_crawl": {}, "visited_urls": set(), "content_hashes": set()}
    
    def save_state(self):
        """Save state to file"""
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            state_copy = self.state.copy()
            if 'content_hashes' in state_copy and isinstance(state_copy['content_hashes'], set):
                state_copy['content_hashes'] = list(state_copy['content_hashes'])
            if 'visited_urls' in state_copy and isinstance(state_copy['visited_urls'], set):
                state_copy['visited_urls'] = list(state_copy['visited_urls'])
            
            with open(self.state_path, 'w') as f:
                json.dump(state_copy, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def check_duplicate(self, content_hash: str) -> bool:
        """Check if content already exists"""
        return content_hash in self.state.get('content_hashes', set())
    
    def add_content_hash(self, content_hash: str, url: str, title: str, source: str):
        """Add new content hash"""
        if 'content_hashes' not in self.state:
            self.state['content_hashes'] = set()
        self.state['content_hashes'].add(content_hash)
        self.save_state()

# ============================================
# FEED PROCESSING FUNCTIONS (NEW)
# ============================================

def process_feed_content(content: str, feed_config: Dict, url: str) -> List[Dict]:
    """Process content from a threat intelligence feed"""
    feed_format = feed_config.get('format', 'text')
    iocs = []
    
    try:
        if feed_format == 'text':
            iocs = parse_text_feed(content, feed_config, url)
        elif feed_format == 'csv':
            iocs = parse_csv_feed(content, feed_config, url)
        elif feed_format == 'json':
            iocs = parse_json_feed(content, feed_config, url)
        else:
            logger.warning(f"Unknown feed format: {feed_format}")
            
    except Exception as e:
        logger.error(f"Failed to parse {feed_format} feed: {e}")
        
    return iocs

def parse_text_feed(content: str, feed_config: Dict, url: str) -> List[Dict]:
    """Parse text-based feeds (one IOC per line)"""
    iocs = []
    feed_name = feed_config['name']
    
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        # Handle URLhaus hostfile format: "127.0.0.1 domain.com"
        if feed_name == 'urlhaus_domain_feed' and '\t' in line:
            parts = line.split('\t')
            if len(parts) >= 2:
                ioc_value = parts[1].strip()  # Take the domain part only
            else:
                ioc_value = line
        else:
            ioc_value = line
            
        ioc_type = determine_ioc_type(ioc_value, feed_config)
        
        if ioc_type and ioc_type != 'unknown':
            ioc_doc = create_ioc_document(ioc_value, ioc_type, feed_name, url)
            iocs.append(ioc_doc)
            
    return iocs

def parse_csv_feed(content: str, feed_config: Dict, url: str) -> List[Dict]:
    """Parse CSV-based feeds"""
    iocs = []
    feed_name = feed_config['name']
    
    try:
        reader = csv.DictReader(content.splitlines())
        for row in reader:
            ioc_candidates = []
            
            for field in ['url', 'domain', 'hostname', 'ip', 'sha256', 'md5', 'cve']:
                if field in row and row[field]:
                    ioc_value = row[field].strip()
                    ioc_type = determine_ioc_type(ioc_value, feed_config)
                    if ioc_type and ioc_type != 'unknown':
                        ioc_candidates.append((ioc_value, ioc_type))
            
            for ioc_value, ioc_type in ioc_candidates:
                ioc_doc = create_ioc_document(ioc_value, ioc_type, feed_name, url)
                iocs.append(ioc_doc)
                
    except Exception as e:
        logger.error(f"CSV parsing error for {feed_name}: {e}")
        
    return iocs

def parse_json_feed(content: str, feed_config: Dict, url: str) -> List[Dict]:
    """Parse JSON-based feeds"""
    iocs = []
    feed_name = feed_config['name']
    
    try:
        data = json.loads(content)
        
        if feed_name == 'cisa_known_exploited_vulns':
            for vuln in data.get('vulnerabilities', []):
                if 'cveID' in vuln:
                    ioc_doc = create_ioc_document(vuln['cveID'], 'cve', feed_name, url)
                    iocs.append(ioc_doc)
                    
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error for {feed_name}: {e}")
        
    return iocs

def determine_ioc_type(value: str, feed_config: Dict) -> str:
    """Determine the type of IOC based on its value"""
    value = value.strip()
    
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return 'ip'
        
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
        return 'domain'
        
    if value.startswith(('http://', 'https://')):
        return 'url'
        
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'sha256'
        
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'md5'
        
    if re.match(r'^CVE-\d{4}-\d+$', value, re.IGNORECASE):
        return 'cve'
        
    feed_type = feed_config.get('type', '')
    if 'hash' in feed_type:
        return 'hash'
    if 'domain' in feed_type or 'url' in feed_type:
        return 'domain'
    if 'ip' in feed_type:
        return 'ip'
        
    return 'unknown'

def create_ioc_document(value: str, ioc_type: str, source: str, feed_url: str) -> Dict:
    """Create an IOC document for Elasticsearch"""
    content_hash = hashlib.sha256(f"{value}:{ioc_type}:{source}".encode()).hexdigest()
    
    return {
        "ioc_value": value,
        "ioc_type": ioc_type,
        "source_feed": source,
        "feed_url": feed_url,
        "timestamp": datetime.utcnow().isoformat(),
        "content_hash": content_hash,
        "threat_types": ["ioc"],
        "entities": extract_entities_from_ioc(value, ioc_type)
    }

def extract_entities_from_ioc(value: str, ioc_type: str) -> Dict:
    """Extract entities from IOC value"""
    entities = {}
    
    if ioc_type == 'ip':
        entities['ips'] = [value]
    elif ioc_type == 'domain':
        entities['domains'] = [value]
    elif ioc_type == 'cve':
        entities['cves'] = [value.upper()]
        
    return entities

# ============================================
# Main Crawler Class (UPDATED)
# ============================================

class EnhancedCrawler:
    """Enhanced crawler that handles both HTML and feed processing"""
    
    def __init__(self, config: CrawlerConfig):
        self.config = config
        
        if config.postgres_dsn:
            logger.info("Using PostgreSQL for deduplication")
            self.db_manager = PostgreSQLManager(config.postgres_dsn)
        else:
            logger.info("Using file-based deduplication")
            self.db_manager = FileBasedManager()
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ThreatIntelCrawler/1.0'
        })
        
        if config.use_tor:
            tor_proxy = os.getenv("TOR_SOCKS", "tor:9050")
            self.session.proxies = {
                'http': f'socks5h://{tor_proxy}',
                'https': f'socks5h://{tor_proxy}'
            }
            logger.info(f"Using Tor proxy: {tor_proxy}")
    
    def crawl_url(self, url: str, site_name: str = "unknown") -> bool:
        """Crawl a single URL - handles both HTML and feeds"""
        try:
            logger.info(f"Processing: {url}")
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            if self.config.crawler_type == "feed":
                return self._process_feed(response.text, url, site_name)
            else:
                return self._process_html(response.text, url, site_name)
                
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")
            return False
    
    def _process_feed(self, content: str, url: str, feed_name: str) -> bool:
        """Process threat intelligence feed"""
        feed_config = self._get_feed_config(feed_name)
        if not feed_config:
            logger.warning(f"No configuration found for feed: {feed_name}")
            return False
        
        ioc_documents = process_feed_content(content, feed_config, url)
        
        successful_indexes = 0
        for doc in ioc_documents:
            if self._index_ioc_document(doc, feed_name):
                successful_indexes += 1
        
        logger.info(f"Processed {successful_indexes}/{len(ioc_documents)} IOCs from {feed_name}")
        return successful_indexes > 0
    
    def _process_html(self, html: str, url: str, site_name: str) -> bool:
        """Process HTML content (legacy mode)"""
        # This is your original HTML processing code
        # Keeping it for backward compatibility
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            
            # Remove unwanted elements
            for element in soup(["script", "style", "nav", "footer", "aside", "header"]):
                element.decompose()
            
            title = ""
            if soup.title:
                title = soup.title.string.strip() if soup.title.string else "Untitled"
            elif soup.find("h1"):
                title = soup.find("h1").get_text(strip=True)
            else:
                title = "Untitled"
            
            # ... rest of your HTML processing logic ...
            
            logger.warning("HTML processing is deprecated. Use feed mode for threat intelligence.")
            return False
            
        except Exception as e:
            logger.error(f"HTML processing failed: {e}")
            return False
    
    def _get_feed_config(self, feed_name: str) -> Dict:
        """Get configuration for a specific feed"""
        site_config = load_config()
        for feed in site_config.get('targets', []):
            if feed.get('name') == feed_name:
                return feed
        return {}
    
    def _index_ioc_document(self, doc: Dict, source: str) -> bool:
        """Index an IOC document to Elasticsearch"""
        try:
            content_hash = doc['content_hash']
            if self.db_manager.check_duplicate(content_hash):
                return False
            
            es_url = f"http://{self.config.elastic_host}:{self.config.elastic_port}/iocs/_doc"
            response = requests.post(es_url, json=doc, timeout=10)
            response.raise_for_status()
            
            self.db_manager.add_content_hash(
                content_hash, 
                doc.get('feed_url', ''), 
                f"{doc['ioc_type']}:{doc['ioc_value']}", 
                source
            )
            
            logger.info(f"Indexed IOC: {doc['ioc_type']}:{doc['ioc_value'][:50]}...")
            return True
            
        except Exception as e:
            logger.error(f"Failed to index IOC document: {e}")
            return False

    def crawl_feed(self, feed_config: Dict) -> int:
        """Crawl a feed based on configuration"""
        feed_name = feed_config.get('name', 'unknown')
        feed_url = feed_config.get('url', '')
        
        logger.info(f"Starting crawl of {feed_name}")
        
        if self.crawl_url(feed_url, feed_name):
            return 1
        
        time.sleep(2)
        return 0

# ============================================
# Main Execution (UPDATED)
# ============================================

def load_config():
    """Load configuration from file"""
    try:
        with open(CFG_PATH, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return {
            'targets': [],
            'crawl_interval': 1800,
            'max_pages_per_seed': 5
        }

def main():
    """Main crawler entry point"""
    logger.info("Starting Threat Intelligence Feed Crawler")
    
    config = CrawlerConfig()
    feed_config = load_config()
    
    crawler = EnhancedCrawler(config)
    
    crawl_count = 0
    while True:
        try:
            crawl_count += 1
            logger.info(f"Starting feed crawl cycle #{crawl_count}")
            
            for feed in feed_config.get('targets', []):
                if feed.get('enabled', True):
                    crawler.crawl_feed(feed)
                    time.sleep(3)
            
            crawl_interval = feed_config.get('crawl_interval', 1800)
            logger.info(f"Feed crawl cycle complete. Sleeping for {crawl_interval} seconds")
            time.sleep(crawl_interval)
            
        except KeyboardInterrupt:
            logger.info("Crawler stopped by user")
            break
        except Exception as e:
            logger.error(f"Crawler error: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
