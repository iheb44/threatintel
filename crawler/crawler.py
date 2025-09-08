# crawler/crawler.py
"""
Enhanced crawler with PostgreSQL and Celery support
Fixes the dataclass issue and maintains backward compatibility
"""

import os
import yaml
import time
import requests
import json
import hashlib
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CFG_PATH = "config/config.yaml"
STATE_PATH = "state/crawler_state.json"

# ============================================
# Configuration with fixed dataclass
# ============================================

@dataclass
class CrawlerConfig:
    """Crawler configuration with proper dataclass defaults"""
    # Use default_factory for mutable defaults (lists)
    elasticsearch_hosts: List[str] = field(default_factory=lambda: ["elasticsearch:9200"])
    
    # Immutable defaults are fine
    postgres_dsn: Optional[str] = None
    redis_url: Optional[str] = None
    elastic_host: str = "elasticsearch"
    elastic_port: str = "9200"
    use_tor: bool = False
    max_pages_per_seed: int = 20
    
    def __post_init__(self):
        """Initialize from environment variables"""
        self.elastic_host = os.getenv("ELASTIC_HOST", self.elastic_host)
        self.elastic_port = os.getenv("ELASTIC_PORT", self.elastic_port)
        self.postgres_dsn = os.getenv("POSTGRES_DSN", self.postgres_dsn)
        self.redis_url = os.getenv("REDIS_URL", self.redis_url)
        self.use_tor = os.getenv("USE_TOR", "false").lower() == "true"
        self.max_pages_per_seed = int(os.getenv("MAX_PAGES_PER_SEED", str(self.max_pages_per_seed)))

# ============================================
# Database Managers
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
                # Convert lists to sets for efficiency
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
            # Convert sets to lists for JSON serialization
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
# Content Extraction and Detection
# ============================================

def extract_meaningful_content(html, url):
    """Extract meaningful content from HTML"""
    soup = BeautifulSoup(html, "html.parser")
    
    # Remove unwanted elements
    for element in soup(["script", "style", "nav", "footer", "aside", "header"]):
        element.decompose()
    
    # Get title
    title = ""
    if soup.title:
        title = soup.title.string.strip() if soup.title.string else "Untitled"
    elif soup.find("h1"):
        title = soup.find("h1").get_text(strip=True)
    else:
        title = "Untitled"
    
    # Get text content
    text_parts = []
    
    # Try to find main content areas
    content_selectors = ['article', '.content', '.post-content', '.entry-content', 'main', '#content']
    
    for selector in content_selectors:
        elements = soup.select(selector)
        if elements:
            for elem in elements:
                content = elem.get_text(" ", strip=True)
                if len(content) > 50:
                    text_parts.append(content)
            break
    
    # Fallback to paragraph extraction
    if not text_parts:
        paragraphs = soup.find_all(["p", "div"])
        text_parts = [p.get_text(" ", strip=True) for p in paragraphs if len(p.get_text(strip=True)) > 30]
    
    # Final fallback
    if not text_parts:
        text = soup.get_text(" ", strip=True)
    else:
        text = "\n".join(text_parts)
    
    # Clean up the text
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    return title, text

def detect_threats(title, text):
    """Detect threats in content"""
    threats = []
    content = f"{title} {text}".lower()
    
    threat_patterns = {
        'malware': r'\b(malware|virus|trojan|ransomware|backdoor|rootkit|keylogger)\b',
        'exploit': r'\b(exploit|vulnerability|cve-\d{4}-\d+|zero.?day|rce)\b',
        'credentials': r'\b(password.*dump|credential.*leak|combo.*list)\b',
        'phishing': r'\b(phishing|phish|fake.*site|spoofed)\b',
        'data_breach': r'\b(data.*breach|database.*leak|stolen.*data)\b'
    }
    
    for threat_type, pattern in threat_patterns.items():
        if re.search(pattern, content):
            threats.append(threat_type)
    
    return threats

def extract_entities(text):
    """Extract entities from text"""
    entities = {}
    
    # Email addresses
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    if emails:
        entities['emails'] = list(set(emails))[:10]
    
    # IP addresses
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    if ips:
        entities['ips'] = list(set(ips))[:10]
    
    # CVE numbers
    cves = re.findall(r'\bCVE-\d{4}-\d+\b', text, re.IGNORECASE)
    if cves:
        entities['cves'] = list(set(cves))
    
    return entities

# ============================================
# Main Crawler Class
# ============================================

class EnhancedCrawler:
    """Enhanced crawler with PostgreSQL and Redis support"""
    
    def __init__(self, config: CrawlerConfig):
        self.config = config
        
        # Initialize database manager
        if config.postgres_dsn:
            logger.info("Using PostgreSQL for deduplication")
            self.db_manager = PostgreSQLManager(config.postgres_dsn)
        else:
            logger.info("Using file-based deduplication")
            self.db_manager = FileBasedManager()
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Setup Tor if enabled
        if config.use_tor:
            tor_proxy = os.getenv("TOR_SOCKS", "tor:9050")
            self.session.proxies = {
                'http': f'socks5h://{tor_proxy}',
                'https': f'socks5h://{tor_proxy}'
            }
            logger.info(f"Using Tor proxy: {tor_proxy}")
    
    def crawl_url(self, url: str, site_name: str = "unknown") -> bool:
        """Crawl a single URL"""
        try:
            logger.info(f"Crawling: {url}")
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            # Extract content
            title, text = extract_meaningful_content(response.text, url)
            
            # Check for duplicate
            content_hash = hashlib.sha256(f"{title}{text}".encode()).hexdigest()
            if self.db_manager.check_duplicate(content_hash):
                logger.info(f"Duplicate content: {url}")
                return False
            
            # Detect threats and extract entities
            threats = detect_threats(title, text)
            entities = extract_entities(text)
            
            # Create document
            doc = {
                "url": url,
                "title": title,
                "text": text[:5000],
                "timestamp": datetime.utcnow().isoformat(),
                "source_site": site_name,
                "threat_types": threats,
                "entities": entities,
                "content_hash": content_hash
            }
            
            # Index to Elasticsearch
            es_url = f"http://{self.config.elastic_host}:{self.config.elastic_port}/posts/_doc"
            response = requests.post(es_url, json=doc, timeout=10)
            response.raise_for_status()
            
            # Add to deduplication database
            self.db_manager.add_content_hash(content_hash, url, title, site_name)
            
            logger.info(f"Successfully indexed: {title[:50]}...")
            
            if threats:
                logger.info(f"Threats detected: {threats}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return False
    
    def crawl_site(self, site_config: Dict) -> int:
        """Crawl a site based on configuration"""
        site_name = site_config.get('name', 'unknown')
        base_url = site_config.get('url', '')
        max_pages = min(
            site_config.get('max_pages', self.config.max_pages_per_seed),
            self.config.max_pages_per_seed
        )
        
        logger.info(f"Starting crawl of {site_name} (max {max_pages} pages)")
        
        pages_crawled = 0
        
        # For now, just crawl the base URL
        # You can expand this to handle pagination
        if self.crawl_url(base_url, site_name):
            pages_crawled += 1
        
        time.sleep(2)  # Be polite
        
        return pages_crawled

# ============================================
# Main Execution
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
    logger.info("Starting Enhanced Dark Web Crawler")
    
    # Initialize configuration
    config = CrawlerConfig()
    
    # Load site configuration
    site_config = load_config()
    
    # Initialize crawler
    crawler = EnhancedCrawler(config)
    
    # Main crawling loop
    crawl_count = 0
    while True:
        try:
            crawl_count += 1
            logger.info(f"Starting crawl cycle #{crawl_count}")
            
            for site in site_config.get('targets', []):
                if site.get('enabled', True):
                    crawler.crawl_site(site)
                    time.sleep(3)  # Delay between sites
            
            crawl_interval = site_config.get('crawl_interval', 1800)
            logger.info(f"Crawl cycle complete. Sleeping for {crawl_interval} seconds")
            time.sleep(crawl_interval)
            
        except KeyboardInterrupt:
            logger.info("Crawler stopped by user")
            break
        except Exception as e:
            logger.error(f"Crawler error: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
