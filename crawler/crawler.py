import os, yaml, time, requests, json, hashlib, re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag, urlparse
from urllib.robotparser import RobotFileParser
from datetime import datetime, timedelta
import logging
from collections import deque
import random
import sqlite3
from typing import Dict, List, Tuple, Optional, Set
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CFG_PATH = "config/config.yaml"
STATE_PATH = "state/crawler_state.json"
HASHES_DB_PATH = "state/content_hashes.db"
FAILED_DOCS_DB_PATH = "state/failed_documents.db"

# Compile regex patterns once for performance
class CompiledPatterns:
    """Pre-compiled regex patterns for performance"""
    
    # IoC patterns
    EMAIL = re.compile(r'\b[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Z|a-z]{2,}\b')
    IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    IPV6 = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b')
    CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
    MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
    SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
    SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
    SHA512 = re.compile(r'\b[a-fA-F0-9]{128}\b')
    URL = re.compile(r'https?://[^\s<>"{}\\|^`\[\]\'\(\)]+')
    DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    BTC_LEGACY = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    BTC_BECH32 = re.compile(r'\bbc1[a-z0-9]{39,59}\b')
    BTC_P2SH = re.compile(r'\b3[a-km-zA-HJ-NP-Z1-9]{33}\b')
    ETH = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
    WINDOWS_PATH = re.compile(r'[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.[a-zA-Z]{2,4}')
    UNIX_PATH = re.compile(r'/(?:usr|home|var|etc|opt|tmp)/[^<>:"\|\?\*\s]+')
    REGISTRY_KEY = re.compile(r'HK[A-Z_]+(?:\\[^\\<>:"\|\?\*\n\r]+)+')
    MITRE = re.compile(r'\b[TS]\d{4}(?:\.\d{3})?\b')
    USER_AGENT = re.compile(r'User-Agent:\s*([^\n\r]+)', re.IGNORECASE)
    
    # Threat patterns
    MALWARE = re.compile(
        r'\b(malware|virus|trojan|ransomware|backdoor|rootkit|keylogger|stealer|loader|dropper|'
        r'rat|remote access trojan|botnet|payload|shellcode|crypter|packer|cryptolocker|wannacry|'
        r'emotet|trickbot|cobalt strike|mimikatz|metasploit|empire|bloodhound|lazagne|redline|'
        r'vidar|raccoon|mars stealer|info stealer)\b', re.IGNORECASE
    )
    EXPLOIT = re.compile(
        r'\b(exploit|vulnerability|cve-\d{4}-\d+|zero[- ]?day|0day|rce|remote code execution|'
        r'lfi|local file inclusion|rfi|remote file inclusion|sqli|sql injection|xss|'
        r'cross[- ]site scripting|csrf|xxe|xml external entity|deserialization|buffer overflow|'
        r'heap spray|use[- ]after[- ]free|privilege escalation|privesc|kernel exploit)\b', re.IGNORECASE
    )

class HashesDatabase:
    """Persistent storage for content hashes using SQLite"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_db()
    
    def init_db(self):
        """Initialize the database with proper schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS content_hashes (
                    hash TEXT PRIMARY KEY,
                    url TEXT,
                    title TEXT,
                    source_site TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    indexed_to_es BOOLEAN DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON content_hashes(timestamp DESC)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_source 
                ON content_hashes(source_site)
            """)
            conn.commit()
    
    def exists(self, content_hash: str) -> bool:
        """Check if hash exists in database"""
        with sqlite3.connect(self.db_path) as conn:
            result = conn.execute(
                "SELECT 1 FROM content_hashes WHERE hash = ?", 
                (content_hash,)
            ).fetchone()
            return result is not None
    
    def add(self, content_hash: str, url: str, title: str, source_site: str):
        """Add new hash to database"""
        with sqlite3.connect(self.db_path) as conn:
            try:
                conn.execute("""
                    INSERT INTO content_hashes (hash, url, title, source_site)
                    VALUES (?, ?, ?, ?)
                """, (content_hash, url, title[:200], source_site))
                conn.commit()
            except sqlite3.IntegrityError:
                pass  # Hash already exists
    
    def cleanup_old(self, days: int = 30):
        """Remove hashes older than specified days"""
        with sqlite3.connect(self.db_path) as conn:
            deleted = conn.execute("""
                DELETE FROM content_hashes 
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            """, (days,)).rowcount
            conn.commit()
            if deleted > 0:
                logger.info(f"🧹 Cleaned up {deleted} old hashes")
            
    def get_stats(self) -> Dict:
        """Get statistics about stored hashes"""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM content_hashes").fetchone()[0]
            by_source = conn.execute("""
                SELECT source_site, COUNT(*) 
                FROM content_hashes 
                GROUP BY source_site
            """).fetchall()
            return {
                'total': total,
                'by_source': dict(by_source)
            }

class FailedDocumentsQueue:
    """Queue for documents that failed to index to Elasticsearch"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.init_db()
    
    def init_db(self):
        """Initialize failed documents database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS failed_docs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document TEXT,
                    error TEXT,
                    retry_count INTEGER DEFAULT 0,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    
    def add(self, doc: Dict, error: str):
        """Add failed document to queue"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO failed_docs (document, error)
                VALUES (?, ?)
            """, (json.dumps(doc), str(error)))
            conn.commit()
    
    def get_retry_batch(self, batch_size: int = 50) -> List[Tuple[int, Dict]]:
        """Get batch of documents to retry"""
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT id, document 
                FROM failed_docs 
                WHERE retry_count < 3
                ORDER BY timestamp ASC
                LIMIT ?
            """, (batch_size,)).fetchall()
            
            return [(row[0], json.loads(row[1])) for row in rows]
    
    def mark_retried(self, doc_id: int, success: bool):
        """Mark document as retried"""
        with sqlite3.connect(self.db_path) as conn:
            if success:
                conn.execute("DELETE FROM failed_docs WHERE id = ?", (doc_id,))
            else:
                conn.execute("""
                    UPDATE failed_docs 
                    SET retry_count = retry_count + 1
                    WHERE id = ?
                """, (doc_id,))
            conn.commit()

class FilteredContentLogger:
    """Log filtered content for auditing"""
    
    def __init__(self, es_host: str, es_port: str):
        self.es_host = es_host
        self.es_port = es_port
        self.filtered_buffer = []
        self.buffer_size = 50
    
    def log_filtered(self, url: str, title: str, reason: str, details: Dict = None):
        """Log why content was filtered"""
        doc = {
            "timestamp": datetime.utcnow().isoformat(),
            "url": url,
            "title": title[:200] if title else "Unknown",
            "filter_reason": reason,
            "filter_details": details or {},
            "doc_type": "filtered_content"
        }
        
        self.filtered_buffer.append(doc)
        
        # Flush buffer if it's full
        if len(self.filtered_buffer) >= self.buffer_size:
            self.flush()
    
    def flush(self):
        """Flush filtered content logs to Elasticsearch"""
        if not self.filtered_buffer:
            return
            
        for doc in self.filtered_buffer:
            try:
                url = f"http://{self.es_host}:{self.es_port}/crawler_audit/_doc"
                requests.post(url, json=doc, timeout=5)
            except Exception as e:
                logger.debug(f"Failed to log filtered content: {e}")
        
        self.filtered_buffer.clear()

class ContentFilter:
    """Enhanced content filtering with weighted scoring"""
    
    @staticmethod
    def is_bot_protection_page(title: str, text: str) -> Tuple[bool, Optional[Dict]]:
        """Detect bot protection with weighted scoring"""
        combined = f"{title} {text}".lower()
        
        # High confidence indicators (weight: 3)
        high_confidence = {
            "cloudflare": ["cloudflare", "ray id:"],
            "recaptcha": ["recaptcha", "verify that you are not a robot"],
            "verification": ["verification failed", "verifying your browser"]
        }
        
        # Medium confidence (weight: 2)
        medium_confidence = {
            "javascript_check": ["javascript is required", "enable javascript"],
            "security": ["security check", "ddos protection"]
        }
        
        # Low confidence (weight: 1)
        low_confidence = {
            "generic": ["just a moment", "checking your browser"]
        }
        
        score = 0
        detected = {}
        
        for category, patterns in high_confidence.items():
            matches = [p for p in patterns if p in combined]
            if matches:
                detected[category] = matches
                score += 3 * len(matches)
        
        for category, patterns in medium_confidence.items():
            matches = [p for p in patterns if p in combined]
            if matches:
                detected[category] = matches
                score += 2 * len(matches)
        
        for category, patterns in low_confidence.items():
            matches = [p for p in patterns if p in combined]
            if matches:
                detected[category] = matches
                score += len(matches)
        
        # Short content with high score = bot protection
        if len(text.strip()) < 500 and score >= 5:
            return True, {"score": score, "detected": detected}
        
        if score >= 8:
            return True, {"score": score, "detected": detected}
            
        return False, None

    @staticmethod
    def is_spam_scam_content(title: str, text: str) -> Tuple[bool, Optional[Dict]]:
        """Detect spam/scam with weighted scoring"""
        combined = f"{title} {text}".lower()
        
        # High risk indicators (weight: 3)
        high_risk = ["make $", "earn $", "instant profit", "free crypto method", 
                     "exchange exploit", "gmail logs"]
        
        # Medium risk (weight: 2)
        medium_risk = ["limited time", "act now", "special offer", "click here"]
        
        # Context-dependent (weight: 1, only count if other indicators present)
        context_dependent = ["free", "guaranteed", "easy money", "no risk"]
        
        score = 0
        detected = []
        
        for pattern in high_risk:
            if pattern in combined:
                detected.append(pattern)
                score += 3
        
        for pattern in medium_risk:
            if pattern in combined:
                detected.append(pattern)
                score += 2
        
        # Only count context-dependent if we already have some score
        if score > 0:
            for pattern in context_dependent:
                if pattern in combined:
                    detected.append(pattern)
                    score += 1
        
        # Money pattern
        if re.search(r'\$\d+.*(?:minutes?|mins?|hours?|daily)', combined):
            detected.append("money_promise")
            score += 3
        
        if score >= 7:  # Raised threshold
            return True, {"score": score, "indicators": detected}
            
        return False, None

    @staticmethod
    def is_promotional_content(title: str, text: str) -> Tuple[bool, Optional[Dict]]:
        """Detect promotional content with context awareness"""
        combined = f"{title} {text}".lower()
        
        # Strong promotional (weight: 3)
        strong_promo = ["black friday", "cyber monday", "limited offer", "buy now", 
                       "sign up today", "exclusive deal"]
        
        # Moderate promotional (weight: 2)
        moderate_promo = ["special offer", "discount", "% off", "free trial"]
        
        # Weak promotional (weight: 1) - could be legitimate
        weak_promo = ["pricing", "plans", "subscribe", "upgrade"]
        
        score = 0
        detected = []
        
        for pattern in strong_promo:
            if pattern in combined:
                detected.append(pattern)
                score += 3
        
        for pattern in moderate_promo:
            if pattern in combined:
                detected.append(pattern)
                score += 2
        
        # Only count weak indicators if content is short
        if len(text) < 500:
            for pattern in weak_promo:
                if pattern in combined:
                    detected.append(pattern)
                    score += 1
        
        # High score OR short content with moderate score
        if score >= 7 or (len(text) < 200 and score >= 4):
            return True, {"score": score, "indicators": detected}
            
        return False, None

    @staticmethod
    def is_low_quality_content(title: str, text: str) -> Tuple[bool, Optional[Dict]]:
        """Enhanced low quality detection"""
        
        # Too short
        text_length = len(text.strip())
        if text_length < 100:
            return True, {"reason": "content_too_short", "length": text_length}
        
        # Error pages
        error_patterns = {
            "404": r"404\s+not\s+found",
            "403": r"403\s+forbidden",
            "500": r"500\s+internal\s+server",
            "502": r"502\s+bad\s+gateway",
            "503": r"503\s+service\s+unavailable",
            "access_denied": r"access\s+denied",
            "not_found": r"page\s+not\s+found"
        }
        
        combined = f"{title} {text}".lower()
        for error_type, pattern in error_patterns.items():
            if re.search(pattern, combined):
                return True, {"reason": "error_page", "error_type": error_type}
        
        # JavaScript requirement (weight-based)
        js_score = 0
        js_indicators = ["javascript", "enable javascript", "javascript required", "noscript"]
        js_matches = [ind for ind in js_indicators if ind in combined]
        js_score = len(js_matches)
        
        if js_score >= 3 or (js_score >= 2 and text_length < 300):
            return True, {"reason": "javascript_required", "indicators": js_matches}
        
        # Navigation-heavy content
        if text_length < 300:  # Only check for short content
            nav_words = ["home", "about", "contact", "login", "register", "menu", "search"]
            words = text.lower().split()
            if words:
                nav_count = sum(1 for word in words if word in nav_words)
                nav_ratio = nav_count / len(words)
                if nav_ratio > 0.3:
                    return True, {"reason": "navigation_only", "nav_ratio": nav_ratio}
        
        return False, None

class RobotsChecker:
    """Check robots.txt compliance"""
    
    def __init__(self):
        self.robots_cache = {}
        self.cache_duration = 3600  # 1 hour
    
    def can_fetch(self, url: str, user_agent: str = "*") -> Tuple[bool, Optional[int]]:
        """Check if URL can be fetched according to robots.txt"""
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        # Check cache
        cache_key = parsed.netloc
        if cache_key in self.robots_cache:
            cached_time, rp, crawl_delay = self.robots_cache[cache_key]
            if time.time() - cached_time < self.cache_duration:
                return rp.can_fetch(user_agent, url), crawl_delay
        
        # Fetch and parse robots.txt
        try:
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            
            # Extract crawl-delay if present
            crawl_delay = None
            try:
                response = requests.get(robots_url, timeout=5)
                if response.status_code == 200:
                    for line in response.text.split('\n'):
                        if line.lower().startswith('crawl-delay:'):
                            crawl_delay = int(line.split(':')[1].strip())
                            break
            except:
                pass
            
            # Cache result
            self.robots_cache[cache_key] = (time.time(), rp, crawl_delay)
            
            return rp.can_fetch(user_agent, url), crawl_delay
            
        except Exception as e:
            logger.debug(f"Could not fetch robots.txt for {parsed.netloc}: {e}")
            return True, None  # Allow if robots.txt cannot be fetched

class EnhancedThreatDetector:
    """Improved threat and IoC detection with pre-compiled patterns"""
    
    @staticmethod
    def detect_threats(title: str, text: str) -> Dict[str, float]:
        """Detect threats using pre-compiled patterns"""
        threats = {}
        content = f"{title} {text}"
        
        # Check each threat type
        if CompiledPatterns.MALWARE.search(content):
            threats['malware'] = 0.9
        
        if CompiledPatterns.EXPLOIT.search(content):
            threats['exploit'] = 0.95
        
        # Add more threat checks as needed...
        
        return threats

    @staticmethod
    def extract_iocs(text: str) -> Dict[str, List]:
        """Extract IoCs using pre-compiled patterns"""
        iocs = {}
        
        # Email addresses
        emails = CompiledPatterns.EMAIL.findall(text)
        if emails:
            iocs['email_addresses'] = list(set(emails))[:20]
        
        # IP addresses
        ipv4_addresses = CompiledPatterns.IPV4.findall(text)
        if ipv4_addresses:
            iocs['ipv4_addresses'] = list(set(ipv4_addresses))[:20]
        
        ipv6_addresses = CompiledPatterns.IPV6.findall(text)
        if ipv6_addresses:
            iocs['ipv6_addresses'] = list(set(ipv6_addresses))[:10]
        
        # CVEs
        cves = CompiledPatterns.CVE.findall(text)
        if cves:
            iocs['cve_ids'] = list(set(cves))[:50]
        
        # File hashes
        md5_hashes = CompiledPatterns.MD5.findall(text)
        if md5_hashes:
            # Filter out potential false positives (e.g., not all lowercase/uppercase)
            valid_md5 = [h for h in md5_hashes if not (h.islower() or h.isupper())]
            if valid_md5:
                iocs['md5_hashes'] = list(set(valid_md5))[:20]
        
        sha1_hashes = CompiledPatterns.SHA1.findall(text)
        if sha1_hashes:
            valid_sha1 = [h for h in sha1_hashes if not (h.islower() or h.isupper())]
            if valid_sha1:
                iocs['sha1_hashes'] = list(set(valid_sha1))[:20]
        
        sha256_hashes = CompiledPatterns.SHA256.findall(text)
        if sha256_hashes:
            valid_sha256 = [h for h in sha256_hashes if not (h.islower() or h.isupper())]
            if valid_sha256:
                iocs['sha256_hashes'] = list(set(valid_sha256))[:20]
        
        # URLs and domains
        urls = CompiledPatterns.URL.findall(text)
        if urls:
            # Clean URLs
            clean_urls = []
            for url in urls[:30]:
                url = re.sub(r'[.,;:!?\'")\]]+$', '', url)
                if 10 < len(url) < 500:
                    clean_urls.append(url)
            if clean_urls:
                iocs['urls'] = list(set(clean_urls))[:20]
        
        domains = CompiledPatterns.DOMAIN.findall(text)
        if domains:
            # Filter common domains
            excluded = {'example.com', 'test.com', 'localhost', 'github.com', 'google.com', 
                       'microsoft.com', 'apple.com', 'amazon.com'}
            clean_domains = [d for d in set(domains) 
                           if d.lower() not in excluded and len(d) > 4][:30]
            if clean_domains:
                iocs['domains'] = clean_domains
        
        # Cryptocurrency addresses
        btc_addresses = (CompiledPatterns.BTC_LEGACY.findall(text) +
                        CompiledPatterns.BTC_BECH32.findall(text) +
                        CompiledPatterns.BTC_P2SH.findall(text))
        if btc_addresses:
            iocs['bitcoin_addresses'] = list(set(btc_addresses))[:10]
        
        eth_addresses = CompiledPatterns.ETH.findall(text)
        if eth_addresses:
            iocs['ethereum_addresses'] = list(set(eth_addresses))[:10]
        
        # File paths
        win_paths = CompiledPatterns.WINDOWS_PATH.findall(text)
        if win_paths:
            iocs['windows_paths'] = list(set(win_paths))[:10]
        
        unix_paths = CompiledPatterns.UNIX_PATH.findall(text)
        if unix_paths:
            iocs['unix_paths'] = list(set(unix_paths))[:10]
        
        # Registry keys
        registry_keys = CompiledPatterns.REGISTRY_KEY.findall(text)
        if registry_keys:
            iocs['registry_keys'] = list(set(registry_keys))[:10]
        
        # MITRE ATT&CK
        mitre_ids = CompiledPatterns.MITRE.findall(text)
        if mitre_ids:
            iocs['mitre_attack_ids'] = list(set(mitre_ids))[:20]
        
        return iocs

class ProductionCrawler:
    """Production-ready crawler with all fixes"""
    
    def __init__(self, es_host: str, es_port: str, use_tor: bool = False):
        self.es_host = es_host
        self.es_port = es_port
        self.use_tor = use_tor
        
        # Initialize user agents BEFORE setup_session
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
        ]
        
        self.session = self._setup_session()
        self.content_filter = ContentFilter()
        self.threat_detector = EnhancedThreatDetector()
        self.hashes_db = HashesDatabase(HASHES_DB_PATH)
        self.failed_docs_queue = FailedDocumentsQueue(FAILED_DOCS_DB_PATH)
        self.filter_logger = FilteredContentLogger(es_host, es_port)
        self.robots_checker = RobotsChecker()
        self.failed_urls = deque(maxlen=100)

    def _setup_session(self):
        """Setup requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if self.use_tor:
            session.proxies = {
                'http': 'socks5h://tor:9050',
                'https': 'socks5h://tor:9050'
            }
            logger.info("🔒 Using Tor proxy")
        
        from requests.adapters import HTTPAdapter
        from requests.packages.urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session

    async def crawl_site_async(self, site_config: Dict, state: Dict, max_pages: int) -> Dict:
        """Async crawling for better performance"""
        # Implementation of async crawling with aiohttp
        # ... (would require full async implementation)
        pass

    def crawl_site(self, site_config: Dict, state: Dict, max_pages: int) -> Dict:
        """Crawl a site with comprehensive tracking"""
        site_name = site_config['name']
        base_url = site_config['url']
        site_max_pages = min(site_config.get('max_pages', max_pages), max_pages)
        
        logger.info(f"🕷️  Starting crawl of {site_name}")
        
        stats = {
            'pages_crawled': 0,
            'threats_found': 0,
            'iocs_extracted': 0,
            'filtered': {
                'bot_protection': 0,
                'promotional': 0,
                'spam': 0,
                'low_quality': 0,
                'duplicate': 0,
                'error': 0,
                'robots_txt': 0
            }
        }
        
        urls = self._generate_urls(base_url, site_config, site_max_pages)
        
        for url in urls:
            if stats['pages_crawled'] >= site_max_pages:
                break
            
            # Check robots.txt
            user_agent = self.session.headers['User-Agent'].split()[0]
            can_fetch, crawl_delay = self.robots_checker.can_fetch(url, user_agent)
            
            if not can_fetch:
                logger.debug(f"🚫 Robots.txt disallows: {url}")
                stats['filtered']['robots_txt'] += 1
                continue
            
            success = self._crawl_url(url, site_name, site_config, state, stats)
            
            if success:
                stats['pages_crawled'] += 1
