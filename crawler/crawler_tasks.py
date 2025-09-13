# crawler/crawler_tasks.py
"""
Celery tasks for distributed threat intelligence feed processing
This file needs to be in the crawler directory for Celery to find it
"""

import os
import time
import requests
import hashlib
import json
import csv
import re
from datetime import datetime
from celery import Celery
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Celery
app = Celery('crawler_tasks')

# Configure Celery
app.conf.update(
    broker_url=os.getenv('CELERY_BROKER', 'redis://redis:6379/0'),
    result_backend=os.getenv('CELERY_BACKEND', 'redis://redis:6379/1'),
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

# Import your new feed processing functions from the modified crawler.py
try:
    from crawler import process_feed_content, determine_ioc_type, create_ioc_document
except ImportError:
    # Fallback implementations if the import fails
    def process_feed_content(content, feed_config, url):
        """Fallback feed processing"""
        return []
    
    def determine_ioc_type(value, feed_config):
        """Fallback IOC type detection"""
        return 'unknown'
    
    def create_ioc_document(value, ioc_type, source, feed_url):
        """Fallback IOC document creation"""
        return {}

@app.task(bind=True, max_retries=3)
def process_feed(self, feed_config):
    """
    Celery task to process a single threat intelligence feed
    """
    try:
        feed_name = feed_config.get('name', 'unknown')
        feed_url = feed_config.get('url', '')
        feed_format = feed_config.get('format', 'text')
        
        logger.info(f"Processing feed: {feed_name} ({feed_format})")
        
        # Fetch the feed content
        headers = {
            'User-Agent': 'ThreatIntelCrawler/1.0'
        }
        
        response = requests.get(feed_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Process the feed content based on format
        ioc_documents = []
        
        if feed_format == 'text':
            ioc_documents = parse_text_feed(response.text, feed_config, feed_url)
        elif feed_format == 'csv':
            ioc_documents = parse_csv_feed(response.text, feed_config, feed_url)
        elif feed_format == 'json':
            ioc_documents = parse_json_feed(response.text, feed_config, feed_url)
        else:
            logger.warning(f"Unknown feed format: {feed_format} for {feed_name}")
        
        # Index IOCs to Elasticsearch
        successful_indexes = 0
        for doc in ioc_documents:
            if index_ioc_document(doc, feed_name):
                successful_indexes += 1
        
        logger.info(f"Processed {successful_indexes}/{len(ioc_documents)} IOCs from {feed_name}")
        
        return {
            'feed': feed_name,
            'iocs_processed': successful_indexes,
            'total_iocs': len(ioc_documents),
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error processing feed {feed_config.get('name', 'unknown')}: {e}")
        raise self.retry(exc=e, countdown=60)

def parse_text_feed(content: str, feed_config: Dict, url: str) -> List[Dict]:
    """Parse text-based feeds (one IOC per line)"""
    iocs = []
    feed_name = feed_config['name']
    
    for line in content.splitlines():
        line = line.strip()
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
            
        # Determine IOC type based on feed type and content
        ioc_value = line
        ioc_type = determine_ioc_type(line, feed_config)
        
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
            # Extract IOCs based on common CSV structures
            ioc_candidates = []
            
            # Check common IOC fields in CSV feeds
            for field in ['url', 'domain', 'hostname', 'ip', 'sha256', 'md5', 'cve']:
                if field in row and row[field]:
                    ioc_value = row[field].strip()
                    ioc_type = determine_ioc_type(ioc_value, feed_config)
                    if ioc_type and ioc_type != 'unknown':
                        ioc_candidates.append((ioc_value, ioc_type))
            
            # Create documents for found IOCs
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
        
        # CISA KEV Feed
        if feed_name == 'cisa_known_exploited_vulns':
            for vuln in data.get('vulnerabilities', []):
                if 'cveID' in vuln:
                    ioc_doc = create_ioc_document(
                        vuln['cveID'], 'cve', feed_name, url
                    )
                    iocs.append(ioc_doc)
        
        # Generic JSON with IOCs array
        elif 'iocs' in data:
            for ioc in data['iocs']:
                if 'value' in ioc and 'type' in ioc:
                    ioc_doc = create_ioc_document(
                        ioc['value'], ioc['type'], feed_name, url
                    )
                    iocs.append(ioc_doc)
                    
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error for {feed_name}: {e}")
        
    return iocs

def determine_ioc_type(value: str, feed_config: Dict) -> str:
    """Determine the type of IOC based on its value"""
    value = value.strip()
    
    # IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
        return 'ip'
        
    # Domain (simple check)
    if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
        return 'domain'
        
    # URL
    if value.startswith(('http://', 'https://')):
        return 'url'
        
    # SHA256 hash
    if re.match(r'^[a-fA-F0-9]{64}$', value):
        return 'sha256'
        
    # MD5 hash
    if re.match(r'^[a-fA-F0-9]{32}$', value):
        return 'md5'
        
    # CVE
    if re.match(r'^CVE-\d{4}-\d+$', value, re.IGNORECASE):
        return 'cve'
        
    # Fallback: use feed type hint
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

def index_ioc_document(doc: Dict, source: str) -> bool:
    """Index an IOC document to Elasticsearch"""
    try:
        es_host = os.getenv('ELASTIC_HOST', 'elasticsearch')
        es_port = os.getenv('ELASTIC_PORT', '9200')
        
        # Index to Elasticsearch - using iocs index
        es_url = f"http://{es_host}:{es_port}/iocs/_doc"
        response = requests.post(es_url, json=doc, timeout=10)
        response.raise_for_status()
        
        logger.debug(f"Indexed IOC: {doc['ioc_type']}:{doc['ioc_value'][:50]}...")
        return True
        
    except Exception as e:
        logger.error(f"Failed to index IOC document: {e}")
        return False

@app.task
def process_feeds_batch(feeds_config):
    """
    Process a batch of feeds
    """
    results = []
    for feed in feeds_config.get('targets', []):
        if feed.get('enabled', True):
            result = process_feed.delay(feed)
            results.append(result.id)
    return results

@app.task
def health_check():
    """
    Health check task
    """
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'threat_intel_processor'
    }

# Celery beat schedule
app.conf.beat_schedule = {
    'process-feeds-hourly': {
        'task': 'crawler_tasks.process_feeds_batch',
        'schedule': 3600.0,  # Every hour
        'args': ({"targets": []},),  # Will be populated from config
    },
    'health-check-5min': {
        'task': 'crawler_tasks.health_check',
        'schedule': 300.0,  # Every 5 minutes
    },
}
