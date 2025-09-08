# crawler/crawler_tasks.py
"""
Celery tasks for distributed crawling
This file needs to be in the crawler directory for Celery to find it
"""

import os
import time
import requests
import hashlib
import json
from datetime import datetime
from celery import Celery
from bs4 import BeautifulSoup
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

# Import your existing crawler code if available
try:
    from crawler import extract_meaningful_content, detect_threats, extract_entities
except ImportError:
    # Fallback implementations if your crawler.py doesn't have these
    def extract_meaningful_content(html, url):
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.title.string if soup.title else "Untitled"
        text = soup.get_text(' ', strip=True)
        return title, text
    
    def detect_threats(title, text):
        # Basic threat detection
        threats = []
        content = f"{title} {text}".lower()
        if 'malware' in content:
            threats.append('malware')
        if 'exploit' in content:
            threats.append('exploit')
        return threats
    
    def extract_entities(text):
        # Basic entity extraction
        return {}

@app.task(bind=True, max_retries=3)
def crawl_url(self, url, site_config=None):
    """
    Celery task to crawl a single URL
    """
    try:
        logger.info(f"Crawling: {url}")
        
        # Basic crawling logic
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Extract content
        title, text = extract_meaningful_content(response.text, url)
        
        # Detect threats
        threats = detect_threats(title, text)
        
        # Extract entities
        entities = extract_entities(text)
        
        # Create document
        doc = {
            'url': url,
            'title': title,
            'text': text[:5000],  # Limit text size
            'threats': threats,
            'entities': entities,
            'timestamp': datetime.utcnow().isoformat(),
            'source_site': site_config.get('name', 'unknown') if site_config else 'unknown'
        }
        
        # Index to Elasticsearch
        es_host = os.getenv('ELASTIC_HOST', 'elasticsearch')
        es_port = os.getenv('ELASTIC_PORT', '9200')
        
        es_url = f"http://{es_host}:{es_port}/posts/_doc"
        requests.post(es_url, json=doc, timeout=10)
        
        logger.info(f"Successfully crawled: {url}")
        return doc
        
    except Exception as e:
        logger.error(f"Error crawling {url}: {e}")
        raise self.retry(exc=e, countdown=60)

@app.task
def process_batch(urls, site_config=None):
    """
    Process a batch of URLs
    """
    results = []
    for url in urls:
        result = crawl_url.delay(url, site_config)
        results.append(result)
    return results

@app.task
def health_check():
    """
    Health check task
    """
    return {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    }
