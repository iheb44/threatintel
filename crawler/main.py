import os
import sys
import logging
import time
import yaml
import signal
from typing import Dict, Optional

# Add the crawler directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging with better error handling
def setup_logging():
    """Setup logging with fallback to console if file logging fails"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    handlers = []
    
    # Always add console handler
    handlers.append(logging.StreamHandler())
    
    # Try to add file handler if directory exists
    log_dir = '/app/logs'
    if os.path.exists(log_dir) and os.access(log_dir, os.W_OK):
        try:
            handlers.append(logging.FileHandler(f'{log_dir}/crawler.log'))
        except Exception as e:
            print(f"Warning: Could not create log file: {e}")
    elif not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
            handlers.append(logging.FileHandler(f'{log_dir}/crawler.log'))
        except Exception as e:
            print(f"Warning: Could not create log directory: {e}")
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=handlers
    )

setup_logging()
logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from environment variables with validation"""
    try:
        from config import EnhancedCrawlerConfig
        
        config = EnhancedCrawlerConfig()
        logger.info("Configuration loaded successfully")
        logger.info(f"Elasticsearch hosts: {config.elasticsearch_hosts}")
        logger.info(f"Use Tor: {config.use_tor}")
        
        return config
        
    except ImportError as e:
        logger.error(f"Failed to import config module: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

def load_feed_config(config_file_path: str) -> Dict:
    """Load feed configuration from YAML file with defaults"""
    default_config = {
        'targets': [
            {
                'name': 'abuse_ch_urlhaus_domains',
                'url': 'https://urlhaus.abuse.ch/downloads/hostfile/',
                'format': 'text',
                'enabled': True,
                'parsing': {
                    'text': {
                        'skip_patterns': ['#', '//']
                    }
                }
            }
        ],
        'crawl_interval': 1800
    }
    
    try:
        if not os.path.exists(config_file_path):
            logger.warning(f"Feed config file not found: {config_file_path}")
            logger.info("Using default feed configuration")
            return default_config
            
        with open(config_file_path, 'r') as f:
            feed_config = yaml.safe_load(f)
            
        # Validate config structure
        if not isinstance(feed_config, dict):
            logger.error("Invalid feed config format")
            return default_config
            
        if 'targets' not in feed_config:
            feed_config['targets'] = []
            
        logger.info(f"Loaded feed configuration with {len(feed_config.get('targets', []))} targets")
        return feed_config
        
    except yaml.YAMLError as e:
        logger.error(f"YAML parsing error in feed config: {e}")
        return default_config
    except Exception as e:
        logger.error(f"Failed to load feed configuration: {e}")
        return default_config

class CrawlerManager:
    """Manager class for handling crawler lifecycle"""
    
    def __init__(self):
        self.crawler = None
        self.running = True
        self.config = None
        self.feed_config = None
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def initialize(self):
        """Initialize crawler components"""
        try:
            # Load configuration
            self.config = load_config()
            self.feed_config = load_feed_config('/app/config/config.yaml')
            
            # Initialize crawler
            from crawler import EnhancedThreatIntelligenceCrawler
            self.crawler = EnhancedThreatIntelligenceCrawler(self.config)
            logger.info("Crawler initialized successfully")
            
            return True
            
        except ImportError as e:
            logger.error(f"Failed to import crawler module: {e}")
            logger.error("Please ensure crawler.py exists and is properly configured")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize crawler: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def run_processing_cycle(self):
        """Run a single processing cycle"""
        cycle_start = time.time()
        total_processed = 0
        
        try:
            logger.info("Starting feed processing cycle")
            
            # Process all enabled feeds
            enabled_feeds = [f for f in self.feed_config.get('targets', []) if f.get('enabled', True)]
            logger.info(f"Processing {len(enabled_feeds)} enabled feeds")
            
            for feed in enabled_feeds:
                if not self.running:
                    logger.info("Shutdown requested, stopping feed processing")
                    break
                    
                try:
                    feed_name = feed.get('name', 'unknown')
                    logger.info(f"Processing feed: {feed_name}")
                    
                    processed_iocs = self.crawler.process_feed(feed)
                    total_processed += len(processed_iocs)
                    
                    logger.info(f"Feed {feed_name} completed: {len(processed_iocs)} IOCs processed")
                    
                    # Small delay between feeds to avoid overwhelming sources
                    if self.running:
                        time.sleep(2)
                        
                except Exception as e:
                    logger.error(f"Error processing feed {feed.get('name', 'unknown')}: {e}")
                    continue
            
            # Log cycle statistics
            cycle_duration = time.time() - cycle_start
            stats = self.crawler.get_stats() if self.crawler else {}
            
            logger.info(f"Cycle completed in {cycle_duration:.2f}s")
            logger.info(f"Total IOCs processed: {total_processed}")
            logger.info(f"Session stats: {stats}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error in processing cycle: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            if self.crawler:
                self.crawler.cleanup()
                logger.info("Crawler cleanup completed")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def run(self):
        """Main execution loop"""
        if not self.initialize():
            logger.error("Failed to initialize crawler")
            return 1
        
        logger.info("Threat Intelligence Crawler started")
        
        try:
            while self.running:
                try:
                    # Run processing cycle
                    success = self.run_processing_cycle()
                    
                    if not success:
                        logger.warning("Processing cycle failed, will retry after delay")
                    
                    # Sleep until next cycle (if still running)
                    if self.running:
                        sleep_time = self.feed_config.get('crawl_interval', 1800)
                        logger.info(f"Sleeping for {sleep_time} seconds until next cycle")
                        
                        # Sleep in chunks to allow for graceful shutdown
                        for _ in range(sleep_time):
                            if not self.running:
                                break
                            time.sleep(1)
                    
                except KeyboardInterrupt:
                    logger.info("Crawler stopped by user")
                    break
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    if self.running:
                        logger.info("Waiting 5 minutes before retrying...")
                        time.sleep(300)
            
            return 0
            
        except Exception as e:
            logger.error(f"Fatal error in crawler: {e}")
            import traceback
            traceback.print_exc()
            return 1
        finally:
            self.cleanup()

def main():
    """Main entry point"""
    try:
        manager = CrawlerManager()
        return manager.run()
    except Exception as e:
        logger.error(f"Failed to start crawler manager: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
