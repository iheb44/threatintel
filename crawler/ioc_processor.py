"""
IOC Data Standardization and Enrichment Module
Handles normalization, enrichment, and deduplication of threat intelligence data
"""

import re
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
import logging
import ipaddress
import socket
import requests
import json
from urllib.parse import urlparse, quote_plus

logger = logging.getLogger(__name__)

class IOCProcessor:
    """Process and enrich IOC data with standardization and enrichment"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.geoip_enabled = self.config.get('geoip_enabled', True)
        self.asn_enabled = self.config.get('asn_enabled', True)
        self.enrichment_timeout = self.config.get('enrichment_timeout', 5)
        
    def process_ioc(self, ioc_value: str, ioc_type: str, source: str, feed_url: str, 
                   raw_data: Optional[Dict] = None) -> Dict:
        """
        Process and enrich a single IOC with standardization and enrichment
        """
        # Normalize IOC value and type
        normalized_value, normalized_type = self.normalize_ioc(ioc_value, ioc_type)
        
        if normalized_type == 'unknown':
            logger.warning(f"Unable to determine type for IOC: {ioc_value}")
            return {}
        
        # Create base IOC document
        ioc_doc = self.create_base_ioc_document(normalized_value, normalized_type, source, feed_url)
        
        # Add enrichment data
        enriched_doc = self.enrich_ioc(ioc_doc, raw_data)
        
        return enriched_doc
    
    def normalize_ioc(self, value: str, suggested_type: str = '') -> Tuple[str, str]:
        """
        Normalize IOC value and determine its type consistently
        """
        value = value.strip()
        
        # Normalize based on type detection
        detected_type = self.detect_ioc_type(value)
        
        # Use detected type if available, otherwise use suggested type
        final_type = detected_type if detected_type != 'unknown' else suggested_type
        
        # Normalize value based on type
        normalized_value = self.normalize_value(value, final_type)
        
        return normalized_value, final_type
    
    def detect_ioc_type(self, value: str) -> str:
        """
        Detect IOC type with enhanced pattern matching
        """
        value = value.strip()
        
        # IP Address (IPv4 with optional CIDR)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', value):
            try:
                ipaddress.IPv4Address(value.split('/')[0])
                return 'ip'
            except (ipaddress.AddressValueError, ValueError):
                pass
        
        # IPv6 Address
        if re.match(r'^[0-9a-fA-F:]+(/\d{1,3})?$', value) and '::' in value:
            try:
                ipaddress.IPv6Address(value.split('/')[0])
                return 'ip'
            except (ipaddress.AddressValueError, ValueError):
                pass
        
        # Domain (enhanced validation)
        if (re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', value) and
            re.match(r'.*\.[a-zA-Z]{2,}$', value) and
            len(value) <= 253):
            return 'domain'
        
        # URL (with proper scheme validation)
        if (value.startswith(('http://', 'https://', 'ftp://', 'ftps://')) and
            len(value) <= 2000 and  # Reasonable URL length limit
            re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', value)):
            try:
                parsed = urlparse(value)
                if parsed.netloc:  # Must have a network location
                    return 'url'
            except:
                pass
        
        # Hash types
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'sha256'
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'sha1'
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'md5'
        
        # CVE (strict validation)
        if re.match(r'^CVE-\d{4}-\d{4,}$', value, re.IGNORECASE):
            return 'cve'
        
        # Email address
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return 'email'
        
        # File path (Windows and Unix)
        if re.match(r'^([a-zA-Z]:\\|\\\\|/).*', value):
            return 'file_path'
        
        return 'unknown'
    
    def normalize_value(self, value: str, ioc_type: str) -> str:
        """
        Normalize IOC value based on its type
        """
        if not value:
            return value
        
        value = value.strip()
        
        if ioc_type in ['sha256', 'sha1', 'md5']:
            # Hashes to lowercase
            return value.lower()
        
        elif ioc_type == 'cve':
            # CVE to uppercase
            return value.upper()
        
        elif ioc_type == 'url':
            # URL normalization
            try:
                parsed = urlparse(value)
                # Normalize scheme and host to lowercase
                normalized_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
                if parsed.query:
                    normalized_url += f"?{parsed.query}"
                if parsed.fragment:
                    normalized_url += f"#{parsed.fragment}"
                return normalized_url
            except:
                return value
        
        elif ioc_type == 'domain':
            # Domain to lowercase
            return value.lower()
        
        elif ioc_type == 'ip':
            # IP address normalization
            try:
                if '/' in value:
                    # CIDR notation
                    ip, cidr = value.split('/', 1)
                    normalized_ip = str(ipaddress.ip_address(ip))
                    return f"{normalized_ip}/{cidr}"
                else:
                    return str(ipaddress.ip_address(value))
            except (ipaddress.AddressValueError, ValueError):
                return value
        
        return value
    
    def create_base_ioc_document(self, value: str, ioc_type: str, source: str, feed_url: str) -> Dict:
        """
        Create standardized base IOC document
        """
        # Generate content hash for deduplication
        content_hash = self.generate_content_hash(value, ioc_type, source)
        
        # Normalize timestamp to UTC
        timestamp = datetime.now(timezone.utc).isoformat()
        
        base_doc = {
            "ioc_value": value,
            "ioc_type": ioc_type,
            "source_feed": source,
            "feed_url": feed_url,
            "timestamp": timestamp,
            "content_hash": content_hash,
            "threat_types": [],
            "entities": {
                ioc_type + "s": [value]
            },
            "metadata": {
                "processed_at": timestamp,
                "normalized": True,
                "enrichment_status": "pending"
            }
        }
        
        # Add type-specific entities
        self.add_type_specific_entities(base_doc, value, ioc_type)
        
        return base_doc
    
    def generate_content_hash(self, value: str, ioc_type: str, source: str) -> str:
        """
        Generate consistent hash for deduplication
        """
        # Use normalized values for consistent hashing
        hash_input = f"{value}:{ioc_type}:{source}".encode('utf-8')
        return hashlib.sha256(hash_input).hexdigest()
    
    def add_type_specific_entities(self, doc: Dict, value: str, ioc_type: str):
        """
        Add type-specific entities to the IOC document
        """
        if ioc_type == 'ip':
            doc['entities']['ips'] = [value]
            # Extract network information for IPs
            try:
                if '/' in value:
                    ip_net = ipaddress.ip_network(value, strict=False)
                    doc['entities']['network'] = str(ip_net)
                    doc['entities']['network_range'] = {
                        'first_ip': str(ip_net[0]),
                        'last_ip': str(ip_net[-1]),
                        'cidr': value
                    }
                else:
                    ip_addr = ipaddress.ip_address(value)
                    if ip_addr.is_private:
                        doc['metadata']['private_ip'] = True
            except (ipaddress.AddressValueError, ValueError):
                pass
        
        elif ioc_type == 'domain':
            doc['entities']['domains'] = [value]
            # Extract domain components
            if '.' in value:
                parts = value.split('.')
                if len(parts) >= 2:
                    doc['entities']['root_domain'] = f"{parts[-2]}.{parts[-1]}"
                    doc['entities']['tld'] = parts[-1]
        
        elif ioc_type == 'url':
            doc['entities']['urls'] = [value]
            # Extract URL components
            try:
                parsed = urlparse(value)
                if parsed.netloc:
                    doc['entities']['domain'] = parsed.netloc
                if parsed.path:
                    doc['entities']['path'] = parsed.path
            except:
                pass
        
        elif ioc_type in ['sha256', 'sha1', 'md5']:
            doc['entities']['hashes'] = [value]
            doc['entities']['hash_type'] = ioc_type
        
        elif ioc_type == 'cve':
            doc['entities']['cves'] = [value]
            # Extract CVE components
            match = re.match(r'CVE-(\d{4})-(\d+)', value, re.IGNORECASE)
            if match:
                doc['entities']['cve_year'] = match.group(1)
                doc['entities']['cve_id'] = match.group(2)
    
    def enrich_ioc(self, ioc_doc: Dict, raw_data: Optional[Dict] = None) -> Dict:
        """
        Enrich IOC with additional data (GeoIP, ASN, threat intelligence)
        """
        enriched_doc = ioc_doc.copy()
        value = enriched_doc['ioc_value']
        ioc_type = enriched_doc['ioc_type']
        
        # Initialize enrichment section
        if 'enrichment' not in enriched_doc:
            enriched_doc['enrichment'] = {}
        
        # IP-based enrichment
        if ioc_type == 'ip' and self.geoip_enabled:
            self.enrich_ip_data(enriched_doc, value)
        
        # Domain-based enrichment
        if ioc_type == 'domain':
            self.enrich_domain_data(enriched_doc, value)
        
        # URL-based enrichment
        if ioc_type == 'url':
            self.enrich_url_data(enriched_doc, value)
        
        # Threat intelligence enrichment
        self.enrich_threat_intel(enriched_doc, raw_data)
        
        # Add tags based on feed and content
        self.add_ioc_tags(enriched_doc, raw_data)
        
        # Update enrichment status
        enriched_doc['metadata']['enrichment_status'] = 'completed'
        enriched_doc['metadata']['enriched_at'] = datetime.now(timezone.utc).isoformat()
        
        return enriched_doc
    
    def enrich_ip_data(self, doc: Dict, ip_value: str):
        """
        Enrich IP address with GeoIP and ASN data
        """
        try:
            # Remove CIDR notation for enrichment
            clean_ip = ip_value.split('/')[0]
            
            # GeoIP enrichment (using free services)
            geo_data = self.get_geoip_data(clean_ip)
            if geo_data:
                doc['enrichment']['geoip'] = geo_data
            
            # ASN enrichment
            asn_data = self.get_asn_data(clean_ip)
            if asn_data:
                doc['enrichment']['asn'] = asn_data
            
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(clean_ip)[0]
                doc['enrichment']['reverse_dns'] = hostname
            except (socket.herror, socket.gaierror):
                pass
                
        except Exception as e:
            logger.warning(f"IP enrichment failed for {ip_value}: {e}")
    
    def get_geoip_data(self, ip: str) -> Optional[Dict]:
        """
        Get GeoIP data using free services
        """
        try:
            # Try ipapi.co (free tier available)
            response = requests.get(
                f"http://ipapi.co/{ip}/json/",
                timeout=self.enrichment_timeout
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'asn': data.get('asn'),
                    'org': data.get('org'),
                    'source': 'ipapi.co'
                }
        except requests.RequestException:
            pass
        
        try:
            # Fallback to ip-api.com
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=self.enrichment_timeout
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'asn': data.get('as'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'source': 'ip-api.com'
                    }
        except requests.RequestException:
            pass
        
        return None
    
    def get_asn_data(self, ip: str) -> Optional[Dict]:
        """
        Get ASN data for IP address
        """
        try:
            # Use Team Cymru IP to ASN service
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            
            try:
                asn_data = socket.gethostbyname_ex(query)
                if asn_data and len(asn_data[2]) > 0:
                    asn_info = asn_data[2][0].split('|')
                    if len(asn_info) >= 3:
                        return {
                            'asn': asn_info[0].strip(),
                            'ip_range': asn_info[1].strip(),
                            'country': asn_info[2].strip(),
                            'source': 'team-cymru'
                        }
            except (socket.herror, socket.gaierror):
                pass
                
        except Exception:
            pass
        
        return None
    
    def enrich_domain_data(self, doc: Dict, domain: str):
        """
        Enrich domain with additional information
        """
        try:
            # Basic domain analysis
            doc['enrichment']['domain_analysis'] = {
                'length': len(domain),
                'subdomain_count': domain.count('.'),
                'is_subdomain': domain.count('.') > 1
            }
            
            # Try to get IP addresses for domain
            try:
                ips = socket.getaddrinfo(domain, None)
                unique_ips = list(set(ip[4][0] for ip in ips))
                doc['enrichment']['resolved_ips'] = unique_ips
            except (socket.gaierror, socket.herror):
                pass
                
        except Exception as e:
            logger.warning(f"Domain enrichment failed for {domain}: {e}")
    
    def enrich_url_data(self, doc: Dict, url: str):
        """
        Enrich URL with additional information
        """
        try:
            parsed = urlparse(url)
            doc['enrichment']['url_analysis'] = {
                'scheme': parsed.scheme,
                'domain': parsed.netloc,
                'path_length': len(parsed.path),
                'has_query': bool(parsed.query),
                'has_fragment': bool(parsed.fragment),
                'url_length': len(url)
            }
        except Exception as e:
            logger.warning(f"URL enrichment failed for {url}: {e}")
    
    def enrich_threat_intel(self, doc: Dict, raw_data: Optional[Dict] = None):
        """
        Add threat intelligence context from raw data
        """
        if not raw_data:
            return
        
        # Extract threat actor information
        threat_actors = self.extract_threat_actors(raw_data)
        if threat_actors:
            doc['enrichment']['threat_actors'] = threat_actors
        
        # Extract malware families
        malware_families = self.extract_malware_families(raw_data)
        if malware_families:
            doc['enrichment']['malware_families'] = malware_families
        
        # Extract attack techniques
        techniques = self.extract_attack_techniques(raw_data)
        if techniques:
            doc['enrichment']['attack_techniques'] = techniques
    
    def extract_threat_actors(self, raw_data: Dict) -> List[str]:
        """Extract threat actor names from raw data"""
        actors = []
        
        # Common field names for threat actors
        actor_fields = ['threat_actor', 'actor', 'group', 'apt', 'campaign']
        
        for field in actor_fields:
            if field in raw_data and raw_data[field]:
                if isinstance(raw_data[field], str):
                    actors.append(raw_data[field])
                elif isinstance(raw_data[field], list):
                    actors.extend(raw_data[field])
        
        return list(set(actors))
    
    def extract_malware_families(self, raw_data: Dict) -> List[str]:
        """Extract malware family names from raw data"""
        families = []
        
        # Common field names for malware families
        family_fields = ['malware', 'family', 'ransomware', 'trojan', 'virus']
        
        for field in family_fields:
            if field in raw_data and raw_data[field]:
                if isinstance(raw_data[field], str):
                    families.append(raw_data[field])
                elif isinstance(raw_data[field], list):
                    families.extend(raw_data[field])
        
        return list(set(families))
    
    def extract_attack_techniques(self, raw_data: Dict) -> List[str]:
        """Extract attack techniques from raw data"""
        techniques = []
        
        # MITRE ATT&CK techniques
        if 'mitre_attack' in raw_data:
            techniques.extend(self.parse_mitre_attack(raw_data['mitre_attack']))
        
        # Common technique fields
        technique_fields = ['technique', 'tactic', 'procedure']
        
        for field in technique_fields:
            if field in raw_data and raw_data[field]:
                if isinstance(raw_data[field], str):
                    techniques.append(raw_data[field])
                elif isinstance(raw_data[field], list):
                    techniques.extend(raw_data[field])
        
        return list(set(techniques))
    
    def parse_mitre_attack(self, mitre_data: Any) -> List[str]:
        """Parse MITRE ATT&CK data"""
        techniques = []
        
        if isinstance(mitre_data, str):
            # Try to parse as JSON
            try:
                mitre_data = json.loads(mitre_data)
            except json.JSONDecodeError:
                # Treat as comma-separated list
                techniques.extend([t.strip() for t in mitre_data.split(',')])
                return techniques
        
        if isinstance(mitre_data, list):
            techniques.extend(mitre_data)
        elif isinstance(mitre_data, dict):
            if 'techniques' in mitre_data:
                techniques.extend(mitre_data['techniques'])
        
        return techniques
    
    def add_ioc_tags(self, doc: Dict, raw_data: Optional[Dict] = None):
        """
        Add appropriate tags based on IOC type and context
        """
        tags = set()
        
        # Add type-based tags
        ioc_type = doc['ioc_type']
        if ioc_type == 'ip':
            tags.update(['network', 'infrastructure'])
        elif ioc_type == 'domain':
            tags.update(['dns', 'network'])
        elif ioc_type == 'url':
            tags.update(['web', 'http'])
        elif ioc_type in ['sha256', 'sha1', 'md5']:
            tags.update(['file', 'hash'])
        elif ioc_type == 'cve':
            tags.update(['vulnerability', 'security'])
        
        # Add tags from source feed name
        source = doc['source_feed']
        if 'phish' in source.lower():
            tags.add('phishing')
        if 'malware' in source.lower() or 'bazaar' in source.lower():
            tags.add('malware')
        if 'ransom' in source.lower():
            tags.add('ransomware')
        if 'exploit' in source.lower() or 'cve' in source.lower():
            tags.add('exploit')
        if 'ssl' in source.lower() or 'tls' in source.lower():
            tags.add('ssl')
        if 'block' in source.lower() or 'drop' in source.lower():
            tags.add('blocklist')
        
        # Add tags from raw data
        if raw_data:
            if 'tags' in raw_data and raw_data['tags']:
                if isinstance(raw_data['tags'], list):
                    tags.update([tag.lower() for tag in raw_data['tags']])
                elif isinstance(raw_data['tags'], str):
                    tags.update([tag.strip().lower() for tag in raw_data['tags'].split(',')])
            
            # Infer tags from other fields
            for field in ['category', 'type', 'classification']:
                if field in raw_data and raw_data[field]:
                    tag_value = str(raw_data[field]).lower()
                    if ' ' in tag_value:
                        # Split multi-word tags
                        tags.update(tag_value.split())
                    else:
                        tags.add(tag_value)
        
        # Add final tags to document
        if tags:
            doc['tags'] = sorted(list(tags))
    
    def is_duplicate(self, content_hash: str, existing_hashes: set) -> bool:
        """
        Check if IOC is a duplicate based on content hash
        """
        return content_hash in existing_hashes
    
    def track_ioc_relationships(self, ioc_docs: List[Dict]) -> List[Dict]:
        """
        Track relationships between IOCs from the same source
        """
        if not ioc_docs:
            return ioc_docs
        
        # Group by source and timestamp
        source_groups = {}
        for doc in ioc_docs:
            source_key = f"{doc['source_feed']}_{doc['timestamp'][:13]}"  # Hour precision
            if source_key not in source_groups:
                source_groups[source_key] = []
            source_groups[source_key].append(doc)
        
        # Add relationship information
        for source_key, docs in source_groups.items():
            if len(docs) > 1:
                # Multiple IOCs from same source around same time
                related_hashes = [doc['content_hash'] for doc in docs]
                for doc in docs:
                    doc['relationships'] = {
                        'related_iocs': related_hashes,
                        'relationship_type': 'same_source',
                        'source_timestamp': source_key
                    }
        
        return ioc_docs

# Utility functions for time normalization
def normalize_timestamp(timestamp: Any) -> str:
    """
    Normalize various timestamp formats to UTC ISO format
    """
    if isinstance(timestamp, datetime):
        # Ensure datetime is timezone-aware and convert to UTC
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)
        return timestamp.isoformat()
    
    elif isinstance(timestamp, str):
        try:
            # Try parsing common timestamp formats
            for fmt in [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d',
                '%Y%m%d%H%M%S'
            ]:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.isoformat()
                except ValueError:
                    continue
        except:
            pass
    
    # Fallback: current UTC time
    return datetime.now(timezone.utc).isoformat()

def should_normalize_timestamp(timestamp: str) -> bool:
    """
    Check if timestamp needs normalization
    """
    # Basic check for ISO format with timezone
    iso_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'
    return not bool(re.match(iso_pattern, timestamp))
