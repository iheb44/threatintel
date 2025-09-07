from fastapi import FastAPI, HTTPException, Response, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import os, requests, csv, io, json, logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment configuration
ES_HOST = os.getenv("ELASTIC_HOST", "elasticsearch")
ES_PORT = os.getenv("ELASTIC_PORT", "9200")
ES_URL = f"http://{ES_HOST}:{ES_PORT}"
ES_INDEX = os.getenv("ES_INDEX", "posts")
API_KEY = os.getenv("API_KEY")  # Optional API key for authentication

app = FastAPI(
    title="Dark Web Intelligence API",
    description="API for searching and exporting dark web threat intelligence data",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if API_KEY and (not credentials or credentials.credentials != API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials

# Pydantic models
class SearchResponse(BaseModel):
    total: int
    hits: List[dict]
    took: int

class HealthResponse(BaseModel):
    status: str
    elasticsearch: str
    timestamp: str

# Helper functions
def elasticsearch_request(endpoint: str, body: dict = None, timeout: int = 10):
    """Make request to Elasticsearch with error handling"""
    try:
        url = f"{ES_URL}/{endpoint}"
        if body:
            response = requests.post(url, json=body, timeout=timeout)
        else:
            response = requests.get(url, timeout=timeout)
        
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Elasticsearch request failed: {e}")
        raise HTTPException(status_code=500, detail="Search service unavailable")

def build_search_query(
    q: str = "",
    threat_types: List[str] = None,
    date_from: str = None,
    date_to: str = None,
    size: int = 50
) -> dict:
    """Build Elasticsearch query with filters"""
    query = {"bool": {"must": []}}
    
    # Text search
    if q:
        query["bool"]["must"].append({
            "multi_match": {
                "query": q,
                "fields": ["title^2", "text", "url"],
                "fuzziness": "AUTO"
            }
        })
    else:
        query["bool"]["must"].append({"match_all": {}})
    
    # Threat type filters
    if threat_types:
        query["bool"]["must"].append({
            "terms": {"threat_type.keyword": threat_types}
        })
    
    # Date range filter
    if date_from or date_to:
        date_filter = {"range": {"timestamp": {}}}
        if date_from:
            date_filter["range"]["timestamp"]["gte"] = date_from
        if date_to:
            date_filter["range"]["timestamp"]["lte"] = date_to
        query["bool"]["must"].append(date_filter)
    
    return {
        "query": query,
        "size": min(size, 1000),  # Limit max size
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["title", "url", "text", "timestamp", "threat_type", "severity", "tags"]
    }

# API Endpoints
@app.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint"""
    try:
        es_response = elasticsearch_request("")
        es_status = "healthy" if es_response else "unhealthy"
    except:
        es_status = "unhealthy"
    
    return HealthResponse(
        status="healthy",
        elasticsearch=es_status,
        timestamp=datetime.utcnow().isoformat()
    )

@app.get("/search", response_model=SearchResponse)
def search_posts(
    q: str = Query("", description="Search query"),
    threat_types: Optional[List[str]] = Query(None, description="Filter by threat types"),
    date_from: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    size: int = Query(50, ge=1, le=1000, description="Number of results"),
    credentials: HTTPAuthorizationCredentials = Depends(verify_api_key)
):
    """Search dark web intelligence data"""
    
    query_body = build_search_query(q, threat_types, date_from, date_to, size)
    
    logger.info(f"Search query: {q}, filters: {threat_types}, size: {size}")
    
    result = elasticsearch_request(f"{ES_INDEX}/_search", query_body, timeout=30)
    
    return SearchResponse(
        total=result["hits"]["total"]["value"],
        hits=[hit["_source"] for hit in result["hits"]["hits"]],
        took=result["took"]
    )

@app.get("/export/csv")
def export_csv(
    q: str = Query("", description="Search query"),
    threat_types: Optional[List[str]] = Query(None, description="Filter by threat types"),
    date_from: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    size: int = Query(1000, ge=1, le=5000, description="Number of results"),
    credentials: HTTPAuthorizationCredentials = Depends(verify_api_key)
):
    """Export search results as CSV"""
    
    query_body = build_search_query(q, threat_types, date_from, date_to, size)
    
    logger.info(f"CSV export: {q}, size: {size}")
    
    result = elasticsearch_request(f"{ES_INDEX}/_search", query_body, timeout=60)
    hits = result.get("hits", {}).get("hits", [])
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # CSV headers
    writer.writerow([
        "title", "url", "text_preview", "timestamp", 
        "threat_type", "severity", "tags"
    ])
    
    for hit in hits:
        source = hit.get("_source", {})
        writer.writerow([
            source.get("title", ""),
            source.get("url", ""),
            (source.get("text", ""))[:500].replace("\n", " ").replace("\r", ""),
            source.get("timestamp", ""),
            source.get("threat_type", ""),
            source.get("severity", ""),
            ", ".join(source.get("tags", []))
        ])
    
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=intelligence_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )

@app.get("/export/json")
def export_json(
    q: str = Query("", description="Search query"),
    threat_types: Optional[List[str]] = Query(None, description="Filter by threat types"),
    date_from: Optional[str] = Query(None, description="Start date (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="End date (YYYY-MM-DD)"),
    size: int = Query(1000, ge=1, le=5000, description="Number of results"),
    credentials: HTTPAuthorizationCredentials = Depends(verify_api_key)
):
    """Export search results as JSON"""
    
    query_body = build_search_query(q, threat_types, date_from, date_to, size)
    
    logger.info(f"JSON export: {q}, size: {size}")
    
    result = elasticsearch_request(f"{ES_INDEX}/_search", query_body, timeout=60)
    
    export_data = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "query": q,
        "filters": {
            "threat_types": threat_types,
            "date_from": date_from,
            "date_to": date_to
        },
        "total_results": result["hits"]["total"]["value"],
        "returned_results": len(result["hits"]["hits"]),
        "data": [hit["_source"] for hit in result["hits"]["hits"]]
    }
    
    return Response(
        content=json.dumps(export_data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=intelligence_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
    )

@app.get("/stats")
def get_statistics(credentials: HTTPAuthorizationCredentials = Depends(verify_api_key)):
    """Get threat intelligence statistics"""
    
    # Total documents
    total_query = {"query": {"match_all": {}}}
    total_result = elasticsearch_request(f"{ES_INDEX}/_count", total_query)
    
    # Threat type aggregation
    agg_query = {
        "size": 0,
        "aggs": {
            "threat_types": {
                "terms": {
                    "field": "threat_type.keyword",
                    "size": 20
                }
            },
            "recent_posts": {
                "date_histogram": {
                    "field": "timestamp",
                    "calendar_interval": "1d",
                    "order": {"_key": "desc"}
                }
            }
        }
    }
    
    agg_result = elasticsearch_request(f"{ES_INDEX}/_search", agg_query)
    
    return {
        "total_documents": total_result["count"],
        "threat_types": [
            {"type": bucket["key"], "count": bucket["doc_count"]}
            for bucket in agg_result["aggregations"]["threat_types"]["buckets"]
        ],
        "daily_activity": [
            {"date": bucket["key_as_string"][:10], "count": bucket["doc_count"]}
            for bucket in agg_result["aggregations"]["recent_posts"]["buckets"][:30]
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
