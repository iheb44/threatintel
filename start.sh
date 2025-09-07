#!/bin/bash

echo "🕸️  Dark Web Intelligence Platform - Quick Start"
echo "=================================================="

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p crawler/state
mkdir -p crawler/logs
mkdir -p api/config

# Set permissions
chmod +x start.sh

echo "🚀 Starting services..."
echo "This may take a few minutes on first run..."

# Start the stack
docker-compose up -d

echo "⏳ Waiting for services to be ready..."
sleep 30

# Check if Elasticsearch is ready
echo "🔍 Checking Elasticsearch..."
until curl -s http://localhost:9200/_cluster/health | grep -q '"status":"green\|yellow"'; do
    echo "Waiting for Elasticsearch to be ready..."
    sleep 10
done

# Apply Elasticsearch template
echo "📋 Setting up Elasticsearch template..."
curl -X PUT "localhost:9200/_index_template/posts_template" \
    -H "Content-Type: application/json" \
    -d @posts_template.json

echo ""
echo "✅ Dark Web Intelligence Platform is now running!"
echo ""
echo "🌐 **Access Points:**"
echo "   • Kibana Dashboard:  http://localhost:5601"
echo "   • Grafana:          http://localhost:3000 (admin/changeme_grafana)"
echo "   • API Docs:         http://localhost:8000/docs"
echo "   • Elasticsearch:    http://localhost:9200"
echo ""
echo "🔧 **Service Status:**"
docker-compose ps

echo ""
echo "📊 **Quick Commands:**"
echo "   • View logs:        docker-compose logs -f crawler"
echo "   • Stop services:    docker-compose down"
echo "   • Restart crawler:  docker-compose restart crawler"
echo ""
echo "🔍 **Search for threats:**"
echo "   curl 'http://localhost:8000/search?q=ransomware&size=10'"
echo ""
echo "📥 **Export data:**"
echo "   curl 'http://localhost:8000/export/csv?q=malware' > threats.csv"
echo ""

# Show recent logs
echo "📝 **Recent Crawler Activity:**"
docker-compose logs --tail=10 crawler

echo ""
echo "🎉 Setup complete! Happy threat hunting! 🕵️‍♂️"
