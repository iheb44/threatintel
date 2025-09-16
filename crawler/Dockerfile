FROM python:3.11-slim

# Install system dependencies efficiently
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    wget \
    gnupg \
    dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Only install Playwright if USE_PLAYWRIGHT is enabled (reduce image size)
# Remove the always-install approach for better efficiency

WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python packages with better caching and security
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Remove spaCy model download since ENABLE_PII_REDACTION=false
# Only install if actually needed

# Copy application code
COPY . .

# Create directories with proper permissions
RUN mkdir -p /app/logs /app/state /app/config \
    && chmod 755 /app/logs /app/state /app/config

# Create non-root user for security
RUN useradd -m -u 1000 crawler \
    && chown -R crawler:crawler /app
USER crawler

# Health check endpoint (matches your API pattern)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Use main.py as entry point
CMD ["python", "main.py"]
