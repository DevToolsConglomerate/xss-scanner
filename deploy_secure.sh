#!/bin/bash
# Secure Deployment Script for XSS Scanner
echo "🚀 Starting Secure Deployment of XSS Scanner"
echo "=" * 50

# Check if required environment variables are set
echo "🔍 Checking environment variables..."

REQUIRED_VARS=(
    "SECRET_KEY"
    "MONGODB_URI"
    "ALLOWED_ORIGINS"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ ERROR: $var environment variable is not set!"
        echo "Please set $var before deployment."
        exit 1
    fi
done

echo "✅ All required environment variables are set."

# Generate secure secret if not provided
if [ "$SECRET_KEY" = "your-secret-key-here" ]; then
    echo "⚠️  WARNING: Using default SECRET_KEY. Generating secure key..."
    export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "Generated SECRET_KEY: $SECRET_KEY"
fi

# Create virtual environment
echo "📦 Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements_fixed.txt

# Run security tests
echo "🧪 Running security tests..."
python test_scanner_fixed.py

if [ $? -ne 0 ]; then
    echo "❌ Security tests failed! Aborting deployment."
    exit 1
fi

echo "✅ Security tests passed!"

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p logs
mkdir -p backups

# Set up logging configuration
echo "📝 Setting up logging..."
cat > logging.conf << EOF
[loggers]
keys=root,xss-scanner

[handlers]
keys=consoleHandler,fileHandler

[formatters]
keys=simpleFormatter

[logger_root]
level=INFO
handlers=consoleHandler

[logger_xss-scanner]
level=INFO
handlers=consoleHandler,fileHandler
qualname=xss-scanner
propagate=0

[handler_consoleHandler]
class=StreamHandler
level=INFO
formatter=simpleFormatter
args=(sys.stdout,)

[handler_fileHandler]
class=FileHandler
level=INFO
formatter=simpleFormatter
args=('logs/xss_scanner.log',)

[formatter_simpleFormatter]
format=%(asctime)s - %(name)s - %(levelname)s - %(message)s
datefmt=%Y-%m-%d %H:%M:%S
EOF

# Create systemd service file (for Linux deployments)
echo "⚙️  Creating systemd service file..."
cat > xss-scanner.service << EOF
[Unit]
Description=XSS Scanner API
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/xss-scanner
Environment="PATH=/path/to/xss-scanner/venv/bin"
ExecStart=/path/to/xss-scanner/venv/bin/uvicorn main_fixed:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Create nginx configuration (for production)
echo "🌐 Creating nginx configuration..."
cat > nginx.conf << EOF
server {
    listen 80;
    server_name yourdomain.com;

    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/private.key;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Rate limiting
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
    }
}
EOF

# Create backup script
echo "💾 Creating backup script..."
cat > backup.sh << EOF
#!/bin/bash
# Backup script for XSS Scanner
BACKUP_DIR="backups"
DATE=\$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p \$BACKUP_DIR

# Backup database
if [ ! -z "\$MONGODB_URI" ]; then
    echo "Backing up database..."
    mongodump --uri="\$MONGODB_URI" --out="\$BACKUP_DIR/db_backup_\$DATE"
fi

# Backup configuration (without secrets)
tar -czf "\$BACKUP_DIR/config_backup_\$DATE.tar.gz" \
    --exclude=config_fixed.py \
    *.py *.txt *.md *.html

# Backup logs
tar -czf "\$BACKUP_DIR/logs_backup_\$DATE.tar.gz" logs/

echo "Backup completed: \$BACKUP_DIR/backup_\$DATE"
EOF

chmod +x backup.sh

# Create health check script
echo "🏥 Creating health check script..."
cat > health_check.py << EOF
#!/usr/bin/env python3
"""
Health check script for XSS Scanner
"""
import requests
import sys
import os

def check_api_health():
    """Check if the API is responding"""
    try:
        response = requests.get("http://localhost:8000/", timeout=10)
        if response.status_code == 200:
            print("✅ API is healthy")
            return True
        else:
            print(f"❌ API returned status code: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API health check failed: {e}")
        return False

def check_database_connection():
    """Check database connectivity"""
    try:
        from pymongo import MongoClient
        client = MongoClient(os.getenv("MONGODB_URI"))
        client.admin.command('ping')
        print("✅ Database connection successful")
        client.close()
        return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

if __name__ == "__main__":
    api_ok = check_api_health()
    db_ok = check_database_connection()

    if api_ok and db_ok:
        print("🎉 All systems operational")
        sys.exit(0)
    else:
        print("⚠️  Some systems have issues")
        sys.exit(1)
EOF

chmod +x health_check.py

# Create startup script
echo "🚀 Creating startup script..."
cat > start.sh << EOF
#!/bin/bash
# Startup script for XSS Scanner
echo "Starting XSS Scanner..."

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export PYTHONPATH=\$PWD

# Start the application
echo "Starting server..."
uvicorn main_fixed:app --host 0.0.0.0 --port 8000 --workers 4
EOF

chmod +x start.sh

# Create Docker configuration (optional)
echo "🐳 Creating Docker configuration..."
cat > Dockerfile << EOF
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements_fixed.txt .
RUN pip install --no-cache-dir -r requirements_fixed.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd --create-home --shell /bin/bash app \\
    && chown -R app:app /app
USER app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD python health_check.py || exit 1

# Start application
CMD ["uvicorn", "main_fixed:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

# Create docker-compose.yml
cat > docker-compose.yml << EOF
version: '3.8'

services:
  xss-scanner:
    build: .
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=\${SECRET_KEY}
      - MONGODB_URI=\${MONGODB_URI}
      - STRIPE_API_KEY=\${STRIPE_API_KEY}
      - STRIPE_WEBHOOK_SECRET=\${STRIPE_WEBHOOK_SECRET}
      - ALLOWED_ORIGINS=\${ALLOWED_ORIGINS}
    depends_on:
      - mongodb
      - redis
    restart: unless-stopped

  mongodb:
    image: mongo:6.0
    environment:
      - MONGO_INITDB_DATABASE=xss_scanner
    volumes:
      - mongodb_data:/data/db
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

volumes:
  mongodb_data:
EOF

echo "✅ Deployment configuration completed!"
echo ""
echo "📋 Next Steps:"
echo "1. Review the generated configuration files"
echo "2. Update nginx.conf with your domain name"
echo "3. Set up SSL certificates"
echo "4. Configure firewall rules"
echo "5. Test the deployment: ./start.sh"
echo "6. Run health check: python health_check.py"
echo ""
echo "🔒 Security Reminders:"
echo "- Keep your SECRET_KEY secure and don't commit it to version control"
echo "- Use HTTPS in production"
echo "- Monitor logs regularly"
echo "- Keep dependencies updated"
echo "- Run security tests regularly"
echo ""
echo "🎉 Deployment preparation complete!"
