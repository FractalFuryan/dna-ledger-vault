# 🚀 DNA Ledger Vault - Production Deployment Guide

## Table of Contents

1. [Quick Start](#quick-start)
2. [Docker Deployment](#docker-deployment)
3. [AWS ECS Deployment](#aws-ecs-deployment)
4. [Azure Container Instances](#azure-container-instances)
5. [Google Cloud Run](#google-cloud-run)
6. [Monitoring & Observability](#monitoring--observability)
7. [Security Hardening](#security-hardening)
8. [Backup & Recovery](#backup--recovery)

---

## Quick Start

### Prerequisites

- Docker 20.10+ and Docker Compose 1.29+
- Python 3.12+ (for local development)
- 2GB RAM minimum, 4GB recommended
- 10GB disk space for ledger storage

### Local Development Setup

```bash
# 1. Clone repository
git clone https://github.com/FractalFuryan/dna-ledger-vault.git
cd dna-ledger-vault

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialize state
python -m cli.main init --out ./state --owner data_steward

# 4. Start API servers
# Terminal 1: v1 API
python -m gunicorn -w 4 -b 0.0.0.0:8080 api.server:app

# Terminal 2: v2 Observability API
python -m uvicorn api.v2.observability:app --host 0.0.0.0 --port 8081 --reload

# 5. Open dashboards
open http://localhost:8080        # Dashboard v1
open http://localhost:8080/v2     # Dashboard v2 (Observability)
open http://localhost:8081/docs   # API v2 Swagger docs
```

---

## Docker Deployment

### Build Image

```bash
cd deployment
docker build -t dna-ledger-vault:latest -f Dockerfile ..
```

### Run with Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# With monitoring (Prometheus + Grafana)
docker-compose --profile monitoring up -d
```

### Services Exposed

| Service | Port | URL |
|---------|------|-----|
| API v1 (Flask) | 8080 | http://localhost:8080/api |
| API v2 (FastAPI) | 8081 | http://localhost:8081 |
| NGINX (Dashboards) | 80 | http://localhost |
| Prometheus | 9090 | http://localhost:9090 |
| Grafana | 3000 | http://localhost:3000 |

### Persistent Volumes

- `ledger_state`: Stores ledger.jsonl and state files
- `ledger_keys`: Stores Ed25519/X25519 keypairs
- `prometheus_data`: Metrics storage
- `grafana_data`: Grafana dashboards

**⚠️ CRITICAL**: Back up `ledger_state` and `ledger_keys` volumes regularly!

---

## AWS ECS Deployment

### Step 1: Create ECR Repository

```bash
aws ecr create-repository --repository-name dna-ledger-vault --region us-east-1

# Get login token
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com

# Tag and push image
docker tag dna-ledger-vault:latest <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/dna-ledger-vault:latest
docker push <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/dna-ledger-vault:latest
```

### Step 2: Create EFS File System

```bash
# Create EFS for persistent storage
aws efs create-file-system \
  --creation-token dna-ledger-state \
  --region us-east-1 \
  --tags Key=Name,Value=dna-ledger-vault-state

# Note the FileSystemId from output
```

### Step 3: Update Task Definition

Edit `aws-ecs-task-definition.json`:
- Replace `<ACCOUNT_ID>` with your AWS account ID
- Replace `<REGION>` with your AWS region (e.g., `us-east-1`)
- Replace `<EFS_FILE_SYSTEM_ID>` with EFS ID from Step 2

### Step 4: Register Task Definition

```bash
aws ecs register-task-definition --cli-input-json file://aws-ecs-task-definition.json
```

### Step 5: Create ECS Service

```bash
aws ecs create-service \
  --cluster default \
  --service-name dna-ledger-vault \
  --task-definition dna-ledger-vault:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxxxx],securityGroups=[sg-xxxxx],assignPublicIp=ENABLED}"
```

### Step 6: Create Application Load Balancer (Optional)

```bash
# Create ALB
aws elbv2 create-load-balancer \
  --name dna-ledger-vault-alb \
  --subnets subnet-xxxxx subnet-yyyyy \
  --security-groups sg-xxxxx

# Create target groups for ports 8080 and 8081
# Configure health checks
# Register ECS service with ALB
```

---

## Azure Container Instances

### Step 1: Create Container Registry

```bash
# Create resource group
az group create --name dna-ledger-vault-rg --location eastus

# Create container registry
az acr create --resource-group dna-ledger-vault-rg --name dnaledgervault --sku Basic

# Login to ACR
az acr login --name dnaledgervault
```

### Step 2: Push Image to ACR

```bash
docker tag dna-ledger-vault:latest dnaledgervault.azurecr.io/dna-ledger-vault:latest
docker push dnaledgervault.azurecr.io/dna-ledger-vault:latest
```

### Step 3: Create Azure File Share

```bash
# Create storage account
az storage account create \
  --resource-group dna-ledger-vault-rg \
  --name dnaledgerstorage \
  --location eastus \
  --sku Standard_LRS

# Create file share
az storage share create \
  --name dna-ledger-state \
  --account-name dnaledgerstorage
```

### Step 4: Update and Deploy

Edit `azure-container-instances.yaml`:
- Replace `<ACR_NAME>` with your ACR name
- Replace `<STORAGE_ACCOUNT_NAME>` and `<STORAGE_ACCOUNT_KEY>`

```bash
az container create --resource-group dna-ledger-vault-rg --file azure-container-instances.yaml
```

### Step 5: Get Public IP

```bash
az container show --resource-group dna-ledger-vault-rg --name dna-ledger-vault --query ipAddress.fqdn
```

---

## Google Cloud Run

### Step 1: Build and Push to GCR

```bash
# Configure Docker for GCR
gcloud auth configure-docker

# Build and tag
docker tag dna-ledger-vault:latest gcr.io/<PROJECT_ID>/dna-ledger-vault:latest

# Push to GCR
docker push gcr.io/<PROJECT_ID>/dna-ledger-vault:latest
```

### Step 2: Create Persistent Disk

```bash
gcloud compute disks create dna-ledger-state \
  --size 10GB \
  --region us-central1
```

### Step 3: Deploy to Cloud Run

Edit `gcp-cloud-run.yaml`:
- Replace `<PROJECT_ID>` with your GCP project ID

```bash
kubectl apply -f gcp-cloud-run.yaml
```

### Step 4: Get Service URLs

```bash
gcloud run services list --platform managed
```

---

## Monitoring & Observability

### Built-in Dashboards

- **Dashboard v1**: Basic ledger viewer and stats
  - URL: `http://<HOST>/`
  - Features: Dataset browser, consent grants, audit trail
  
- **Dashboard v2**: Advanced observability
  - URL: `http://<HOST>/v2`
  - Features: Compliance scoring, anomaly detection, timeline viewer

### API Endpoints

**v1 API (Flask - Port 8080)**
- `GET /api/health` - Health check
- `GET /api/ledger/stats` - Ledger statistics
- `GET /api/datasets` - List all datasets
- `GET /api/grants` - List consent grants
- `GET /api/audit-trail` - Complete audit trail
- `POST /api/passports/issue` - Issue GA4GH Passport
- `POST /api/verify` - Verify passport

**v2 Observability API (FastAPI - Port 8081)**
- `GET /compliance-health` - Compliance health score (0-100)
- `GET /regulator-report` - GDPR/CPRA audit report
- `GET /timeline/{dataset_id}` - Dataset lifecycle timeline
- `GET /anomaly-detection` - Security anomaly detection
- `GET /docs` - Interactive Swagger documentation

### Prometheus Metrics (Optional)

If running with `--profile monitoring`:

```bash
# Access Prometheus
open http://localhost:9090

# Access Grafana
open http://localhost:3000
# Default credentials: admin/admin
```

**Custom Metrics** (add to application):
- `ledger_events_total` - Total events by type
- `consent_grants_active` - Active consent grants gauge
- `api_requests_total` - API request counter
- `erasure_operations_total` - Erasure requests processed

---

## Security Hardening

### TLS/HTTPS Configuration

**For Production**: Enable TLS on all endpoints.

#### NGINX TLS Termination

Add to `nginx.conf`:

```nginx
server {
    listen 443 ssl http2;
    server_name dna-ledger-vault.example.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # ... rest of configuration
}
```

#### Let's Encrypt (Certbot)

```bash
# Install certbot
apt-get install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d dna-ledger-vault.example.com

# Auto-renewal (cron job)
0 0 * * * certbot renew --quiet
```

### Firewall Rules

**Docker Compose**:
```bash
# Only expose NGINX port 443
# Block direct access to 8080, 8081
```

**AWS Security Group**:
```bash
# Inbound: Allow 443 (HTTPS) from 0.0.0.0/0
# Inbound: Allow 8080, 8081 from ALB security group only
# Outbound: Allow all
```

### Authentication

**API Key Authentication** (recommended for production):

1. Add to `api/server.py`:
```python
from functools import wraps
from flask import request, jsonify

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key != os.environ.get('DNA_LEDGER_API_KEY'):
            return jsonify({"error": "Invalid API key"}), 401
        return f(*args, **kwargs)
    return decorated_function
```

2. Set environment variable:
```bash
export DNA_LEDGER_API_KEY="<STRONG_RANDOM_KEY>"
```

**OAuth2 / OIDC** (for enterprise):
- Integrate with Auth0, Okta, or Keycloak
- Add JWT verification to API endpoints
- Implement role-based access control (RBAC)

### Secrets Management

**AWS Secrets Manager**:
```bash
aws secretsmanager create-secret \
  --name dna-ledger-vault/api-key \
  --secret-string "your-strong-api-key"
```

**Azure Key Vault**:
```bash
az keyvault secret set \
  --vault-name dna-ledger-kv \
  --name api-key \
  --value "your-strong-api-key"
```

**GCP Secret Manager**:
```bash
echo -n "your-strong-api-key" | gcloud secrets create dna-ledger-api-key --data-file=-
```

---

## Backup & Recovery

### Automated Backups

**Docker Volumes**:

```bash
#!/bin/bash
# backup-ledger.sh

BACKUP_DIR="/backups/dna-ledger-vault"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Backup ledger state
docker run --rm \
  -v ledger_state:/data \
  -v $BACKUP_DIR:/backup \
  alpine tar czf /backup/ledger_state_$TIMESTAMP.tar.gz /data

# Backup keys (CRITICAL)
docker run --rm \
  -v ledger_keys:/data \
  -v $BACKUP_DIR:/backup \
  alpine tar czf /backup/ledger_keys_$TIMESTAMP.tar.gz /data

# Encrypt backups
gpg --symmetric --cipher-algo AES256 $BACKUP_DIR/ledger_keys_$TIMESTAMP.tar.gz

# Upload to S3 (example)
aws s3 cp $BACKUP_DIR/ledger_state_$TIMESTAMP.tar.gz s3://dna-ledger-backups/
aws s3 cp $BACKUP_DIR/ledger_keys_$TIMESTAMP.tar.gz.gpg s3://dna-ledger-backups/

# Retain last 30 days
find $BACKUP_DIR -name "*.tar.gz*" -mtime +30 -delete
```

**Schedule with cron**:
```bash
0 2 * * * /usr/local/bin/backup-ledger.sh
```

### AWS EFS Backups

```bash
# Enable automatic backups
aws efs put-backup-policy \
  --file-system-id fs-xxxxx \
  --backup-policy Status=ENABLED
```

### Azure Files Backups

```bash
# Create backup vault
az backup vault create \
  --resource-group dna-ledger-vault-rg \
  --name dna-ledger-backup-vault \
  --location eastus

# Enable backup for file share
az backup protection enable-for-azurefileshare \
  --vault-name dna-ledger-backup-vault \
  --resource-group dna-ledger-vault-rg \
  --storage-account dnaledgerstorage \
  --azure-file-share dna-ledger-state \
  --policy-name DefaultPolicy
```

### Disaster Recovery

**Recovery Time Objective (RTO)**: < 1 hour  
**Recovery Point Objective (RPO)**: < 24 hours

**Recovery Steps**:

1. **Restore State**:
```bash
# Extract backup
tar xzf ledger_state_TIMESTAMP.tar.gz -C /restore_path

# Copy to Docker volume
docker run --rm -v ledger_state:/data -v /restore_path:/backup alpine sh -c "cp -r /backup/* /data/"
```

2. **Restore Keys** (CRITICAL):
```bash
# Decrypt keys backup
gpg ledger_keys_TIMESTAMP.tar.gz.gpg

# Extract
tar xzf ledger_keys_TIMESTAMP.tar.gz -C /restore_path

# Copy to volume
docker run --rm -v ledger_keys:/data -v /restore_path:/backup alpine sh -c "cp -r /backup/* /data/"
```

3. **Verify Integrity**:
```bash
python -m cli.main verify --out /restore_path
```

4. **Restart Services**:
```bash
docker-compose up -d
```

---

## Troubleshooting

### Common Issues

**1. Ledger not found (404)**
- Check that `/app/state/ledger.jsonl` exists
- Verify volume mounts: `docker inspect <container>`
- Initialize ledger: `docker exec <container> python -m cli.main init --out /app/state --owner admin`

**2. Permission denied errors**
- Container runs as non-root user `dna_ledger`
- Ensure volumes have correct ownership: `chown -R 1000:1000 /path/to/volume`

**3. API not responding**
- Check container logs: `docker logs <container>`
- Verify ports are exposed: `docker ps`
- Test health endpoint: `curl http://localhost:8080/api/health`

**4. Dashboard showing old data**
- Clear browser cache
- Check dashboard refresh interval (default: 30s)
- Verify API endpoints are reachable from browser

### Health Checks

```bash
# API v1 health
curl http://localhost:8080/api/health

# API v2 health
curl http://localhost:8081/

# Ledger integrity check
docker exec <container> python -m cli.main verify --out /app/state
```

### Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api-v1

# Last 100 lines
docker-compose logs --tail=100 api-v2
```

---

## Performance Tuning

### Gunicorn Workers

Adjust worker count based on CPU cores:

```bash
# Formula: (2 x CPU cores) + 1
gunicorn -w 9 -b 0.0.0.0:8080 api.server:app  # For 4 CPU system
```

### Uvicorn Workers

```bash
uvicorn api.v2.observability:app --workers 4 --host 0.0.0.0 --port 8081
```

### Database Optimization

For large ledgers (>10,000 events):
- Consider migrating to PostgreSQL for `ledger.jsonl`
- Implement event pagination in API endpoints
- Add caching layer (Redis) for frequently accessed data

---

## Support & Maintenance

### Update Procedures

```bash
# Pull latest image
docker pull <registry>/dna-ledger-vault:latest

# Rolling update (zero downtime)
docker-compose up -d --no-deps --build api-v1
docker-compose up -d --no-deps --build api-v2

# Verify health
curl http://localhost:8080/api/health
curl http://localhost:8081/
```

### Version Compatibility

| Component | Version |
|-----------|---------|
| Python | 3.12+ |
| Docker | 20.10+ |
| Docker Compose | 1.29+ |
| NGINX | 1.21+ |
| Gunicorn | 21.0+ |
| Uvicorn | 0.24+ |

---

## Security Contacts

**Report Security Vulnerabilities**:
- Email: security@example.com
- Responsible Disclosure: Follow SECURITY.md guidelines

**Compliance Inquiries**:
- GDPR: dpo@example.com
- CPRA: privacy@example.com

---

**Last Updated**: 2024-01-15  
**Version**: 2.0.0 (Phase 2 - Enterprise Activation)
