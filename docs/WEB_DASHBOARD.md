# Web Dashboard MVP

## Overview

DNA Ledger Vault Web Dashboard provides a **browser-based interface** for:

- ✅ **Ledger Visualization**: Real-time view of all events
- ✅ **Dataset Management**: Browse genomic datasets and their status
- ✅ **Consent Grant Workflow**: View active/revoked/expired grants
- ✅ **Audit Trail Export**: Complete compliance reporting
- ✅ **GA4GH Passport Issuance**: Generate bearer tokens via REST API

**Tech Stack:**
- **Backend**: Flask REST API (Python)
- **Frontend**: Vanilla HTML/CSS/JavaScript (no build step)
- **Deployment**: Gunicorn + Nginx (production-ready)

---

## ⚠️ CRITICAL INVARIANT: Dashboard Non-Authority

**The dashboard is strictly observational.**

It must never:
- ❌ Gate access to datasets or operations
- ❌ Alter consent policy or governance rules
- ❌ Trigger enforcement actions
- ❌ Initiate cryptographic operations (signing, encryption, key rotation)

All mutations flow through the CLI or direct API calls with explicit actor identity.
**The dashboard displays state; it does not create or modify it.**

This invariant prevents a future "helpful" engineer from turning charts into controls.

---

## Quick Start

### Development Mode

```bash
# Install dependencies
pip install flask flask-cors gunicorn

# Start API server
export DNA_LEDGER_STATE=./state
flask --app api.server run --port 8080

# Open browser
open http://localhost:8080
```

### Production Deployment

```bash
# Run with Gunicorn (4 workers)
gunicorn -w 4 -b 0.0.0.0:8080 api.server:app

# Or with Nginx reverse proxy
gunicorn -w 4 -b 127.0.0.1:8080 api.server:app
```

---

## Architecture

### REST API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Health check (uptime, version) |
| `/api/ledger/stats` | GET | Ledger statistics |
| `/api/ledger/events` | GET | All events (with filtering) |
| `/api/datasets` | GET | List all datasets |
| `/api/datasets/<id>` | GET | Dataset details |
| `/api/grants` | GET | All consent grants |
| `/api/audit-trail` | GET | Complete audit trail |
| `/api/passports/issue` | POST | Issue GA4GH Passport JWT |
| `/api/verify` | GET | Verify ledger integrity |

### Frontend Components

1. **Stats Dashboard**
   - Total events counter
   - Dataset count
   - Active grants
   - Chain integrity status

2. **Dataset Browser**
   - Dataset ID, owner, merkle root
   - Active/total grants
   - Compute attestation count
   - Erasure status

3. **Consent Grant Manager**
   - Grant ID, dataset, grantee
   - Purpose, scope restrictions
   - Active/revoked/expired status
   - Expiration timestamps

4. **Ledger Event Viewer**
   - Recent 20 events
   - Event type icons
   - Timestamp sorting
   - Event details

5. **Audit Trail**
   - Complete event history
   - Chain root verification
   - Chronological ordering
   - Export-ready format

---

## API Reference

### GET /api/health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.3.0-pq-preview",
  "timestamp": "2026-01-18T14:30:00Z"
}
```

### GET /api/ledger/stats

Get ledger statistics.

**Response:**
```json
{
  "total_events": 42,
  "chain_root": "8f7e6d5c4b3a2918...",
  "event_types": {
    "DatasetCommit": 10,
    "ConsentGrant": 15,
    "ComputeAttestation": 12,
    "ConsentRevocation": 3,
    "SecureErasureEvent": 2
  },
  "integrity": "verified",
  "last_updated": "2026-01-18T14:30:00Z"
}
```

### GET /api/ledger/events

Get ledger events with optional filtering.

**Query Parameters:**
- `kind` - Filter by event type (e.g., `DatasetCommit`)
- `dataset_id` - Filter by dataset ID
- `identity` - Filter by identity
- `limit` - Max events to return (default: 100)
- `offset` - Pagination offset (default: 0)

**Example:**
```bash
curl "http://localhost:8080/api/ledger/events?kind=ConsentGrant&limit=10"
```

**Response:**
```json
{
  "events": [
    {
      "kind": "ConsentGrant",
      "grant_id": "cg_abc123",
      "dataset_id": "ds_genomic_001",
      "grantee": "researcher_alice",
      "allowed_purpose": "research",
      "timestamp_utc": "2026-01-15T10:00:00Z",
      "expires_utc": "2026-04-15T10:00:00Z"
    }
  ],
  "total": 15,
  "limit": 10,
  "offset": 0
}
```

### GET /api/datasets

Get all datasets with current status.

**Response:**
```json
{
  "datasets": [
    {
      "dataset_id": "ds_genomic_001",
      "owner": "alice",
      "merkle_root": "a1b2c3d4...",
      "commit_timestamp": "2026-01-10T12:00:00Z",
      "active_grants": 3,
      "total_grants": 5,
      "compute_count": 8,
      "erased": false
    }
  ]
}
```

### GET /api/datasets/<dataset_id>

Get detailed information about a specific dataset.

**Response:**
```json
{
  "dataset_id": "ds_genomic_001",
  "owner": "alice",
  "merkle_root": "a1b2c3d4...",
  "commit_timestamp": "2026-01-10T12:00:00Z",
  "grants": [
    {
      "grant_id": "cg_abc123",
      "grantee": "researcher_alice",
      "allowed_purpose": "research",
      "revoked": false
    }
  ],
  "attestations": [
    {
      "researcher": "researcher_alice",
      "algo": "ancestry_model",
      "result_hash": "sha256:ef78..."
    }
  ],
  "erasures": [],
  "status": "active"
}
```

### GET /api/grants

Get all consent grants with revocation/expiration status.

**Response:**
```json
{
  "grants": [
    {
      "grant_id": "cg_abc123",
      "dataset_id": "ds_genomic_001",
      "grantee": "researcher_alice",
      "allowed_purpose": "research",
      "scope_restriction": null,
      "timestamp_utc": "2026-01-15T10:00:00Z",
      "expires_utc": "2026-04-15T10:00:00Z",
      "revoked": false,
      "expired": false
    }
  ]
}
```

### GET /api/audit-trail

Get complete audit trail for compliance.

**Response:**
```json
{
  "audit_trail": [
    {
      "index": 0,
      "kind": "DatasetCommit",
      "timestamp": "2026-01-10T12:00:00Z",
      "identity": "alice",
      "dataset_id": "ds_genomic_001",
      "details": { ... }
    }
  ],
  "chain_root": "8f7e6d5c4b3a2918...",
  "total_events": 42
}
```

### POST /api/passports/issue

Issue a GA4GH Passport JWT for a grantee.

**Request Body:**
```json
{
  "actor": "alice",
  "grantee": "researcher_bob",
  "dataset_id": "ds_genomic_001",
  "lifetime_hours": 24
}
```

**Response:**
```json
{
  "passport": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "expires_in_hours": 24,
  "grantee": "researcher_bob",
  "dataset_id": "ds_genomic_001"
}
```

**Error Response:**
```json
{
  "error": "No active grant found"
}
```

### GET /api/verify

Verify ledger integrity.

**Response:**
```json
{
  "valid": true,
  "chain_root": "8f7e6d5c4b3a2918...",
  "total_events": 42
}
```

---

## Frontend Features

### Real-Time Updates

Dashboard auto-refreshes every 30 seconds:

```javascript
// Auto-refresh
init();
setInterval(init, 30000);
```

### Tab Navigation

Switch between datasets, grants, events, and audit trail:

```javascript
function switchTab(tabName) {
    // Remove active class from all tabs/content
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    // Activate selected tab
    event.target.classList.add('active');
    document.getElementById(tabName).classList.add('active');
}
```

### Status Badges

Visual indicators for dataset/grant status:

- 🟢 **Active**: Green badge
- 🔴 **Erased**: Red badge with opacity
- 🟡 **Revoked**: Yellow/orange badge
- 🔵 **Info**: Blue badge for event types

---

## Deployment

### Docker Deployment

```dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "api.server:app"]
```

**Build & Run:**
```bash
docker build -t dna-ledger-vault-dashboard .
docker run -p 8080:8080 -v ./state:/app/state dna-ledger-vault-dashboard
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name dashboard.dna-ledger-vault.example;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    # WebSocket support (future)
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### HTTPS with Let's Encrypt

```bash
# Install certbot
apt-get install certbot python3-certbot-nginx

# Obtain certificate
certbot --nginx -d dashboard.dna-ledger-vault.example

# Auto-renewal (cron)
0 3 * * * certbot renew --quiet
```

---

## Security Considerations

### Authentication (Future)

Current MVP has **no authentication** (read-only ledger data).

**Planned:**
- JWT-based authentication
- Role-based access control (RBAC)
- OAuth2/OIDC integration
- Session management

### CORS Configuration

Configurable CORS for development:

```python
from flask_cors import CORS

# Development: Allow all origins
CORS(app)

# Production: Restrict origins
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://dashboard.dna-ledger-vault.example"]
    }
})
```

### Rate Limiting (Future)

```bash
pip install flask-limiter

# Apply rate limits
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@limiter.limit("10 per minute")
@app.route("/api/passports/issue", methods=["POST"])
def issue_passport():
    # ... implementation
```

---

## Monitoring & Logging

### Application Logging

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

@app.route("/api/ledger/events")
def get_ledger_events():
    logger.info(f"Fetching events: kind={request.args.get('kind')}")
    # ... implementation
```

### Metrics (Prometheus)

```bash
pip install prometheus-flask-exporter

from prometheus_flask_exporter import PrometheusMetrics

metrics = PrometheusMetrics(app)

# Access metrics at /metrics
# - http_request_duration_seconds
# - http_request_total
```

---

## Testing

### API Unit Tests

```python
# tests/test_dashboard_api.py

import pytest
from api.server import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health_check(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'

def test_ledger_stats(client):
    response = client.get('/api/ledger/stats')
    assert response.status_code == 200
    data = response.get_json()
    assert 'total_events' in data
    assert 'chain_root' in data

def test_datasets_endpoint(client):
    response = client.get('/api/datasets')
    assert response.status_code == 200
    data = response.get_json()
    assert 'datasets' in data
```

### Frontend Integration Tests

```javascript
// tests/dashboard.test.js

describe('Dashboard', () => {
    it('should load stats on init', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            json: async () => ({ total_events: 42 })
        });
        
        await fetchStats();
        
        expect(document.getElementById('totalEvents').textContent).toBe('42');
    });
});
```

---

## Performance

### Caching Strategy

```python
from functools import lru_cache
import time

# Cache ledger stats for 10 seconds
@lru_cache(maxsize=1)
def cached_ledger_stats(cache_key):
    ledger = HashChainedLedger.load_from_jsonl(LEDGER_PATH)
    return compute_stats(ledger)

@app.route("/api/ledger/stats")
def ledger_stats():
    cache_key = int(time.time() / 10)  # 10-second cache
    stats = cached_ledger_stats(cache_key)
    return jsonify(stats)
```

### Database Backend (Future)

For high-performance deployments, index ledger in PostgreSQL:

```sql
CREATE TABLE ledger_events (
    id SERIAL PRIMARY KEY,
    event_index INTEGER NOT NULL,
    kind VARCHAR(50) NOT NULL,
    dataset_id VARCHAR(100),
    identity VARCHAR(100),
    timestamp TIMESTAMP NOT NULL,
    payload JSONB NOT NULL
);

CREATE INDEX idx_dataset_id ON ledger_events(dataset_id);
CREATE INDEX idx_identity ON ledger_events(identity);
CREATE INDEX idx_timestamp ON ledger_events(timestamp);
```

---

## Roadmap

### v1.3 (Current MVP)

- ✅ REST API with 9 endpoints
- ✅ HTML/CSS/JS frontend (no build step)
- ✅ Real-time stats dashboard
- ✅ Dataset/grant/event browsing
- ✅ Audit trail export

### v1.4 (Q2 2026)

- ⏳ WebSocket support for live updates
- ⏳ JWT authentication
- ⏳ User management (create identities via UI)
- ⏳ GA4GH Passport issuance UI
- ⏳ PDF export for compliance reports

### v1.5 (Q3 2026)

- ⏳ React/Vue rewrite for better UX
- ⏳ GraphQL API option
- ⏳ Advanced filtering/search
- ⏳ Ledger event visualizations (charts)
- ⏳ Merkle proof viewer

### v2.0 (Q4 2026)

- ⏳ Multi-tenant support
- ⏳ Role-based access control (RBAC)
- ⏳ Audit log export to S3/GCS
- ⏳ Integration with KMS
- ⏳ Post-quantum crypto indicators

---

## Troubleshooting

### Issue: "Ledger not found"

```bash
# Ensure state directory exists
export DNA_LEDGER_STATE=./state

# Initialize if empty
dna-ledger init --out ./state --owner alice
dna-ledger commit --out ./state --actor alice --dataset-id test --file data.vcf
```

### Issue: CORS errors in browser

```javascript
// Check CORS is enabled
from flask_cors import CORS
CORS(app)

// Or allow specific origin
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
```

### Issue: "Address already in use"

```bash
# Find process using port 8080
lsof -i :8080

# Kill process
kill -9 <PID>

# Or use different port
flask --app api.server run --port 8081
```

---

## References

- **Flask Documentation**: https://flask.palletsprojects.com/
- **Gunicorn**: https://gunicorn.org/
- **Flask-CORS**: https://flask-cors.readthedocs.io/
- **Prometheus Flask Exporter**: https://github.com/rycus86/prometheus_flask_exporter

---

## Support

For dashboard questions:

- **Technical Issues**: See [README.md](../README.md)
- **API Documentation**: `/api/health` endpoint
- **Security**: [SECURITY.md](SECURITY.md)

**Live Demo**: Coming soon at `https://dashboard.dna-ledger-vault.example`
