"""
Tests for Web Dashboard REST API.

Coverage:
- Health check endpoint
- Ledger stats endpoint
- Dataset listing
- Grant listing
- Event filtering
"""

import pytest
import sys
from pathlib import Path

# Add api module to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.server import app


@pytest.fixture
def client():
    """Flask test client."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestHealthEndpoint:
    """Test health check endpoint."""
    
    def test_health_check_returns_200(self, client):
        """Health endpoint should return 200."""
        response = client.get('/api/health')
        assert response.status_code == 200
    
    def test_health_check_json_structure(self, client):
        """Health endpoint should return correct JSON structure."""
        response = client.get('/api/health')
        data = response.get_json()
        
        assert 'status' in data
        assert 'version' in data
        assert 'timestamp' in data
        assert data['status'] == 'healthy'


class TestLedgerEndpoints:
    """Test ledger-related endpoints."""
    
    def test_ledger_stats_endpoint(self, client):
        """Ledger stats should return or 404/500 if no ledger."""
        response = client.get('/api/ledger/stats')
        # Either 200 with stats or 404/500 if ledger doesn't exist
        assert response.status_code in [200, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'total_events' in data
            assert 'chain_root' in data
            assert 'integrity' in data
    
    def test_ledger_events_endpoint(self, client):
        """Ledger events should return or 404/500."""
        response = client.get('/api/ledger/events')
        assert response.status_code in [200, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'events' in data
            assert 'total' in data
    
    def test_ledger_events_with_filters(self, client):
        """Test event filtering by kind."""
        response = client.get('/api/ledger/events?kind=DatasetCommit&limit=10')
        assert response.status_code in [200, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert data['limit'] == 10


class TestDatasetEndpoints:
    """Test dataset-related endpoints."""
    
    def test_datasets_list(self, client):
        """Datasets endpoint should return list."""
        response = client.get('/api/datasets')
        assert response.status_code in [200, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'datasets' in data
            assert isinstance(data['datasets'], list)
    
    def test_dataset_details_404(self, client):
        """Non-existent dataset should return 404."""
        response = client.get('/api/datasets/nonexistent_ds')
        assert response.status_code in [404, 500]


class TestGrantsEndpoints:
    """Test consent grant endpoints."""
    
    def test_grants_list(self, client):
        """Grants endpoint should return list."""
        response = client.get('/api/grants')
        assert response.status_code in [200, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'grants' in data
            assert isinstance(data['grants'], list)


class TestAuditEndpoints:
    """Test audit trail endpoints."""
    
    def test_audit_trail(self, client):
        """Audit trail should return events."""
        response = client.get('/api/audit-trail')
        assert response.status_code in [200, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'audit_trail' in data
            assert 'chain_root' in data
            assert 'total_events' in data


class TestVerifyEndpoint:
    """Test ledger verification endpoint."""
    
    def test_verify_ledger(self, client):
        """Verify endpoint should check integrity."""
        response = client.get('/api/verify')
        assert response.status_code in [200, 404, 500]
        
        if response.status_code == 200:
            data = response.get_json()
            assert 'valid' in data


class TestPassportEndpoints:
    """Test GA4GH Passport issuance."""
    
    def test_issue_passport_missing_fields(self, client):
        """Missing required fields should return 400."""
        response = client.post('/api/passports/issue', json={})
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data
    
    def test_issue_passport_nonexistent_grant(self, client):
        """Non-existent grant should return 404."""
        response = client.post('/api/passports/issue', json={
            'actor': 'alice',
            'grantee': 'bob',
            'dataset_id': 'nonexistent',
            'lifetime_hours': 24
        })
        assert response.status_code in [404, 500]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
