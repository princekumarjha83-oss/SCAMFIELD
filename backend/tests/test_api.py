"""
ScamShield AI - Comprehensive Backend Test Suite
Tests API routing, input validation, static inspection invariants, heuristics, and database CRUD.
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import Base, engine

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    # Initialize tables
    Base.metadata.create_all(bind=engine)
    yield

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "version" in data
    assert data["db_connected"] is True

def test_model_info():
    response = client.get("/api/v1/model-info")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "confusion_matrix" in data["metrics"]
    assert "accuracy" in data["metrics"]
    assert "dataset_license" in data
    assert "CC-BY" in data["dataset_license"]

def test_scan_benign_url():
    url = "https://en.wikipedia.org/wiki/Computer_security"
    response = client.post("/api/v1/scan", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == url
    assert data["risk_score"] < 40
    assert data["risk_level"] in ("SAFE", "SUSPICIOUS")
    assert "disclaimer" in data
    assert "offline static inspection" in data["disclaimer"]

def test_scan_brand_phishing_url():
    url = "https://paypal.com.account-verification-service.xyz/webapps/login.php"
    response = client.post("/api/v1/scan", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 65
    assert data["risk_level"] == "HIGH"
    
    # Check that brand impersonation indicator was identified
    indicator_names = [ind["name"] for ind in data["indicators"]]
    assert any("Brand Impersonation" in name for name in indicator_names)

def test_scan_direct_ip_url():
    url = "http://185.220.101.5:8080/secure/auth/login.html"
    response = client.post("/api/v1/scan", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    indicator_names = [ind["name"] for ind in data["indicators"]]
    assert any("Direct IPv4" in name for name in indicator_names)

def test_scan_at_symbol_deception():
    url = "http://amazon.com:security-check@malicious-host.top/auth"
    response = client.post("/api/v1/scan", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    indicator_names = [ind["name"] for ind in data["indicators"]]
    assert any("At-Symbol" in name for name in indicator_names)

def test_validation_rejects_empty_url():
    response = client.post("/api/v1/scan", json={"url": ""})
    assert response.status_code == 422

def test_validation_rejects_dangerous_pseudo_schemes():
    forbidden = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "blob:http://localhost/uuid",
        "ftp://files.example.com",
    ]
    for bad_url in forbidden:
        response = client.post("/api/v1/scan", json={"url": bad_url})
        assert response.status_code == 422, f"Failed to reject forbidden scheme for {bad_url}"

def test_history_crud_flow():
    # 1. Clear existing history
    del_res = client.delete("/api/v1/history")
    assert del_res.status_code == 200

    # 2. Add two scans
    client.post("/api/v1/scan", json={"url": "https://python.org/downloads"})
    client.post("/api/v1/scan", json={"url": "https://chase.com.security-alert.top/signin"})

    # 3. Retrieve history
    history_res = client.get("/api/v1/history?limit=10")
    assert history_res.status_code == 200
    items = history_res.json()
    assert len(items) >= 2

    # 4. Delete single record
    item_id = items[0]["id"]
    delete_item_res = client.delete(f"/api/v1/history/{item_id}")
    assert delete_item_res.status_code == 200

    # 5. Verify deleted
    history_res_after = client.get("/api/v1/history?limit=10")
    remaining_ids = [it["id"] for it in history_res_after.json()]
    assert item_id not in remaining_ids

def test_analytics_metrics():
    response = client.get("/api/v1/analytics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "high_risk_scans" in data
    assert "avg_risk_score" in data
    assert "top_indicators" in data
    assert "db_type" in data
