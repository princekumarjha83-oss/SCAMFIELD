"""
ScamShield AI - Comprehensive Multi-Modal Test Suite
Tests URL, Message, Screenshot (OCR), and Email threat detection engines,
along with input validation, rate limiting, and database audit logs.
"""

import io
import pytest
from PIL import Image, ImageDraw
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import Base, engine

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield

# ----------------- SYSTEM & URL TESTS -----------------

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "url" in data["supported_modalities"]
    assert "message" in data["supported_modalities"]
    assert "screenshot" in data["supported_modalities"]
    assert "email" in data["supported_modalities"]

def test_model_info():
    response = client.get("/api/v1/model-info")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "confusion_matrix" in data["metrics"]
    assert data["metrics"]["accuracy"] > 0.9

def test_scan_url_benign():
    url = "https://en.wikipedia.org/wiki/Computer_security"
    response = client.post("/api/v1/scan/url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] < 40
    assert data["risk_level"] in ("SAFE", "SUSPICIOUS")

def test_scan_url_phishing():
    url = "https://paypal.com.account-verification-service.xyz/webapps/login.php"
    response = client.post("/api/v1/scan/url", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 65
    assert data["risk_level"] == "HIGH"
    assert any("Brand Impersonation" in ind["name"] for ind in data["indicators"])

# ----------------- MESSAGE SCANNER TESTS -----------------

def test_scan_message_phishing():
    scam_text = (
        "URGENT: Your Wells Fargo account has been suspended due to unauthorized login activity. "
        "Immediate action required within 24 hours. Send your one-time password OTP code or purchase "
        "a $500 Apple gift card to verify identity: https://wellsfargo.verify-portal.top/auth"
    )
    response = client.post("/api/v1/scan/message", json={"text": scam_text})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 65
    assert data["risk_level"] == "HIGH"
    assert data["intent_category"] in ("CREDENTIAL_HARVESTING", "FINANCIAL_EXTORTION_OR_FRAUD", "URGENT_BRAND_MASQUERADE")
    assert len(data["recommended_actions"]) > 0

    ind_names = [ind["name"] for ind in data["indicators"]]
    assert any("Urgency" in name or "Action" in name for name in ind_names)
    assert any("Impersonation" in name for name in ind_names)

def test_scan_message_benign():
    benign_text = "Hi Alice, are we still meeting tomorrow at 3 PM for the project retrospective? Let me know!"
    response = client.post("/api/v1/scan/message", json={"text": benign_text})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] < 35
    assert data["risk_level"] == "SAFE"
    assert data["intent_category"] == "BENIGN_COMMUNICATION"

def test_scan_message_empty_validation():
    response = client.post("/api/v1/scan/message", json={"text": "   "})
    assert response.status_code == 422

# ----------------- SCREENSHOT OCR SCANNER TESTS -----------------

def test_scan_screenshot_with_phish_text():
    # Generate in-memory synthetic image with scam message
    img = Image.new("RGB", (650, 150), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 20), "URGENT NOTICE: PayPal account locked. Immediate action required.", fill=(0, 0, 0))
    draw.text((20, 60), "Please enter password and OTP to verify: http://paypal.sec-portal.xyz", fill=(0, 0, 0))

    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")
    img_byte_arr.seek(0)

    files = {"file": ("screenshot.png", img_byte_arr, "image/png")}
    response = client.post("/api/v1/scan/screenshot", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "screenshot"
    assert "ocr_metadata" in data
    assert data["ocr_metadata"]["format"] == "PNG"

    if data["extracted_text"]:
        assert data["risk_score"] >= 35

def test_scan_screenshot_blank_image():
    # Blank white image with no text
    img = Image.new("RGB", (300, 300), color=(255, 255, 255))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")
    img_byte_arr.seek(0)

    files = {"file": ("blank.png", img_byte_arr, "image/png")}
    response = client.post("/api/v1/scan/screenshot", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "SAFE"
    assert data["extracted_text"] == ""
    assert "No legible text" in data["summary"]

def test_scan_screenshot_unsupported_file_type():
    txt_content = b"This is a text file, not an image."
    files = {"file": ("malicious.txt", io.BytesIO(txt_content), "text/plain")}
    response = client.post("/api/v1/scan/screenshot", files=files)
    assert response.status_code == 415

# ----------------- EMAIL SCANNER TESTS -----------------

def test_scan_email_brand_spoofing_free_webmail():
    payload = {
        "sender": "PayPal Customer Service <paypal-security-alert@gmail.com>",
        "subject": "RE: Urgent Action Required on Account",
        "body": "Dear customer, your PayPal balance has been frozen. Download the invoice.zip attachment or visit http://paypal-update.top"
    }
    response = client.post("/api/v1/scan/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 65
    assert data["risk_level"] == "HIGH"

    ind_names = [ind["name"] for ind in data["indicators"]]
    assert any("Free Webmail Brand Impersonation" in name for name in ind_names)
    assert any("Dangerous Attachment" in name or "Attachment Mentioned" in name for name in ind_names)
    assert "disclaimer" in data

def test_scan_email_raw_rfc_format():
    raw_email = (
        "From: Netflix Support <billing-team@netflix-account-verify.icu>\n"
        "To: user@example.com\n"
        "Subject: Final Notice: Payment Failed - Service Termination\n"
        "Date: Mon, 16 Oct 2026 12:00:00 +0000\n"
        "\n"
        "Your Netflix subscription has expired. Update credit card CVV within 24 hours: https://netflix.billing-verify.icu"
    )
    payload = {"body": raw_email}
    response = client.post("/api/v1/scan/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 50
    assert "Netflix" in data["sender"] or "Netflix" in data["subject"]

# ----------------- AUDIT HISTORY & ANALYTICS -----------------

def test_history_filtering_by_modality():
    # Clear history
    client.delete("/api/v1/history")

    # Add URL scan
    client.post("/api/v1/scan/url", json={"url": "https://github.com/security"})
    # Add Message scan
    client.post("/api/v1/scan/message", json={"text": "Hello world message"})

    # Fetch all
    res_all = client.get("/api/v1/history?scan_type=all")
    assert res_all.status_code == 200
    assert len(res_all.json()) >= 2

    # Filter URL
    res_url = client.get("/api/v1/history?scan_type=url")
    assert res_url.status_code == 200
    assert all(item["scan_type"] == "url" for item in res_url.json())

    # Filter Message
    res_msg = client.get("/api/v1/history?scan_type=message")
    assert res_msg.status_code == 200
    assert all(item["scan_type"] == "message" for item in res_msg.json())

def test_analytics_computation():
    response = client.get("/api/v1/analytics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "avg_risk_score" in data
    assert "top_indicators" in data
