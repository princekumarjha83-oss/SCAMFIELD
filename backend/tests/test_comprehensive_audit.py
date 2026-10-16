"""
Comprehensive Feature-by-Feature End-to-End Audit Test Suite for ScamShield AI
Executes every single feature, scanning modality, edge cases, error conditions,
history operations, and analytics against the live running API server.
"""

import sys
import io
import json
import urllib.request
import urllib.error
from PIL import Image, ImageDraw

BASE_URL = "http://127.0.0.1:8000"

def log_test(name, passed, detail=""):
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} | {name}: {detail}")
    if not passed:
        raise AssertionError(f"Test failed: {name} - {detail}")

def http_req(path, method="GET", data=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_headers = headers or {}
    req_data = None
    if data is not None:
        if isinstance(data, dict):
            req_data = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        elif isinstance(data, bytes):
            req_data = data
    
    req = urllib.request.Request(url, data=req_data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if "application/json" in resp.headers.get("Content-Type", "") else body
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(err_body)
        except Exception:
            return e.code, err_body

def run_audit():
    print("==================================================")
    print("Starting ScamShield AI Live System Feature Audit")
    print("==================================================")

    # 1. System Health Probe
    status, res = http_req("/api/v1/health")
    log_test("Health Probe", status == 200 and res.get("status") == "online" and res.get("model_loaded") is True, f"Status: {res.get('status')}, Modalities: {res.get('supported_modalities')}")

    # 2. Model Provenance & Provenance Metadata
    status, res = http_req("/api/v1/model-info")
    log_test("Model Provenance", status == 200 and "RandomForest" in res.get("model_name", "") and res.get("metrics", {}).get("accuracy") is not None, f"Model: {res.get('model_name')}, Accuracy: {res.get('metrics', {}).get('accuracy')}")

    # 3. URL Scanner - Benign URL
    status, res = http_req("/api/v1/scan/url", method="POST", data={"url": "https://www.wikipedia.org"})
    log_test("URL Scanner (Benign)", status == 200 and res.get("risk_level") == "SAFE", f"Score: {res.get('risk_score')}, Level: {res.get('risk_level')}")

    # 4. URL Scanner - Phishing URL (Subdomain stacking + Brand lure)
    status, res = http_req("/api/v1/scan/url", method="POST", data={"url": "https://paypal.com.account-verification-portal.top/login.php"})
    log_test("URL Scanner (Phishing)", status == 200 and res.get("risk_level") == "HIGH" and res.get("risk_score") >= 70, f"Score: {res.get('risk_score')}, Flags: {len(res.get('indicators', []))}")

    # 5. URL Scanner - Malformed URL Validation
    status, res = http_req("/api/v1/scan/url", method="POST", data={"url": "not-a-valid-url"})
    log_test("URL Scanner (Validation Reject)", status == 422, f"Expected 422, received: {status}")

    # 6. Message Scanner - Benign Message
    status, res = http_req("/api/v1/scan/message", method="POST", data={"text": "Hey team, the quarterly security sync is rescheduled to Thursday at 3 PM. See you there!"})
    log_test("Message Scanner (Benign)", status == 200 and res.get("risk_level") == "SAFE" and res.get("intent_category") == "BENIGN_COMMUNICATION", f"Score: {res.get('risk_score')}, Category: {res.get('intent_category')}")

    # 7. Message Scanner - Credential Harvesting Phish
    scam_msg = "URGENT: Your Wells Fargo online banking has been restricted. Immediate action required. Send your one-time verification password OTP or your account will be locked: https://wellsfargo.verify-access.xyz"
    status, res = http_req("/api/v1/scan/message", method="POST", data={"text": scam_msg})
    log_test("Message Scanner (Credential Phish)", status == 200 and res.get("risk_level") == "HIGH" and len(res.get("indicators")) >= 2, f"Score: {res.get('risk_score')}, Category: {res.get('intent_category')}, Actions: {len(res.get('recommended_actions', []))}")

    # 8. Message Scanner - Financial Extortion / Gift Card
    extortion_msg = "INTERNAL REVENUE SERVICE NOTICE: Immediate warrant issued for your arrest. You must settle your unpaid tax balance using $1000 Apple gift card immediately to avoid federal marshals."
    status, res = http_req("/api/v1/scan/message", method="POST", data={"text": extortion_msg})
    log_test("Message Scanner (Financial Extortion)", status == 200 and res.get("risk_score") >= 60, f"Score: {res.get('risk_score')}, Category: {res.get('intent_category')}")

    # 9. Message Scanner - Empty Text Rejection
    status, res = http_req("/api/v1/scan/message", method="POST", data={"text": "   "})
    log_test("Message Scanner (Empty Rejection)", status == 422, f"Expected 422, received: {status}")

    # 10. Message Scanner - Excessively Long Text Rejection (>10k chars)
    oversized_text = "A" * 12000
    status, res = http_req("/api/v1/scan/message", method="POST", data={"text": oversized_text})
    log_test("Message Scanner (Oversized Rejection)", status == 422, f"Expected 422 for >10k chars, received: {status}")

    # 11. Email Scanner - Benign Internal Memo
    status, res = http_req("/api/v1/scan/email", method="POST", data={
        "sender": "Alice Smith <asmith@acme-corp.com>",
        "subject": "Sprint Review Notes",
        "body": "Hi everyone, here are the meeting notes from today. Thanks for attending."
    })
    log_test("Email Scanner (Benign)", status == 200 and res.get("risk_level") == "SAFE", f"Score: {res.get('risk_score')}, Level: {res.get('risk_level')}")

    # 12. Email Scanner - Free Webmail Spoofing & Credential Lure
    status, res = http_req("/api/v1/scan/email", method="POST", data={
        "sender": "PayPal Fraud Security <paypal-fraud-alerts@gmail.com>",
        "subject": "URGENT NOTICE: Account Frozen - Action Required in 24 Hours",
        "body": "Dear customer, unauthorized activity detected. Download the attached invoice.zip and verify password at https://paypal.com.user-resolution.top/login"
    })
    log_test("Email Scanner (Free Webmail Spoof)", status == 200 and res.get("risk_level") == "HIGH", f"Score: {res.get('risk_score')}, Flags: {[i['name'] for i in res.get('indicators', [])]}")

    # 13. Email Scanner - Raw RFC 822 Format
    raw_rfc_email = (
        "From: Netflix Support <billing@netflix-suspicious.icu>\n"
        "Subject: Final Notice: Subscription Cancelled\n"
        "Date: Mon, 16 Oct 2026 12:00:00 +0000\n\n"
        "We could not process payment. Update credit card immediately at http://netflix.billing-fix.top"
    )
    status, res = http_req("/api/v1/scan/email", method="POST", data={"body": raw_rfc_email})
    log_test("Email Scanner (Raw RFC 822)", status == 200 and res.get("subject") == "Final Notice: Subscription Cancelled", f"Parsed Subject: {res.get('subject')}, Risk: {res.get('risk_score')}")

    # 14. Email Scanner - Empty Body Rejection
    status, res = http_req("/api/v1/scan/email", method="POST", data={"body": "  "})
    log_test("Email Scanner (Empty Body Rejection)", status == 422, f"Expected 422, received: {status}")

    # 15. Screenshot Scanner - Synthetic Image with Phishing Text (Multipart)
    img = Image.new("RGB", (600, 140), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 20), "ALERT: Wells Fargo account locked due to suspicious activity.", fill=(0, 0, 0))
    draw.text((20, 60), "Send OTP verification code immediately: http://wellsfargo.sec-login.xyz", fill=(0, 0, 0))
    
    img_bytes_io = io.BytesIO()
    img.save(img_bytes_io, format="PNG")
    img_bytes = img_bytes_io.getvalue()

    boundary = "----ScamShieldBoundary12345678"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test_screenshot.png"\r\n'
        f"Content-Type: image/png\r\n\r\n"
    ).encode("utf-8") + img_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    status, res = http_req("/api/v1/scan/screenshot", method="POST", data=body, headers=headers)
    log_test("Screenshot Scanner (Synthetic Phish)", status == 200 and res.get("scan_type") == "screenshot", f"Engine: {res.get('ocr_metadata', {}).get('engine')}, Extracted Text: {res.get('extracted_text')[:50]}..., Score: {res.get('risk_score')}")

    # 16. Screenshot Scanner - Unsupported File Type Rejection
    fake_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="malicious.exe"\r\n'
        f"Content-Type: application/x-msdownload\r\n\r\n"
        f"MZ9000000000\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    status, res = http_req("/api/v1/scan/screenshot", method="POST", data=fake_body, headers=headers)
    log_test("Screenshot Scanner (Invalid File Type)", status in (400, 415), f"Expected 415/400 for .exe, received: {status}")

    # 17. Screenshot Scanner - Blank Image (Zero Text)
    blank_img = Image.new("RGB", (100, 100), color=(240, 240, 240))
    blank_bytes_io = io.BytesIO()
    blank_img.save(blank_bytes_io, format="PNG")
    blank_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="blank.png"\r\n'
        f"Content-Type: image/png\r\n\r\n"
    ).encode("utf-8") + blank_bytes_io.getvalue() + f"\r\n--{boundary}--\r\n".encode("utf-8")
    status, res = http_req("/api/v1/scan/screenshot", method="POST", data=blank_body, headers=headers)
    log_test("Screenshot Scanner (Blank Image)", status == 200 and res.get("ocr_metadata", {}).get("has_text") is False and res.get("risk_level") == "SAFE", f"Has Text: {res.get('ocr_metadata', {}).get('has_text')}, Risk: {res.get('risk_level')}")

    # 18. Scan History - Listing & Modality Filtering
    status, res_all = http_req("/api/v1/history?limit=50")
    log_test("History (All Records)", status == 200 and len(res_all) >= 4, f"Total records retrieved: {len(res_all)}")

    status, res_msg = http_req("/api/v1/history?scan_type=message")
    log_test("History Filter (Message)", status == 200 and all(r.get("scan_type") == "message" for r in res_msg), f"Message records: {len(res_msg)}")

    status, res_url = http_req("/api/v1/history?scan_type=url")
    log_test("History Filter (URL)", status == 200 and all(r.get("scan_type") == "url" for r in res_url), f"URL records: {len(res_url)}")

    status, res_screen = http_req("/api/v1/history?scan_type=screenshot")
    log_test("History Filter (Screenshot)", status == 200 and all(r.get("scan_type") == "screenshot" for r in res_screen), f"Screenshot records: {len(res_screen)}")

    status, res_email = http_req("/api/v1/history?scan_type=email")
    log_test("History Filter (Email)", status == 200 and all(r.get("scan_type") == "email" for r in res_email), f"Email records: {len(res_email)}")

    # 19. Threat Analytics Computation
    status, res_ana = http_req("/api/v1/analytics")
    log_test("Analytics Calculation", status == 200 and res_ana.get("total_scans") > 0 and "top_indicators" in res_ana, f"Total Scans: {res_ana.get('total_scans')}, High Risk: {res_ana.get('high_risk_scans')}, Safe: {res_ana.get('safe_scans')}, Avg Score: {res_ana.get('avg_risk_score')}")

    # 20. History Deletion (Single Record)
    if res_all:
        target_id = res_all[0]["id"]
        status, del_res = http_req(f"/api/v1/history/{target_id}", method="DELETE")
        log_test("Delete Single History Record", status == 200 and del_res.get("deleted") is True, f"Deleted ID {target_id}")

    print("==================================================")
    print("ALL 20 END-TO-END FEATURE AUDIT CHECKS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    try:
        run_audit()
    except Exception as e:
        print(f"\nAUDIT FAILED: {e}")
        sys.exit(1)

