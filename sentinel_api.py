"""
SENTINEL API - Groq LLM + Fixed Heuristic
Properly decodes Gmail base64 email body from n8n
"""

import os
import re
import json
import base64
import logging
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
PORT         = int(os.environ.get("PORT", 5000))

logger.info(f"=== SENTINEL STARTING === model:{GROQ_MODEL} key_set:{bool(GROQ_API_KEY)}")

# ── Heuristic patterns ──
PHISHING_KEYWORDS = [
    "urgent", "immediate action", "act now", "verify account",
    "confirm identity", "suspended", "locked", "limited time",
    "click here", "download now", "update payment", "confirm details",
    "unusual activity", "security alert", "verify password",
    "your account", "reset password", "login attempt", "unusual sign",
    "will be suspended", "verify your", "validate your"
]
SPAM_KEYWORDS = [
    "viagra", "cialis", "casino", "lottery", "prize",
    "congratulations", "claim reward", "you have won",
    "limited offer", "buy now", "earn money", "work from home",
    "make money fast", "free gift", "click below"
]
SUSPICIOUS_TLDS = [".xyz", ".ru", ".tk", ".top", ".cn", ".pw", ".ml", ".ga", ".cf"]

SOCIAL_ENGINEERING = [
    "send me", "transfer", "wire", "bitcoin", "gift card",
    "i need to buy", "send money", "bank account", "western union",
    "you owe", "payment required", "invoice attached"
]


# ── Decode base64 Gmail body ──
def decode_body(text: str) -> str:
    """Gmail sends base64url-encoded body via n8n. Decode it."""
    if not text:
        return ""

    # If it looks like base64 (long string, no spaces, contains +/= or url-safe chars)
    cleaned = text.strip().replace('\n', '').replace('\r', '')
    if len(cleaned) > 100 and ' ' not in cleaned[:100]:
        try:
            # Try URL-safe base64 first (Gmail uses this)
            decoded = base64.urlsafe_b64decode(cleaned + '==').decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 10:
                logger.info(f"Decoded base64 body: {len(decoded)} chars")
                # Strip HTML tags if present
                decoded = re.sub(r'<[^>]+>', ' ', decoded)
                decoded = re.sub(r'\s+', ' ', decoded).strip()
                return decoded
        except Exception:
            pass
        try:
            # Try standard base64
            decoded = base64.b64decode(cleaned + '==').decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 10:
                decoded = re.sub(r'<[^>]+>', ' ', decoded)
                decoded = re.sub(r'\s+', ' ', decoded).strip()
                return decoded
        except Exception:
            pass

    # Already plain text — just strip HTML if any
    plain = re.sub(r'<[^>]+>', ' ', text)
    plain = re.sub(r'\s+', ' ', plain).strip()
    return plain


# ── Heuristic Analysis ──
def heuristic_analysis(sender: str, subject: str, body: str) -> dict:
    score = 0
    flags = []
    # Combine all text for scanning
    text = (sender + " " + subject + " " + body).lower()

    logger.info(f"Heuristic scanning text ({len(text)} chars): '{text[:200]}'")

    # Phishing keywords
    ph_hits = [kw for kw in PHISHING_KEYWORDS if kw in text]
    if ph_hits:
        score += len(ph_hits) * 8
        flags.append(f"phishing_keywords: {', '.join(ph_hits[:3])}")
        logger.info(f"Phishing hits: {ph_hits}")

    # Spam keywords
    sp_hits = [kw for kw in SPAM_KEYWORDS if kw in text]
    if sp_hits:
        score += len(sp_hits) * 6
        flags.append(f"spam_keywords: {', '.join(sp_hits[:3])}")
        logger.info(f"Spam hits: {sp_hits}")

    # Social engineering (money requests etc.)
    se_hits = [kw for kw in SOCIAL_ENGINEERING if kw in text]
    if se_hits:
        score += len(se_hits) * 12
        flags.append(f"social_engineering: {', '.join(se_hits[:3])}")
        logger.info(f"Social engineering hits: {se_hits}")

    # Suspicious sender domain
    if "@" in sender:
        domain = sender.split("@")[1].lower()
        if any(domain.endswith(t) for t in SUSPICIOUS_TLDS):
            score += 20
            flags.append(f"suspicious_tld: {domain}")
        if len(domain) > 30:
            score += 10
            flags.append("long_domain")
        if domain.count("-") >= 2:
            score += 8
            flags.append("multiple_hyphens_in_domain")

    # All caps subject
    if subject and subject == subject.upper() and len(subject) > 5:
        score += 10
        flags.append("all_caps_subject")

    # Very short email body
    if len(body.strip()) < 50:
        score += 5
        flags.append("very_short_body")

    # URLs in body
    urls = re.findall(r'https?://\S+', body)
    if urls:
        score += 3 * len(urls)
        flags.append(f"contains_{len(urls)}_url(s)")

    final_score = min(score, 100)
    logger.info(f"Heuristic score: {final_score} | flags: {flags}")

    return {
        "heuristic_score": final_score,
        "heuristic_flags": flags[:5]
    }


# ── Groq LLM Analysis ──
def groq_analysis(sender: str, subject: str, body: str) -> dict:
    if not GROQ_API_KEY:
        return {"success": False, "error": "GROQ_API_KEY not set"}

    api_key = GROQ_API_KEY.strip()
    logger.info(f"Calling Groq: model={GROQ_MODEL}")

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are a cybersecurity email threat analyst. Always respond with only valid JSON, no markdown."
            },
            {
                "role": "user",
                "content": f"""Analyze this email for phishing, spam, and social engineering threats.

From: {sender}
Subject: {subject}
Body: {body[:600]}

Return ONLY this JSON structure (fill in the values):
{{"risk_score": 0, "classification": "legitimate", "explanation": "one sentence here", "red_flags": []}}

Classification must be one of: phishing, malware, spam, suspicious, legitimate
risk_score: 0-100 (0=safe, 100=critical threat)"""
            }
        ],
        "temperature": 0.1,
        "max_tokens": 250
    }

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=25
        )

        logger.info(f"Groq status: {resp.status_code}")

        if resp.status_code != 200:
            logger.error(f"Groq error: {resp.text[:300]}")
            return {"success": False, "error": f"Groq {resp.status_code}: {resp.text[:150]}"}

        content = resp.json()["choices"][0]["message"]["content"]
        logger.info(f"Groq response: {content[:300]}")

        # Extract JSON from response
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match:
            data = json.loads(match.group(0))
            # Ensure risk_score is int
            data["risk_score"] = int(data.get("risk_score", 0))
            logger.info(f"Groq success: score={data['risk_score']} class={data.get('classification')}")
            return {"success": True, "analysis": data}
        else:
            return {"success": False, "error": f"No JSON in Groq response: {content[:100]}"}

    except requests.exceptions.Timeout:
        return {"success": False, "error": "Groq timeout"}
    except Exception as e:
        logger.error(f"Groq error: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


# ── Combined Analysis ──
def analyze_email(sender: str, subject: str, body: str) -> dict:
    # Decode body first (handles Gmail base64)
    decoded_body = decode_body(body)
    logger.info(f"Body after decode: '{decoded_body[:200]}'")

    h       = heuristic_analysis(sender, subject, decoded_body)
    h_score = h["heuristic_score"]
    groq    = groq_analysis(sender, subject, decoded_body)

    if groq["success"]:
        a         = groq["analysis"]
        llm_score = int(a.get("risk_score", h_score))
        final     = int(h_score * 0.3 + llm_score * 0.7)
        logger.info(f"Blend: h={h_score} llm={llm_score} final={final}")
        return {
            "risk_score":      min(final, 100),
            "classification":  a.get("classification", "unknown"),
            "explanation":     a.get("explanation", ""),
            "red_flags":       a.get("red_flags", []) + h["heuristic_flags"],
            "heuristic_score": h_score,
            "llm_score":       llm_score,
            "method":          "groq_blend",
            "decoded_body_preview": decoded_body[:100],
            "timestamp":       datetime.now().isoformat()
        }
    else:
        if h_score < 30:   cls = "legitimate"
        elif h_score < 55: cls = "suspicious"
        elif h_score < 80: cls = "phishing"
        else:              cls = "malware"

        return {
            "risk_score":      h_score,
            "classification":  cls,
            "explanation":     f"Heuristic analysis (Groq error: {groq.get('error', 'unknown')})",
            "red_flags":       h["heuristic_flags"],
            "method":          "heuristic_only",
            "decoded_body_preview": decoded_body[:100],
            "timestamp":       datetime.now().isoformat()
        }


# ── Routes ──
@app.route('/health', methods=['GET'])
def health():
    key = GROQ_API_KEY.strip() if GROQ_API_KEY else ""
    return jsonify({
        "status":          "ok",
        "service":         "SENTINEL API",
        "groq_key_set":    bool(key),
        "groq_key_prefix": key[:10] + "..." if key else "EMPTY",
        "groq_model":      GROQ_MODEL,
        "timestamp":       datetime.now().isoformat()
    }), 200


@app.route('/api/test-groq', methods=['GET'])
def test_groq():
    key = GROQ_API_KEY.strip() if GROQ_API_KEY else ""
    if not key:
        return jsonify({"error": "GROQ_API_KEY not set"}), 400
    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={"model": GROQ_MODEL, "messages": [{"role": "user", "content": "Say: WORKING"}], "max_tokens": 10},
            timeout=15
        )
        return jsonify({"status_code": resp.status_code, "response": resp.text[:300], "model": GROQ_MODEL}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/test-heuristic', methods=['GET'])
def test_heuristic():
    """Test heuristic with a known phishing sample"""
    result = analyze_email(
        sender="noreply@fake-bank.xyz",
        subject="URGENT: VERIFY YOUR ACCOUNT NOW",
        body="Click here to verify your account immediately or it will be suspended. Send me 1000 rupees gift card."
    )
    return jsonify(result), 200


@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        data       = request.json
        sender     = data.get("sender",     "unknown@unknown.com").strip()
        subject    = data.get("subject",    "").strip()
        body       = data.get("text",       "").strip()
        message_id = data.get("message_id", "unknown")

        if not body:
            return jsonify({"error": "Missing 'text' field"}), 400

        logger.info(f"Analyze: id={message_id} from={sender[:40]} body_len={len(body)}")
        result               = analyze_email(sender, subject, body[:50000])
        result["message_id"] = message_id
        logger.info(f"Done: score={result['risk_score']} method={result['method']}")
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return jsonify({"error": str(e), "risk_score": 50, "classification": "unknown"}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
