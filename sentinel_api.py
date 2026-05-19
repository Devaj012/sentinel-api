"""
SENTINEL API - Groq LLM - Debug Version
"""

import os
import re
import json
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
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama3-8b-8192")
PORT         = int(os.environ.get("PORT", 5000))

logger.info(f"=== SENTINEL STARTING ===")
logger.info(f"GROQ_API_KEY present: {bool(GROQ_API_KEY)}")
logger.info(f"GROQ_API_KEY length: {len(GROQ_API_KEY)}")
logger.info(f"GROQ_API_KEY starts with: {GROQ_API_KEY[:8] if GROQ_API_KEY else 'EMPTY'}")
logger.info(f"GROQ_MODEL: {GROQ_MODEL}")
logger.info(f"PORT: {PORT}")

PHISHING_KEYWORDS = [
    "urgent", "immediate action", "act now", "verify account",
    "confirm identity", "suspended", "locked", "limited time",
    "click here", "download now", "update payment", "confirm details",
    "unusual activity", "security alert"
]
SPAM_KEYWORDS = [
    "viagra", "cialis", "casino", "lottery", "prize",
    "congratulations", "claim reward", "you have won", "limited offer", "buy now"
]
SUSPICIOUS_TLDS = [".xyz", ".ru", ".tk", ".top", ".cn", ".pw"]


def heuristic_analysis(sender: str, subject: str, body: str) -> dict:
    score = 0
    flags = []
    text  = (sender + " " + subject + " " + body).lower()

    ph = sum(1 for kw in PHISHING_KEYWORDS if kw in text)
    if ph:
        score += ph * 8
        flags.append(f"phishing_keywords:{ph}")

    sp = sum(1 for kw in SPAM_KEYWORDS if kw in text)
    if sp:
        score += sp * 6
        flags.append(f"spam_keywords:{sp}")

    if "@" in sender:
        domain = sender.split("@")[1].lower()
        if any(domain.endswith(t) for t in SUSPICIOUS_TLDS):
            score += 20
            flags.append("suspicious_tld")
        if len(domain) > 30:
            score += 10
            flags.append("long_domain")
        if domain.count("-") >= 2:
            score += 8
            flags.append("multiple_hyphens")

    if subject == subject.upper() and len(subject) > 10:
        score += 10
        flags.append("all_caps_subject")

    if len(body) < 50:
        score += 5
        flags.append("very_short_email")

    urls = re.findall(r'https?://\S+', body)
    if urls:
        score += 3 * len(urls)
        flags.append(f"url_count:{len(urls)}")

    return {"heuristic_score": min(score, 100), "heuristic_flags": flags[:4]}


def groq_analysis(sender: str, subject: str, body: str) -> dict:
    if not GROQ_API_KEY:
        logger.error("GROQ_API_KEY is empty!")
        return {"success": False, "error": "GROQ_API_KEY not set in Railway variables"}

    api_key = GROQ_API_KEY.strip()

    logger.info(f"Calling Groq... key starts: {api_key[:10]}... model: {GROQ_MODEL}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You are a cybersecurity email threat analyst. Always respond with only valid JSON."
            },
            {
                "role": "user",
                "content": f"""Analyze this email for threats.

From: {sender}
Subject: {subject}
Body: {body[:500]}

Respond with ONLY this JSON (no markdown, no extra text):
{{"risk_score": 0, "classification": "legitimate", "explanation": "explanation here", "red_flags": []}}"""
            }
        ],
        "temperature": 0.1,
        "max_tokens": 200
    }

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=25
        )

        logger.info(f"Groq status: {resp.status_code}")
        logger.info(f"Groq body: {resp.text[:500]}")

        if resp.status_code == 400:
            return {"success": False, "error": f"Groq 400: {resp.text[:200]}"}
        if resp.status_code == 401:
            return {"success": False, "error": "Groq 401: Invalid API key"}
        if resp.status_code == 429:
            return {"success": False, "error": "Groq 429: Rate limited"}

        resp.raise_for_status()

        content = resp.json()["choices"][0]["message"]["content"]
        logger.info(f"Groq content: {content[:300]}")

        match = re.search(r'\{.*?\}', content, re.DOTALL)
        if match:
            data = json.loads(match.group(0))
            return {"success": True, "analysis": data}
        else:
            return {"success": False, "error": f"No JSON in response: {content[:100]}"}

    except requests.exceptions.Timeout:
        return {"success": False, "error": "Groq timeout after 25s"}
    except requests.exceptions.ConnectionError as e:
        return {"success": False, "error": f"Cannot connect to Groq: {str(e)[:100]}"}
    except Exception as e:
        logger.error(f"Groq error: {e}", exc_info=True)
        return {"success": False, "error": str(e)}


def analyze_email(sender: str, subject: str, body: str) -> dict:
    h       = heuristic_analysis(sender, subject, body)
    h_score = h["heuristic_score"]
    groq    = groq_analysis(sender, subject, body)

    if groq["success"]:
        a         = groq["analysis"]
        llm_score = int(a.get("risk_score", h_score))
        final     = int(h_score * 0.3 + llm_score * 0.7)
        return {
            "risk_score":      min(final, 100),
            "classification":  a.get("classification", "unknown"),
            "explanation":     a.get("explanation", ""),
            "red_flags":       a.get("red_flags", []),
            "heuristic_score": h_score,
            "llm_score":       llm_score,
            "method":          "groq_blend",
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
            "explanation":     f"Heuristic only — Groq error: {groq.get('error', 'unknown')}",
            "red_flags":       h["heuristic_flags"],
            "method":          "heuristic_only",
            "timestamp":       datetime.now().isoformat()
        }


@app.route('/health', methods=['GET'])
def health():
    api_key = GROQ_API_KEY.strip() if GROQ_API_KEY else ""
    return jsonify({
        "status":          "ok",
        "service":         "SENTINEL API",
        "groq_key_set":    bool(api_key),
        "groq_key_prefix": api_key[:10] + "..." if api_key else "EMPTY",
        "groq_model":      GROQ_MODEL,
        "timestamp":       datetime.now().isoformat()
    }), 200


@app.route('/api/test-groq', methods=['GET'])
def test_groq():
    """Direct Groq connection test"""
    api_key = GROQ_API_KEY.strip() if GROQ_API_KEY else ""
    if not api_key:
        return jsonify({"error": "GROQ_API_KEY not set"}), 400
    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": "Say the word: WORKING"}],
                "max_tokens": 10
            },
            timeout=15
        )
        return jsonify({
            "status_code": resp.status_code,
            "response":    resp.text[:500],
            "key_prefix":  api_key[:10] + "...",
            "model":       GROQ_MODEL
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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

        logger.info(f"Analyze: id={message_id} from={sender[:30]}")
        result               = analyze_email(sender, subject, body[:50000])
        result["message_id"] = message_id
        logger.info(f"Result: score={result['risk_score']} method={result['method']}")
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return jsonify({"error": str(e), "risk_score": 50, "classification": "unknown"}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
