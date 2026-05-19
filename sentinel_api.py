"""
SENTINEL API - Groq LLM (Free, Fast, No Setup Required)
Railway Deployment Ready
"""

import os
import re
import logging
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ── Config from Railway Environment Variables ──
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL   = os.environ.get("GROQ_MODEL", "llama3-8b-8192")
PORT         = int(os.environ.get("PORT", 5000))

logger.info(f"SENTINEL API starting | Groq model: {GROQ_MODEL} | Groq key set: {bool(GROQ_API_KEY)}")

# ── Heuristic patterns ──
PHISHING_KEYWORDS = [
    "urgent", "immediate action", "act now", "verify account",
    "confirm identity", "suspended", "locked", "limited time",
    "click here", "download now", "update payment", "confirm details",
    "unusual activity", "security alert", "verify password"
]
SPAM_KEYWORDS = [
    "viagra", "cialis", "casino", "lottery", "prize",
    "congratulations", "claim reward", "you have won",
    "limited offer", "buy now"
]
SUSPICIOUS_TLDS = [".xyz", ".ru", ".tk", ".top", ".cn", ".pw"]


# ── Heuristic Analysis ──
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
            flags.append(f"suspicious_tld")
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


# ── Groq LLM Analysis ──
def groq_analysis(sender: str, subject: str, body: str) -> dict:
    if not GROQ_API_KEY:
        logger.warning("GROQ_API_KEY not set")
        return {"success": False, "error": "GROQ_API_KEY not configured"}

    prompt = f"""You are a cybersecurity email threat analyst. Analyze this email.

From: {sender}
Subject: {subject}
Body: {body[:800]}

Return ONLY valid JSON (no markdown, no extra text):
{{
  "risk_score": <0-100>,
  "classification": "<phishing|malware|spam|suspicious|legitimate>",
  "explanation": "<one clear sentence>",
  "red_flags": [<up to 3 specific threats detected>]
}}"""

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 300
            },
            timeout=20
        )
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]
        logger.info(f"Groq raw response: {text[:200]}")

        match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
        if match:
            import json
            data = json.loads(match.group(0))
            logger.info(f"Groq success: score={data.get('risk_score')}")
            return {"success": True, "analysis": data}
        else:
            logger.error("No JSON in Groq response")
            return {"success": False, "error": "No JSON in response"}

    except requests.exceptions.Timeout:
        logger.error("Groq timeout")
        return {"success": False, "error": "Groq timeout"}
    except requests.exceptions.HTTPError as e:
        logger.error(f"Groq HTTP error: {e}")
        return {"success": False, "error": f"Groq HTTP {e.response.status_code}"}
    except Exception as e:
        logger.error(f"Groq error: {e}")
        return {"success": False, "error": str(e)}


# ── Combined Analysis ──
def analyze_email(sender: str, subject: str, body: str) -> dict:
    h      = heuristic_analysis(sender, subject, body)
    h_score = h["heuristic_score"]

    groq = groq_analysis(sender, subject, body)

    if groq["success"]:
        a          = groq["analysis"]
        llm_score  = a.get("risk_score", h_score)
        final      = int(h_score * 0.3 + llm_score * 0.7)
        logger.info(f"Blend: heuristic={h_score}, llm={llm_score}, final={final}")
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
        # Heuristic-only fallback
        if h_score < 30:   cls = "legitimate"
        elif h_score < 55: cls = "suspicious"
        elif h_score < 80: cls = "phishing"
        else:              cls = "malware"

        return {
            "risk_score":      h_score,
            "classification":  cls,
            "explanation":     f"Heuristic only (Groq unavailable: {groq.get('error')})",
            "red_flags":       h["heuristic_flags"],
            "method":          "heuristic_only",
            "timestamp":       datetime.now().isoformat()
        }


# ── Routes ──
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status":        "ok",
        "service":       "SENTINEL API",
        "groq_key_set":  bool(GROQ_API_KEY),
        "groq_model":    GROQ_MODEL,
        "timestamp":     datetime.now().isoformat()
    }), 200


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

        body = body[:50000]
        logger.info(f"Analyzing: id={message_id} sender={sender[:30]}")

        result = analyze_email(sender, subject, body)
        result["message_id"] = message_id
        logger.info(f"Done: score={result['risk_score']} method={result['method']}")
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return jsonify({"error": str(e), "risk_score": 50, "classification": "unknown"}), 500


@app.route('/api/config', methods=['GET'])
def config():
    return jsonify({
        "service":    "SENTINEL API",
        "version":    "4.0",
        "ai_backend": "Groq (cloud LLM)",
        "model":      GROQ_MODEL,
        "endpoints":  ["/health", "/api/analyze", "/api/config"]
    }), 200


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
