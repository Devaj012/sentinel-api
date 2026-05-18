"""
SENTINEL API Server
Exposes HTTP endpoints for n8n and external integrations to analyze emails
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import re
import logging
from datetime import datetime
from typing import Dict, Any
import os
from groq import Groq

# ──────────────────────────────────────────────
# Setup
# ──────────────────────────────────────────────
app = Flask(__name__)

groq_client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)

CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
AI_MODEL = "llama3-70b-8192"

# ──────────────────────────────────────────────
# Threat Detection Patterns
# ──────────────────────────────────────────────
PHISHING_PATTERNS = {
    "urgent_action": [
        r"urgent",
        r"immediate action",
        r"act now",
        r"verify account",
        r"confirm identity",
        r"suspended",
        r"locked",
        r"limited time"
    ],
    "suspicious_links": [
        r"click here",
        r"download now",
        r"open attachment",
        r"update payment",
        r"confirm details"
    ],
    "fake_authority": [
        r"amazon",
        r"paypal",
        r"bank",
        r"google",
        r"microsoft",
        r"apple"
    ]
}

SPAM_KEYWORDS = [
    "viagra",
    "casino",
    "lottery",
    "prize",
    "claim reward",
    "buy now",
    "limited offer"
]

# ──────────────────────────────────────────────
# Heuristic Analysis
# ──────────────────────────────────────────────
def heuristic_analysis(sender: str, subject: str, body: str) -> Dict[str, Any]:

    score = 0
    flags = []

    text_lower = f"{sender} {subject} {body}".lower()

    for category, patterns in PHISHING_PATTERNS.items():
        matches = [p for p in patterns if re.search(p, text_lower, re.I)]

        if matches:
            score += len(matches) * 10
            flags.append(f"{category}: {', '.join(matches[:2])}")

    spam_count = sum(1 for keyword in SPAM_KEYWORDS if keyword in text_lower)

    if spam_count > 0:
        score += spam_count * 5
        flags.append(f"spam_keywords: {spam_count}")

    if len(body) < 50:
        score += 5
        flags.append("very_short_email")

    if subject.isupper() and len(subject) > 10:
        score += 10
        flags.append("all_caps_subject")

    score = min(score, 100)

    return {
        "heuristic_score": score,
        "heuristic_flags": flags,
        "use_llm": True
    }

# ──────────────────────────────────────────────
# LLM Analysis
# ──────────────────────────────────────────────
def llm_analysis(sender: str, subject: str, body: str):

    prompt = f"""
You are a cybersecurity threat analyst.

Analyze this email for:
- phishing
- malware
- spam
- suspicious intent
- scams
- fraud

FROM:
{sender}

SUBJECT:
{subject}

BODY:
{body[:3000]}

Return ONLY valid JSON:
{{
  "risk_score": 0-100,
  "classification": "phishing|spam|malware|suspicious|legitimate",
  "explanation": "short explanation",
  "red_flags": ["flag1", "flag2"]
}}
"""

    try:

        response = groq_client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are an advanced email security AI. Respond ONLY in valid JSON."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.2
        )

        response_text = response.choices[0].message.content

        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)

        if json_match:
            analysis = json.loads(json_match.group(0))

            return {
                "llm_analysis": analysis,
                "llm_success": True
            }

    except Exception as e:
        logger.error(f"Groq analysis failed: {e}")

    return {
        "llm_analysis": {
            "risk_score": 50,
            "classification": "unknown",
            "explanation": "AI analysis failed",
            "red_flags": ["analysis_failed"]
        },
        "llm_success": False
    }

# ──────────────────────────────────────────────
# Combined Analysis
# ──────────────────────────────────────────────
def analyze_email(sender: str, subject: str, body: str):

    heuristic = heuristic_analysis(sender, subject, body)

    llm = llm_analysis(sender, subject, body)

    h_score = heuristic.get("heuristic_score", 0)

    llm_score = llm.get(
        "llm_analysis",
        {}
    ).get(
        "risk_score",
        h_score
    )

    final_score = int((h_score * 0.3) + (llm_score * 0.7))

    final_analysis = llm.get("llm_analysis", {})

    return {
        "risk_score": min(final_score, 100),
        "classification": final_analysis.get("classification", "unknown"),
        "explanation": final_analysis.get("explanation", ""),
        "red_flags": final_analysis.get("red_flags", []),
        "heuristic_score": h_score,
        "heuristic_flags": heuristic.get("heuristic_flags", []),
        "used_llm": True,
        "timestamp": datetime.now().isoformat()
    }

# ──────────────────────────────────────────────
# Health Endpoint
# ──────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():

    return jsonify({
        "status": "ok",
        "service": "SENTINEL API",
        "timestamp": datetime.now().isoformat()
    }), 200

# ──────────────────────────────────────────────
# Main Analysis Endpoint
# ──────────────────────────────────────────────
@app.route('/api/analyze', methods=['POST'])
def analyze():

    try:

        if not request.is_json:
            return jsonify({
                "error": "Content-Type must be application/json"
            }), 400

        data = request.json

        sender = data.get('sender', 'unknown@unknown.com')
        subject = data.get('subject', '[No Subject]')
        body = data.get('text', '')

        if not body:
            return jsonify({
                "error": "Missing 'text' field"
            }), 400

        logger.info(f"Analyzing email from {sender}")

        result = analyze_email(sender, subject, body)

        return jsonify(result), 200

    except Exception as e:

        logger.error(f"Analysis error: {e}", exc_info=True)

        return jsonify({
            "error": str(e),
            "classification": "unknown",
            "risk_score": 50
        }), 500

# ──────────────────────────────────────────────
# Config Endpoint
# ──────────────────────────────────────────────
@app.route('/api/config', methods=['GET'])
def config():

    return jsonify({
        "ai_model": AI_MODEL,
        "endpoints": {
            "health": "/health",
            "analyze": "/api/analyze",
            "config": "/api/config"
        }
    }), 200

# ──────────────────────────────────────────────
# Error Handlers
# ──────────────────────────────────────────────
@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "error": "Endpoint not found"
    }), 404

@app.errorhandler(500)
def internal_error(error):

    logger.error(f"Internal server error: {error}")

    return jsonify({
        "error": "Internal server error"
    }), 500

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
if __name__ == '__main__':

    logger.info("Starting SENTINEL API Server...")
    logger.info(f"AI Model: {AI_MODEL}")
    logger.info("Listening on http://0.0.0.0:5000")

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )
