"""
SENTINEL API Server
Exposes HTTP endpoints for n8n and external integrations to analyze emails

Run: python sentinel_api.py
Endpoint: http://localhost:5000/api/analyze (POST)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import re
import requests
import logging
from datetime import datetime
from typing import Dict, Any, Tuple
import os
from groq import Groq


# ──────────────────────────────────────────────
#  Setup
# ──────────────────────────────────────────────
app = Flask(__name__)
groq_client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)
CORS(app)  # Allow requests from n8n

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────
AI_MODEL = "llama3-70b-8192"  # Change to mistral, neural-chat, etc. for speed

# Phishing detection patterns
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
        r"from (amazon|apple|google|bank|paypal|microsoft)",
        r"official notice",
        r"security alert",
        r"support team"
    ],
    "grammar_errors": [
        r"grammer|spelling|broken english|typo"  # heuristic
    ]
}

SPAM_KEYWORDS = [
    "viagra", "cialis", "casino", "lottery", "prize",
    "click here", "buy now", "limited offer", "claim reward",
    "you have won", "congratulations", "act now"
]

# ──────────────────────────────────────────────
#  Heuristic Analysis (Fast Fallback)
# ──────────────────────────────────────────────
def heuristic_analysis(sender: str, subject: str, body: str) -> Dict[str, Any]:
    """
    Quick heuristic analysis before calling LLM
    Returns early if pattern matches are strong
    """
    score = 0
    flags = []
    
    text_lower = (sender + " " + subject + " " + body).lower()
    
    # Check phishing patterns
    for category, patterns in PHISHING_PATTERNS.items():
        matches = [p for p in patterns if re.search(p, text_lower, re.I)]
        if matches:
            score += len(matches) * 10
            flags.append(f"{category}: {', '.join(matches[:2])}")
    
    # Check spam keywords
    spam_count = sum(1 for keyword in SPAM_KEYWORDS if keyword in text_lower)
    if spam_count > 0:
        score += spam_count * 5
        flags.append(f"spam_keywords: found {spam_count}")
    
    # Suspicious sender domain
    if "@" in sender:
        domain = sender.split("@")[1].lower()
        if domain in ["suspicious.com", "phishing-site.com", "temp-mail.com"]:
            score += 30
            flags.append(f"known_malicious_domain: {domain}")
    
    # Very short email (suspicious)
    if len(body) < 50:
        score += 5
        flags.append("very_short_email")
    
    # All caps subject (spam indicator)
    if subject.isupper() and len(subject) > 10:
        score += 10
        flags.append("all_caps_subject")
    
    score = min(score, 100)
    
    return {
        "heuristic_score": score,
        "heuristic_flags": flags,
        "use_llm": score < 50 or score > 80  # Use LLM if uncertain or very high
    }

# ──────────────────────────────────────────────
#  LLM Analysis (Accurate)
# ──────────────────────────────────────────────
def llm_analysis(sender: str, subject: str, body: str, max_retries: int = 3) -> Dict[str, Any]:
    """
    Use Ollama/LLM for detailed threat analysis
    """
    prompt = f"""You are a cybersecurity threat analyst. Analyze this email for phishing, malware, and security threats.

From: {sender}
Subject: {subject}
Body: {body[:1000]}  [truncated if longer]

Respond with ONLY valid JSON (no markdown, no extra text):
{{
  "risk_score": <number 0-100>,
  "classification": "<phishing|malware|spam|suspicious|legitimate>",
  "explanation": "<1-2 sentence explanation>",
  "red_flags": [<list of detected threats>]
}}"""

    for attempt in range(max_retries):
        try:
            logger.info(f"LLM Analysis attempt {attempt + 1}/{max_retries}")
            response = groq_client.chat.completions.create(
    model=AI_MODEL,
    messages=[
        {
            "role": "system",
            "content": "You are an advanced email security AI. Analyze emails for phishing, scams, malware, suspicious intent, fraud, urgency, and cyber threats. Respond ONLY in JSON format."
        },
        {
            "role": "user",
            "content": prompt
        }
    ],
    temperature=0.2
)

response_text = response.choices[0].message.content
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group(0))
                logger.info(f"LLM returned score: {analysis.get('risk_score')}")
                return {
                    "llm_analysis": analysis,
                    "llm_success": True
                }
        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.warning(f"LLM attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                logger.error("All LLM attempts failed")
                break
    
    # Fallback if LLM fails
    return {
        "llm_analysis": {
            "risk_score": 50,
            "classification": "unknown",
            "explanation": "Could not connect to analysis engine. Manual review recommended.",
            "red_flags": ["analysis_failed"]
        },
        "llm_success": False
    }

# ──────────────────────────────────────────────
#  Combined Analysis
# ──────────────────────────────────────────────
def analyze_email(sender: str, subject: str, body: str) -> Dict[str, Any]:
    """
    Combine heuristic + LLM analysis
    """
    # Step 1: Fast heuristic check
    heuristic = heuristic_analysis(sender, subject, body)
    h_score = heuristic.get("heuristic_score", 0)
    
    # Step 2: Decide if we need LLM
    needs_llm = heuristic.get("use_llm", True)
    
    if needs_llm:
        llm = llm_analysis(sender, subject, body)
        llm_score = llm.get("llm_analysis", {}).get("risk_score", h_score)
        
        # Combine scores (weighted average)
        final_score = int((h_score * 0.3 + llm_score * 0.7))
        final_analysis = llm.get("llm_analysis", {})
    else:
        # Use heuristic only if confident
        final_score = h_score
        final_analysis = {
            "risk_score": h_score,
            "classification": "spam" if h_score > 50 else "legitimate",
            "explanation": "Flagged by heuristic pattern matching",
            "red_flags": heuristic.get("heuristic_flags", [])
        }
    
    return {
        "risk_score": min(final_score, 100),
        "classification": final_analysis.get("classification", "unknown"),
        "explanation": final_analysis.get("explanation", ""),
        "red_flags": final_analysis.get("red_flags", []),
        "heuristic_score": h_score,
        "heuristic_flags": heuristic.get("heuristic_flags", []),
        "used_llm": needs_llm,
        "timestamp": datetime.now().isoformat()
    }

# ──────────────────────────────────────────────
#  API Endpoints
# ──────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    """
    Health check endpoint
    Returns 200 if API is running
    """
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "service": "SENTINEL Email Threat Analyzer"
    }), 200

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Main analysis endpoint
    
    Request:
    {
      "text": "email body content",
      "sender": "sender@example.com",
      "subject": "email subject line",
      "message_id": "unique_message_id" (optional),
      "timestamp": "2024-01-15T10:30:00Z" (optional)
    }
    
    Response:
    {
      "risk_score": 0-100,
      "classification": "phishing|malware|spam|suspicious|legitimate",
      "explanation": "brief explanation",
      "red_flags": ["flag1", "flag2"],
      "heuristic_score": 0-100,
      "heuristic_flags": ["pattern1", "pattern2"],
      "used_llm": true/false,
      "timestamp": "2024-01-15T10:30:05Z"
    }
    """
    try:
        # Validate request
        if not request.is_json:
            return jsonify({
                "error": "Content-Type must be application/json"
            }), 400
        
        data = request.json
        sender = data.get('sender', 'unknown@unknown.com').strip()
        subject = data.get('subject', '[No Subject]').strip()
        body = data.get('text', '').strip()
        message_id = data.get('message_id', 'unknown')
        
        # Validate inputs
        if not body:
            return jsonify({
                "error": "Missing 'text' field (email body)"
            }), 400
        
        if len(body) > 50000:  # Truncate very long emails
            body = body[:50000]
            logger.warning(f"Email {message_id} truncated to 50KB")
        
        logger.info(f"Analyzing email {message_id} from {sender}")
        
        # Perform analysis
        result = analyze_email(sender, subject, body)
        result["message_id"] = message_id
        
        logger.info(f"Analysis complete: score={result['risk_score']}, " +
                   f"class={result['classification']}")
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        return jsonify({
            "error": str(e),
            "risk_score": 50,
            "classification": "unknown"
        }), 500

@app.route('/api/analyze/batch', methods=['POST'])
def analyze_batch():
    """
    Batch analysis endpoint for multiple emails
    
    Request:
    {
      "emails": [
        {"text": "...", "sender": "...", "subject": "..."},
        ...
      ]
    }
    
    Response:
    {
      "results": [
        {"risk_score": ..., "classification": ..., ...},
        ...
      ],
      "processed": 3,
      "errors": 0
    }
    """
    try:
        data = request.json
        emails = data.get('emails', [])
        
        if not isinstance(emails, list) or len(emails) == 0:
            return jsonify({"error": "Invalid batch format"}), 400
        
        if len(emails) > 100:
            return jsonify({"error": "Batch size limited to 100 emails"}), 400
        
        results = []
        errors = 0
        
        for email in emails:
            try:
                result = analyze_email(
                    email.get('sender', 'unknown'),
                    email.get('subject', ''),
                    email.get('text', '')
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Batch item error: {e}")
                errors += 1
        
        return jsonify({
            "results": results,
            "processed": len(results),
            "errors": errors,
            "timestamp": datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Batch analysis error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/api/config', methods=['GET'])
def config():
    """
    Returns API configuration info
    """
    return jsonify({
        "ollama_host": OLLAMA_HOST,
        "ollama_model": OLLAMA_MODEL,
        "endpoints": {
            "health": "/health",
            "analyze": "/api/analyze",
            "batch_analyze": "/api/analyze/batch",
            "config": "/api/config"
        },
        "risk_thresholds": {
            "safe": "0-29",
            "medium": "30-54",
            "high": "55-79",
            "critical": "80-100"
        }
    }), 200

# ──────────────────────────────────────────────
#  Error Handlers
# ──────────────────────────────────────────────
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────
if __name__ == '__main__':
    logger.info("Starting SENTINEL API Server...")
    logger.info(f"Ollama Host: {OLLAMA_HOST}")
    logger.info(f"Ollama Model: {OLLAMA_MODEL}")
    logger.info("Listening on http://0.0.0.0:5000")
    logger.info("Endpoints:")
    logger.info("  - GET  /health")
    logger.info("  - POST /api/analyze")
    logger.info("  - POST /api/analyze/batch")
    logger.info("  - GET  /api/config")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,  # Set to True for development
        threaded=True
    )
