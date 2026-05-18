"""
SENTINEL API - Ollama Only (Clean, Production-Ready)
Railway Deployment
"""

import os
import json
import re
import requests
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# ──────────────────────────────────────────────
#  CONFIGURATION - FROM RAILWAY ENV VARS
# ──────────────────────────────────────────────

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")
PORT = int(os.environ.get("PORT", 5000))
TIMEOUT = int(os.environ.get("TIMEOUT", "30"))

logger.info("=" * 60)
logger.info("SENTINEL API Starting")
logger.info(f"Ollama Host: {OLLAMA_HOST}")
logger.info(f"Ollama Model: {OLLAMA_MODEL}")
logger.info(f"Port: {PORT}")
logger.info(f"Timeout: {TIMEOUT}s")
logger.info("=" * 60)

# ──────────────────────────────────────────────
#  HEURISTIC PATTERNS
# ──────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "urgent", "immediate action", "act now", "verify account",
    "confirm identity", "suspended", "locked", "limited time",
    "click here", "download now", "update payment", "confirm details",
    "unusual activity", "security alert"
]

SPAM_KEYWORDS = [
    "viagra", "cialis", "casino", "lottery", "prize",
    "congratulations", "claim reward", "you have won", "limited offer",
    "buy now"
]

SUSPICIOUS_TLDS = [".xyz", ".ru", ".tk", ".top", ".cn", ".pw"]

# ──────────────────────────────────────────────
#  HEURISTIC ANALYSIS
# ──────────────────────────────────────────────

def heuristic_analysis(sender: str, subject: str, body: str) -> dict:
    """Fast pattern-based threat detection"""
    score = 0
    flags = []
    
    text_lower = (sender + " " + subject + " " + body).lower()
    
    # Check phishing keywords
    phishing_count = sum(1 for kw in PHISHING_KEYWORDS if kw in text_lower)
    if phishing_count > 0:
        score += phishing_count * 8
        flags.append(f"phishing_keywords: {phishing_count}")
    
    # Check spam keywords
    spam_count = sum(1 for kw in SPAM_KEYWORDS if kw in text_lower)
    if spam_count > 0:
        score += spam_count * 6
        flags.append(f"spam_keywords: {spam_count}")
    
    # Check suspicious sender domain
    if "@" in sender:
        domain = sender.split("@")[1].lower()
        
        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 20
                flags.append(f"suspicious_tld: {tld}")
                break
        
        # Long domain
        if len(domain) > 30:
            score += 10
            flags.append("long_domain")
        
        # Multiple hyphens
        if domain.count("-") >= 2:
            score += 8
            flags.append("multiple_hyphens")
    
    # All caps subject
    if subject == subject.upper() and len(subject) > 10:
        score += 10
        flags.append("all_caps_subject")
    
    # Very short email
    if len(body) < 50:
        score += 5
        flags.append("very_short_email")
    
    # URLs in body
    urls = re.findall(r'http[s]?://\S+', body)
    if urls:
        score += 3 * len(urls)
        flags.append(f"urls: {len(urls)}")
    
    score = min(max(score, 0), 100)
    
    return {
        "heuristic_score": score,
        "heuristic_flags": flags[:3]
    }

# ──────────────────────────────────────────────
#  OLLAMA LLM ANALYSIS
# ──────────────────────────────────────────────

def llm_analysis(sender: str, subject: str, body: str) -> dict:
    """AI-based threat analysis using Ollama"""
    
    # Truncate body if too long
    body_text = body[:800] if len(body) > 800 else body
    
    prompt = f"""You are a cybersecurity email threat analyst. Analyze this email for phishing, malware, and spam.

From: {sender}
Subject: {subject}
Body: {body_text}

Return ONLY valid JSON (no markdown):
{{
  "risk_score": <number 0-100>,
  "classification": "<phishing|malware|spam|suspicious|legitimate>",
  "explanation": "<brief explanation>",
  "red_flags": [<list of detected threats>]
}}"""

    try:
        logger.info(f"Calling Ollama: POST {OLLAMA_HOST}/api/generate")
        
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "temperature": 0.3
            },
            timeout=TIMEOUT
        )
        
        logger.info(f"Ollama response status: {response.status_code}")
        response.raise_for_status()
        
        result = response.json()
        response_text = result.get("response", "")
        
        logger.info(f"Ollama returned {len(response_text)} chars")
        
        # Extract JSON
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response_text, re.DOTALL)
        
        if json_match:
            analysis = json.loads(json_match.group(0))
            logger.info(f"LLM Success: score={analysis.get('risk_score')}")
            
            return {
                "success": True,
                "analysis": analysis
            }
        else:
            logger.error(f"No JSON found in response: {response_text[:200]}")
            return {
                "success": False,
                "error": "Invalid JSON in Ollama response"
            }
            
    except requests.exceptions.Timeout:
        logger.error(f"Ollama timeout after {TIMEOUT}s")
        return {"success": False, "error": "Ollama timeout"}
    
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Cannot connect to Ollama at {OLLAMA_HOST}: {e}")
        return {"success": False, "error": f"Cannot reach Ollama at {OLLAMA_HOST}"}
    
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error: {e}")
        return {"success": False, "error": "Ollama returned invalid JSON"}
    
    except Exception as e:
        logger.error(f"LLM analysis error: {e}", exc_info=True)
        return {"success": False, "error": str(e)}

# ──────────────────────────────────────────────
#  ANALYZE EMAIL
# ──────────────────────────────────────────────

def analyze_email(sender: str, subject: str, body: str) -> dict:
    """Combine heuristic + LLM analysis"""
    
    logger.info(f"Starting analysis: sender={sender[:30]}")
    
    # Heuristic first
    heuristic = heuristic_analysis(sender, subject, body)
    h_score = heuristic.get("heuristic_score", 0)
    logger.info(f"Heuristic score: {h_score}")
    
    # Try LLM
    llm = llm_analysis(sender, subject, body)
    
    if llm.get("success"):
        analysis = llm.get("analysis", {})
        llm_score = analysis.get("risk_score", h_score)
        logger.info(f"LLM score: {llm_score}")
        
        # Weighted blend: 30% heuristic + 70% LLM
        final_score = int((h_score * 0.3) + (llm_score * 0.7))
        logger.info(f"Final blended score: {final_score}")
        
        return {
            "risk_score": min(final_score, 100),
            "classification": analysis.get("classification", "unknown"),
            "explanation": analysis.get("explanation", ""),
            "red_flags": analysis.get("red_flags", []),
            "method": "llm_blend",
            "heuristic_score": h_score,
            "llm_score": llm_score,
            "timestamp": datetime.now().isoformat()
        }
    else:
        # Fallback to heuristic
        logger.warning(f"LLM failed: {llm.get('error')}. Using heuristic only.")
        
        if h_score < 30:
            classification = "legitimate"
        elif h_score < 55:
            classification = "suspicious"
        elif h_score < 80:
            classification = "phishing"
        else:
            classification = "malware"
        
        return {
            "risk_score": h_score,
            "classification": classification,
            "explanation": f"Heuristic analysis only (LLM unavailable: {llm.get('error')})",
            "red_flags": heuristic.get("heuristic_flags", []),
            "method": "heuristic_only",
            "timestamp": datetime.now().isoformat()
        }

# ──────────────────────────────────────────────
#  ROUTES
# ──────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    logger.info("Health check requested")
    
    try:
        # Test Ollama connection
        ollama_status = "unavailable"
        try:
            r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
            if r.ok:
                ollama_status = "ok"
                logger.info("Ollama connection OK")
            else:
                logger.warning(f"Ollama returned {r.status_code}")
        except Exception as e:
            logger.warning(f"Ollama connection failed: {e}")
        
        return jsonify({
            "status": "ok",
            "service": "SENTINEL API",
            "timestamp": datetime.now().isoformat(),
            "ollama_host": OLLAMA_HOST,
            "ollama_model": OLLAMA_MODEL,
            "ollama_status": ollama_status
        }), 200
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Main analysis endpoint"""
    try:
        if not request.is_json:
            logger.warning("Request is not JSON")
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.json
        sender = data.get('sender', 'unknown@unknown.com').strip()
        subject = data.get('subject', '').strip()
        body = data.get('text', '').strip()
        message_id = data.get('message_id', 'unknown')
        
        logger.info(f"Analyze request: message_id={message_id}, sender={sender[:30]}")
        
        if not body:
            logger.warning("No text provided")
            return jsonify({"error": "Missing 'text' field"}), 400
        
        # Analyze
        result = analyze_email(sender, subject, body)
        result["message_id"] = message_id
        
        logger.info(f"Analysis complete: score={result['risk_score']}, method={result['method']}")
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Analyze error: {e}", exc_info=True)
        return jsonify({
            "error": str(e),
            "risk_score": 50,
            "classification": "unknown"
        }), 500

@app.route('/api/config', methods=['GET'])
def config():
    """Configuration info"""
    return jsonify({
        "service": "SENTINEL API",
        "version": "3.0",
        "mode": "ollama_only",
        "ollama_host": OLLAMA_HOST,
        "ollama_model": OLLAMA_MODEL,
        "timeout_seconds": TIMEOUT,
        "endpoints": ["/health", "/api/analyze", "/api/config"]
    }), 200

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

if __name__ == '__main__':
    logger.info(f"Starting Flask on 0.0.0.0:{PORT}")
    app.run(
        host='0.0.0.0',
        port=PORT,
        debug=False,
        threaded=True
    )
