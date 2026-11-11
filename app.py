import os
import re
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
from openai import OpenAI
from database import TriageDatabaseManager, DatabaseTransactionError

load_dotenv()

app = Flask(__name__, static_folder=".")
CORS(app)
db = TriageDatabaseManager()

class EnterpriseTriageAgent:
    """AI-901 & AI-103: Executes PII sanitization and routes classification to Local Ollama via OpenAI SDK."""

    def __init__(self):
        self.endpoint = os.getenv("AI_ENDPOINT", "http://localhost:11434/v1").strip()
        self.api_key = os.getenv("AI_API_KEY", "ollama").strip()
        self.model = os.getenv("AI_MODEL", "llama3.2:1b").strip()

    @staticmethod
    def sanitize_pii(raw_text: str) -> tuple[str, int]:
        """AI-901: Detects and redacts emails, SA phone numbers, and 13-digit SA IDs."""
        patterns = [
            (r"[\w\.-]+@[\w\.-]+\.\w+", "[REDACTED_EMAIL]"),
            (r"\b(?:\+27|0)[1-9][0-9]{8}\b", "[REDACTED_PHONE]"),
            (r"\b[0-9]{13}\b", "[REDACTED_SA_ID]")
        ]
        sanitized = raw_text
        total_redactions = 0
        for regex, replacement in patterns:
            matches = re.findall(regex, sanitized)
            total_redactions += len(matches)
            sanitized = re.sub(regex, replacement, sanitized)
        return sanitized, total_redactions

    def evaluate_ticket(self, raw_text: str) -> dict:
        redacted_text, pii_count = self.sanitize_pii(raw_text)

        try:
            client = OpenAI(base_url=self.endpoint, api_key=self.api_key, timeout=8.0)
            completion = client.chat.completions.create(
                model=self.model,
                response_format={"type": "json_object"},
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an IT support triage agent. Return ONLY valid JSON with three keys: "
                            "'category' ('Hardware Diagnostics', 'Network Infrastructure', 'Database Administration', or 'Cloud & Software Access'), "
                            "'sentiment' ('Negative (High Priority)', 'Neutral', or 'Positive'), "
                            "and 'confidence' (float between 0.80 and 0.99)."
                        )
                    },
                    {"role": "user", "content": redacted_text}
                ],
                temperature=0.1
            )
            parsed = json.loads(completion.choices[0].message.content)
            return {
                "redacted_text": redacted_text,
                "pii_count": pii_count,
                "category": parsed.get("category", "Hardware Diagnostics"),
                "sentiment": parsed.get("sentiment", "Neutral"),
                "confidence": float(parsed.get("confidence", 0.92)),
                "engine_used": f"Local Ollama ({self.model})"
            }
        except Exception:
            pass

        lower_text = redacted_text.lower()
        if any(k in lower_text for k in ["cat6", "wifi", "router", "packet", "dns", "switch", "network"]):
            category, conf = "Network Infrastructure", 0.93
        elif any(k in lower_text for k in ["ram", "motherboard", "blink", "ssd", "palmrest", "boot", "laptop"]):
            category, conf = "Hardware Diagnostics", 0.95
        elif any(k in lower_text for k in ["sql", "index", "database", "query", "deadlock", "backup"]):
            category, conf = "Database Administration", 0.91
        else:
            category, conf = "Cloud & Software Access", 0.86

        sentiment = "Negative (High Priority)" if any(k in lower_text for k in ["urgent", "critical", "broken", "down", "failed"]) else "Neutral"
        return {
            "redacted_text": redacted_text,
            "pii_count": pii_count,
            "category": category,
            "sentiment": sentiment,
            "confidence": conf,
            "engine_used": "Deterministic NLP Engine"
        }

agent = EnterpriseTriageAgent()

@app.route("/")
def serve_frontend():
    return send_from_directory(".", "index.html")

@app.route("/api/tickets", methods=["GET"])
def list_tickets():
    try:
        return jsonify({"status": "ok", "tickets": db.get_all_tickets()}), 200
    except DatabaseTransactionError as err:
        return jsonify({"status": "error", "message": str(err)}), 500

@app.route("/api/triage", methods=["POST"])
def process_ticket():
    body = request.get_json(silent=True) or {}
    raw_text = body.get("text", "").strip()
    if not raw_text:
        return jsonify({"status": "error", "message": "Ticket text is required."}), 400

    result = agent.evaluate_ticket(raw_text)
    saved_record = db.log_ticket(
        redacted_text=result["redacted_text"],
        pii_count=result["pii_count"],
        category=result["category"],
        sentiment=result["sentiment"],
        confidence=result["confidence"],
        engine_used=result["engine_used"]
    )
    return jsonify({"status": "ok", "ticket": saved_record}), 201

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)