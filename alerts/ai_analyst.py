import requests
import json

GROQ_API_KEY = "GROQ_API_KEY"
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"


def _call_gemini(prompt: str) -> str:
    """Calls Groq API — drop-in replacement for Gemini"""
    response = requests.post(
        GROQ_URL,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}"
        },
        json={
            "model":       "llama-3.3-70b-versatile",
            "messages":    [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens":  1500
        },
        timeout=20
    )
    data = response.json()
    if "error" in data:
        raise Exception(data["error"].get("message", "Groq error"))
    raw = data["choices"][0]["message"]["content"].strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return raw.strip()

def analyze_threat(alert_data: dict) -> dict:
    """
    Full forensic analysis of a detected alert.
    Returns structured JSON report.
    """
    prompt = f"""You are a senior cybersecurity analyst inside a real-time
Intrusion Detection System. An attack was just detected on a live network.
Analyze it deeply and return ONLY a JSON object — no markdown, no text outside JSON.

DETECTED ATTACK DATA:
- Source IP:       {alert_data.get('ip')}
- Threat Type:     {alert_data.get('threat_type')}
- Severity:        {alert_data.get('severity')}
- Protocol:        {alert_data.get('protocol', 'TCP')}
- Packets/sec:     {alert_data.get('packets_per_sec', 'N/A')}
- Bytes/sec:       {alert_data.get('bytes_per_sec', 'N/A')}
- Destination Port:{alert_data.get('dst_port', 'N/A')}
- Timestamp:       {alert_data.get('timestamp')}
- Country:         {alert_data.get('country', 'Unknown')}
- ISP:             {alert_data.get('isp', 'Unknown')}

Return exactly this JSON structure with detailed, specific answers:
{{
  "attack_summary": "3-4 sentence plain English summary of exactly what happened",
  "attack_type_explanation": "Detailed explanation of this attack type and how it works technically",
  "why_this_ip": "Is this likely a botnet, nation-state, script kiddie, automated scanner? Why?",
  "what_they_were_trying": "Specific goal — data theft, DDoS, ransomware staging, reconnaissance?",
  "threat_indicators": ["specific indicator 1", "specific indicator 2", "specific indicator 3", "specific indicator 4"],
  "immediate_actions": ["action 1", "action 2", "action 3", "action 4"],
  "remediation_steps": ["step 1", "step 2", "step 3", "step 4", "step 5"],
  "prevention": ["prevention 1", "prevention 2", "prevention 3", "prevention 4"],
  "severity_reason": "Detailed explanation of why this is rated {alert_data.get('severity')}",
  "mitre_technique": "MITRE ATT&CK technique ID and full name — e.g. T1595.001 Active Scanning",
  "mitre_tactic": "The MITRE tactic this falls under — e.g. Reconnaissance",
  "risk_level": "LOW or MEDIUM or HIGH or CRITICAL",
  "confidence": "e.g. 92% — percentage confidence in this classification",
  "attacker_sophistication": "LOW or MEDIUM or HIGH or NATION-STATE",
  "estimated_damage": "What damage could this cause if not stopped"
}}"""

    try:
        raw    = _call_gemini(prompt)
        return json.loads(raw)
    except Exception as e:
        print(f"[AI ANALYST] Error: {e}")
        return _fallback(alert_data)


def predict_next_attack(recent_alerts: list) -> dict:
    """
    Given a list of recent alerts, predicts the next likely attack.
    Called after every CRITICAL analysis.
    Returns a prediction dict.
    """
    if not recent_alerts:
        return {}

    # Summarize recent alerts for the prompt
    summary = "\n".join([
        f"- {a.get('Threat_Type','?')} from {a.get('Source_IP','?')} "
        f"[{a.get('Severity','?')}] at {a.get('Timestamp','?')}"
        for a in recent_alerts[-10:]
    ])

    prompt = f"""You are a predictive threat intelligence AI inside an IDS.
Based on the attack pattern below, predict what the attacker is likely to do next.
Return ONLY a JSON object — no markdown, no text outside JSON.

RECENT ATTACK HISTORY (newest last):
{summary}

Return exactly this JSON:
{{
  "prediction": "1-2 sentence description of the most likely next attack",
  "attack_type": "Name of the predicted attack type",
  "probability": "e.g. 78% — how likely this prediction is",
  "timeframe": "e.g. Within 10 minutes / Within 1 hour / Unknown",
  "reasoning": "Why you predict this based on the pattern",
  "ports_to_watch": ["port1", "port2"],
  "recommended_action": "Single most important thing to do right now",
  "threat_level": "LOW or MEDIUM or HIGH or CRITICAL"
}}"""

    try:
        raw = _call_gemini(prompt)
        return json.loads(raw)
    except Exception as e:
        print(f"[AI PREDICT] Error: {e}")
        return {}


def _fallback(alert_data: dict) -> dict:
    return {
        "attack_summary":          f"A {alert_data.get('threat_type')} attack from {alert_data.get('ip')}.",
        "attack_type_explanation": "Analysis unavailable.",
        "why_this_ip":             "Unknown",
        "what_they_were_trying":   "Unknown",
        "threat_indicators":       ["Detected by behavioral engine"],
        "immediate_actions":       ["Block the source IP", "Review packet logs"],
        "remediation_steps":       ["Investigate the source IP", "Review firewall rules"],
        "prevention":              ["Enable stricter firewall rules"],
        "severity_reason":         f"Rated {alert_data.get('severity')} by the detection engine.",
        "mitre_technique":         "Unknown",
        "mitre_tactic":            "Unknown",
        "risk_level":              alert_data.get("severity", "MEDIUM"),
        "confidence":              "N/A",
        "attacker_sophistication": "Unknown",
        "estimated_damage":        "Unknown",
    }