import json
import requests
from rich.console import Console

console = Console()
OLLAMA_URL = "http://localhost:11434/api/generate"

def generate_triage(payload: dict) -> dict:
    """Calls Ollama locally using the Phase 5 constraints."""
    system_prompt = (
        "You are an AI triage assistant for a SOC. Evaluate the provided log match summary. "
        "Focus purely on the behavior, ignoring identities. Return JSON only with keys: "
        "'verdict' (Escalate, Monitor, False Positive), 'confidence' (HIGH, MEDIUM, LOW), "
        "and 'reasoning' (max 2 sentences)."
    )

    # Compress JSON heavily per roadmap specs
    compact_payload = json.dumps(payload, separators=(',', ':'))

    data = {
        "model": "llama3.1",  
        "system": system_prompt,
        "prompt": compact_payload,
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.05,
            "num_ctx": 4096,
            "top_p": 0.9
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=data, timeout=45)
        response.raise_for_status()
        result_text = response.json().get("response", "{}")
        return json.loads(result_text)
    except Exception as e:
        console.print(f"[dim yellow]Ollama call failed: {e}. Defaulting to Monitor.[/dim yellow]")
        return {"verdict": "Monitor", "confidence": "LOW", "reasoning": f"AI unavailable: {e}"}