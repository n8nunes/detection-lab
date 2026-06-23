def _s(val: any) -> str:
    """Coerces to string safely."""
    return str(val) if val is not None else ""

def clamp_int(val: any, min_val: int = 0, max_val: int = 100) -> int:
    """Coerces to bounded integer."""
    try:
        v = int(val)
        return max(min_val, min(v, max_val))
    except (ValueError, TypeError):
        return min_val

def sanitize_triage(response_dict: dict) -> dict:
    """Validates the Ollama response against the allowed Phase 5 schema."""
    raw_verdict = _s(response_dict.get("verdict")).title()
    verdict = raw_verdict if raw_verdict in ["Escalate", "Monitor", "False Positive"] else "Monitor"

    raw_conf = _s(response_dict.get("confidence")).upper()
    confidence = raw_conf if raw_conf in ["HIGH", "MEDIUM", "LOW"] else "LOW"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": _s(response_dict.get("reasoning", "No reasoning provided."))[:500]
    }