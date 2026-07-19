from config import RISK_WEIGHTS


def calculate_risk(threat_type: str) -> int:
    return RISK_WEIGHTS.get(threat_type, 1)
