"""
Risk Score Engine
=================
Menghitung skor risiko berdasarkan findings dari ZAP dan Nikto.

Skala skor: 0 - 100
  0  - 30  → Low Risk    (hijau)
  31 - 60  → Medium Risk (kuning)
  61 - 80  → High Risk   (oranye)
  81 - 100 → Critical    (merah)
"""

RISK_WEIGHTS = {
    "High":          10,
    "Critical":      15,
    "Medium":         5,
    "Low":            2,
    "Informational":  0,
    "Unknown":        1,
}

MAX_SCORE = 100


def calculate_risk_score(findings: list[dict]) -> dict:
    """
    Hitung risk score dari list findings.
    Return dict dengan score dan level.
    """
    if not findings:
        return {"score": 0, "level": "Low Risk", "color": "green"}

    raw_score = 0
    breakdown = {"High": 0, "Critical": 0, "Medium": 0, "Low": 0, "Informational": 0}

    for finding in findings:
        # Skip jika ini error entry
        if "error" in finding:
            continue

        risk_level = finding.get("risk", "Unknown")

        # Normalize risk level dari Nikto (kadang pakai angka OSVDB)
        if risk_level not in RISK_WEIGHTS:
            risk_level = "Unknown"

        weight = RISK_WEIGHTS.get(risk_level, 1)
        raw_score += weight

        # Hitung breakdown
        if risk_level in breakdown:
            breakdown[risk_level] += 1

    # Cap di 100
    final_score = min(raw_score, MAX_SCORE)

    # Tentukan level
    if final_score <= 30:
        level = "Low Risk"
        color = "green"
    elif final_score <= 60:
        level = "Medium Risk"
        color = "yellow"
    elif final_score <= 80:
        level = "High Risk"
        color = "orange"
    else:
        level = "Critical"
        color = "red"

    return {
        "score": final_score,
        "level": level,
        "color": color,
        "breakdown": breakdown,
        "total_findings": len(findings),
    }