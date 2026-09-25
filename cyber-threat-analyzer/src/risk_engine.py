SEVERITY_WEIGHTS = {
    "Critical": 30,
    "High": 24,
    "Medium": 16,
    "Low": 8,
    "Informational": 0
}

EXPLOITABILITY_WEIGHTS = {
    "Easy": 20,
    "Moderate": 10,
    "Difficult": 0
}

EXPOSURE_WEIGHTS = {
    "Internet-facing": 20,
    "Internal": 10,
    "Isolated": 0
}

CONFIDENCE_WEIGHTS = {
    "High": 20,
    "Medium": 10,
    "Low": 0
}

FREQUENCY_WEIGHTS = {
    "Repeated": 10,
    "Occasional": 5,
    "Single Event": 0
}


def calculate_risk_factors(
    severity: str,
    exploitability: str,
    exposure: str,
    confidence: str,
    frequency: str
) -> dict:
    """
    Calculates the individual contribution of each security parameter to the total risk score.
    Returns a dictionary of factor names and their integer score contributions.
    """
    severity_score = SEVERITY_WEIGHTS.get(severity, 0)
    exploitability_score = EXPLOITABILITY_WEIGHTS.get(exploitability, 0)
    exposure_score = EXPOSURE_WEIGHTS.get(exposure, 0)
    confidence_score = CONFIDENCE_WEIGHTS.get(confidence, 0)
    frequency_score = FREQUENCY_WEIGHTS.get(frequency, 0)

    return {
        "Vulnerability Severity": severity_score,
        "Exploitability": exploitability_score,
        "Asset Exposure": exposure_score,
        "Detection Confidence": confidence_score,
        "Event Frequency": frequency_score
    }


def calculate_risk_score(
    severity: str,
    exploitability: str,
    exposure: str,
    confidence: str,
    frequency: str
) -> int:
    """
    Calculates a deterministic educational risk score based on provided factors.
    """
    breakdown = calculate_risk_factors(
        severity, exploitability, exposure, confidence, frequency
    )
    score = sum(breakdown.values())
    return min(100, max(0, score))


def classify_risk(risk_score: int) -> dict:
    """
    Demonstrates Python if / elif / else multi-condition logic to classify a risk score.
    Returns a dictionary containing the results and the explanation of the condition trace.
    """
    # This is the core logical demonstration
    if risk_score >= 90:
        severity = "CRITICAL"
        matched_condition = "risk_score >= 90"
    elif risk_score >= 70:
        severity = "HIGH"
        matched_condition = "risk_score >= 70"
    elif risk_score >= 40:
        severity = "MEDIUM"
        matched_condition = "risk_score >= 40"
    elif risk_score >= 20:
        severity = "LOW"
        matched_condition = "risk_score >= 20"
    else:
        severity = "INFORMATIONAL"
        matched_condition = "else"

    # Generate the trace explanation
    conditions = [
        {"condition": "risk_score >= 90", "threshold": 90, "type": "if"},
        {"condition": "risk_score >= 70", "threshold": 70, "type": "elif"},
        {"condition": "risk_score >= 40", "threshold": 40, "type": "elif"},
        {"condition": "risk_score >= 20", "threshold": 20, "type": "elif"}
    ]
    
    trace_details = []
    explanation_parts = [f"The calculated risk score is {risk_score}."]
    
    matched = False
    for i, cond in enumerate(conditions):
        if matched:
            trace_details.append({"text": cond["condition"], "status": "NOT CHECKED", "symbol": "○", "class": "trace-untested"})
        else:
            if risk_score >= cond["threshold"]:
                trace_details.append({"text": cond["condition"], "status": "TRUE", "symbol": "✓", "class": "trace-true"})
                explanation_parts.append(f"The condition, {cond['condition']}, evaluated to True.")
                matched = True
            else:
                trace_details.append({"text": cond["condition"], "status": "FALSE", "symbol": "✗", "class": "trace-false"})
                if i == 0:
                    explanation_parts.append(f"The first condition, {cond['condition']}, evaluated to False.")
                else:
                    explanation_parts.append(f"The next condition, {cond['condition']}, evaluated to False.")
    
    if not matched:
        trace_details.append({"text": "else", "status": "EXECUTED", "symbol": "✓", "class": "trace-true"})
        explanation_parts.append("All previous conditions evaluated to False, so the `else` block was executed.")
    else:
        trace_details.append({"text": "else", "status": "NOT EXECUTED", "symbol": "○", "class": "trace-untested"})

    explanation_parts.append(f"Python therefore classified the event as {severity}.")
    
    return {
        "severity": severity,
        "score": risk_score,
        "matched_condition": matched_condition,
        "explanation": "\n\n".join(explanation_parts),
        "conditions": trace_details
    }
