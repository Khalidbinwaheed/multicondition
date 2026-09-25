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
    score = 0
    
    # Severity weighting
    if severity == "Critical":
        score += 30
    elif severity == "High":
        score += 24
    elif severity == "Medium":
        score += 16
    elif severity == "Low":
        score += 8
    else: # Informational
        score += 0
        
    # Exploitability weighting
    if exploitability == "Easy":
        score += 20
    elif exploitability == "Moderate":
        score += 10
    else: # Difficult
        score += 0
        
    # Asset Exposure weighting
    if exposure == "Internet-facing":
        score += 20
    elif exposure == "Internal":
        score += 10
    else: # Isolated
        score += 0
        
    # Detection Confidence weighting
    if confidence == "High":
        score += 20
    elif confidence == "Medium":
        score += 10
    else: # Low
        score += 0
        
    # Event Frequency weighting
    if frequency == "Repeated":
        score += 10
    elif frequency == "Occasional":
        score += 5
    else: # Single Event
        score += 0
        
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
