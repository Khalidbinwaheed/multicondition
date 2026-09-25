def validate_inputs(inputs: dict) -> bool:
    """
    Validates that the input dictionary contains all necessary cybersecurity
    event keys required to calculate a risk score.
    """
    required_keys = ["severity", "exploitability", "exposure", "confidence", "frequency"]
    return all(key in inputs for key in required_keys)
