def risk_score(severity, exposure, criticality):
    values = [severity, exposure, criticality]

    for value in values:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 5:
            raise ValueError("Risk values must be integers between 1 and 5")

    return severity * exposure * criticality


def risk_label(score):
    if score >= 80:
        return "Critical"
    elif score >= 45:
        return "High"
    elif score >= 15:
        return "Medium"
    else:
        return "Low"