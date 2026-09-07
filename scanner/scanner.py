import json


def scan_configuration(config):
    findings = []

    if config["storage_public"] is True:
        findings.append({
            "issue": "Public Storage Access",
            "severity": "HIGH",
            "description": "Storage is publicly accessible.",
            "recommendation": "Disable public access and allow only authorized users."
        })

    if config["admin_access"] is True:
        findings.append({
            "issue": "Excessive Admin Access",
            "severity": "HIGH",
            "description": "Administrative access is enabled.",
            "recommendation": "Follow the principle of least privilege."
        })

    if config["ssh_open_to_world"] is True:
        findings.append({
            "issue": "SSH Open to Internet",
            "severity": "CRITICAL",
            "description": "SSH access is exposed to the public internet.",
            "recommendation": "Restrict SSH access to trusted sources."
        })

    if config["encryption_enabled"] is False:
        findings.append({
            "issue": "Encryption Disabled",
            "severity": "MEDIUM",
            "description": "Data encryption is not enabled.",
            "recommendation": "Enable encryption for stored data."
        })

    return findings


def calculate_risk(findings):
    risk_points = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1
    }

    total_score = 0

    for finding in findings:
        severity = finding["severity"]
        total_score += risk_points.get(severity, 0)

    if total_score >= 20:
        risk_level = "HIGH"
    elif total_score >= 10:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return total_score, risk_level


if __name__ == "__main__":
    with open("config/sample_config.json", "r") as file:
        config = json.load(file)

    results = scan_configuration(config)

    score, risk_level = calculate_risk(results)

    print("\n=== Cloud Security Scan Results ===\n")

    for finding in results:
        print(f"Issue: {finding['issue']}")
        print(f"Severity: {finding['severity']}")
        print(f"Description: {finding['description']}")
        print(f"Recommendation: {finding['recommendation']}")
        print("-" * 50)

    print(f"\nOverall Risk Score: {score}")
    print(f"Overall Risk Level: {risk_level}")