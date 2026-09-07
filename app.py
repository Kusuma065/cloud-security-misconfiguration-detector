from flask import Flask, render_template, send_file
import json
import os
from datetime import datetime

from scanner.scanner import scan_configuration, calculate_risk

app = Flask(__name__)


@app.route("/")
def dashboard():
    with open("config/sample_config.json", "r") as file:
        config = json.load(file)

    findings = scan_configuration(config)
    score, risk_level = calculate_risk(findings)

    return render_template(
        "dashboard.html",
        config=config,
        findings=findings,
        score=score,
        risk_level=risk_level
    )


@app.route("/scan", methods=["POST"])
def scan():
    with open("config/sample_config.json", "r") as file:
        config = json.load(file)

    findings = scan_configuration(config)

    score, risk_level = calculate_risk(findings)

    report = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": score,
        "risk_level": risk_level,
        "total_issues": len(findings),
        "findings": findings
    }

    with open("reports/security_report.json", "w") as file:
        json.dump(report, file, indent=4)

    return render_template(
        "dashboard.html",
        config=config,
        findings=findings,
        score=score,
        risk_level=risk_level
    )

@app.route("/report")
def report():
    return send_file(
        "reports/security_report.json",
        as_attachment=True,
        download_name="cloud_security_report.json"
    )
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )