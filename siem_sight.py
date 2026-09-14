import re
import json
import os

class SIEMSight:
    def __init__(self, log_file):
        self.log_file = log_file
        self.rules = {
            "SQL Injection": {
                "pattern": r"(SELECT|UNION|INSERT|DELETE|OR 1=1|'--|<script>)",
                "severity": "HIGH"
            },
            "XSS Attack": {
                "pattern": r"(<script>|javascript:|alert\(|onerror=)",
                "severity": "HIGH"
            },
            "Path Traversal": {
                "pattern": r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd)",
                "severity": "CRITICAL"
            },
            "Brute Force / Failed Login": {
                "pattern": r"(401|Failed password|Unauthorized)",
                "severity": "MEDIUM"
            }
        }

    def analyze(self):
        if not os.path.exists(self.log_file):
            print(f"[-] Error: File {self.log_file} not found.")
            return []

        alerts = []
        print(f"[*] SIEMSight Engine Started - Analyzing: {self.log_file}\n" + "="*55)

        with open(self.log_file, "r") as file:
            for line_num, line in enumerate(file, 1):
                for threat, config in self.rules.items():
                    if re.search(config["pattern"], line, re.IGNORECASE):
                        alerts.append({
                            "line": line_num,
                            "threat_type": threat,
                            "severity": config["severity"],
                            "raw_log": line.strip()
                        })

        return alerts

    def generate_report(self, alerts, output_file="security_report.json"):
        summary = {
            "total_threats": len(alerts),
            "critical": len([a for a in alerts if a["severity"] == "CRITICAL"]),
            "high": len([a for a in alerts if a["severity"] == "HIGH"]),
            "medium": len([a for a in alerts if a["severity"] == "MEDIUM"]),
            "alerts": alerts
        }

        with open(output_file, "w") as f:
            json.dump(summary, f, indent=4)

        print(f"\n[+] Analysis Complete!")
        print(f"[➔] Total Threats Found: {summary['total_threats']}")
        print(f"    - CRITICAL: {summary['critical']}")
        print(f"    - HIGH:     {summary['high']}")
        print(f"    - MEDIUM:   {summary['medium']}")
        print(f"[➔] Detailed JSON report saved to: {output_file}\n")

if __name__ == "__main__":
    engine = SIEMSight("sample_logs.txt")
    detected_alerts = engine.analyze()
    engine.generate_report(detected_alerts)
