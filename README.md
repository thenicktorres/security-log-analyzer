Linux Security Log Analyzer 🔐

Python-Based Security Log Analysis & Threat Detection Tool

What is Linux Security Log Analyzer?

Linux Security Log Analyzer is a Python-based security tool that parses and analyzes Linux authentication logs (/var/log/auth.log) to identify potential security threats such as brute force attacks, anomalous login times, and multi-IP account targeting.

The tool simulates SIEM-style detection logic and generates automated security reports in CSV or PDF format, including a calculated risk level and login activity visualization.


Features
Regex Log Parsing — Extracts timestamp, hostname, process, login status, username, and source IP
Brute Force Detection — Flags IPs with more than 5 failed login attempts within 5 minutes
Anomalous Login Detection — Detects login activity outside business hours (9 PM – 6 AM)
Multi-IP Account Targeting Detection — Detects multiple IPs attempting to access the same account
Top Suspicious IP Summary — Displays top 5 suspicious IPs in CLI
CSV Report Export — Raw list of flagged events
PDF Security Report — Professional report with risk level assessment
Login Activity Visualization — Failed vs Successful login chart
Scalable Log Processing — Generator-based parsing supports large log files (1GB+)
CLI Interface — Run analysis from terminal using arguments

Tech Stack
Layer	Technology
Language	Python 3
Log Parsing	Regex
Data Processing	Pandas
Visualization	Matplotlib
Report Generation	ReportLab
CLI	Argparse

Project Structure
security-log-analyzer/
│
├── main.py              # CLI entry point
├── parser.py            # Log parsing engine (Regex + Generator)
├── analyzer.py          # Threat detection logic
├── report_gen.py        # CSV + PDF report generation
├── requirements.txt     # Python dependencies
├── README.md            # Project documentation
├── output/              # Generated reports
└── .git/                # Git repository

Detection Logic
Threat Type	Description
Brute Force Attack	More than 5 failed login attempts from same IP within 5 minutes
Anomalous Login	Login attempts outside business hours (9 PM – 6 AM)
Multi-IP Targeting	Multiple IP addresses attempting to log into the same account
Risk Level Calculation

Risk level is calculated based on:

Number of brute force IPs detected
Number of accounts targeted by multiple IPs
Number of anomalous login attempts
Score	Risk Level
0–10	LOW
11–20	MEDIUM
21+	HIGH


CLI Output

Top 5 Suspicious IPs:
192.168.1.10    12 failed attempts
10.0.0.5        9 failed attempts

Generated Reports

output/security_report.csv
output/security_report.pdf
Future Improvements
GeoIP lookup for IP addresses
IP reputation / blacklist checking
Email alerting for high-risk activity
Real-time log monitoring (tail -f)
Docker container deployment
Unit testing with pytest
Web dashboard for visualization
SIEM integration (Splunk / ELK)
Author

Nick Torres
GitHub: https://github.com/thenicktorres

License

This project is licensed under the MIT License.