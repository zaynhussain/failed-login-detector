# Failed SSH Login Detector  

A Python project that automatically parses SSH authentication logs to detect failed login attempts and suspicious IP addresses.  
The script takes messy raw log files and transforms them into structured, actionable reports for IT and cybersecurity teams.  

---

## About The Project  

Logs are one of the first places IT and security teams look when troubleshooting access problems or investigating brute-force attempts. The problem is that raw logs are hard to read, unstructured, and time-consuming to analyze.  

This project solves that problem by:  
- Automatically extracting IP addresses, timestamps, and usernames from SSH logs.  
- Flagging suspicious IPs with excessive failed attempts.  
- Saving results into multiple formats (TXT, CSV, JSON) for easy sharing.  
- Storing enriched log data in an SQLite database for historical analysis and quick queries.  
- Producing ready-made analytics reports (Top IPs, Targeted Usernames, Attempts by Hour).  

This helps IT and cyber teams cut down on manual log review time and focus directly on suspicious behavior.  

---

## Built With  

- Python  
- Regex  
- SQLite  
- CSV / JSON / TXT  

---

## Repository Structure  

Failed-SSH-Login-Detector/
│
├── failed_login_detector.py         # Main script
├── simulated_auth.log               # Sample log file (for testing/demo)
│
├── attempts_by_hour.csv             # [Output] Failed attempts grouped by hour
├── flagged_attempts.json            # [Output] Suspicious attempts in JSON
├── flagged_events.json              # [Output] All enriched events
├── flagged_ips.csv                  # [Output] Suspicious IPs in CSV format
├── flagged_ips.txt                  # [Output] Suspicious IPs in plain text
├── flagged_suspicious_events.json   # [Output] Only suspicious enriched events
├── sql_attempts_by_hour.csv         # [Output] SQL analytics: failed attempts by hour
├── sql_top_ips.csv                  # [Output] SQL analytics: top attacker IPs
├── sql_top_users.csv                # [Output] SQL analytics: most targeted users
├── ssh_attempts.db                  # [Output] SQLite database storing all attempts
├── top_ips.csv                      # [Output] Top attacker IPs (Counter-based analytics)
├── top_users.csv                    # [Output] Most targeted users (Counter-based analytics)
└── totals.txt                       # [Output] Total failed attempts count
```  

---

## Getting Started  

### Prerequisites  
- Python 3.x  

### Installation  

1. Clone the repo  
   ```bash
   git clone https://github.com/zaynhussain/Failed-SSH-Login-Detector.git
   cd Failed-SSH-Login-Detector
   ```

2. Run the script with your log file:  
   ```bash
   python3 failed_login_detector.py --file simulated_auth.log --threshold 3
   ```  

---

## Usage  

Raw log example:  
```log
Jul 25 13:10:01 localhost sshd[20245]: Failed password for invalid user root from 203.0.113.5 port 50266 ssh2
```

Processed output (Top IPs):  
```csv
IP,Count
203.0.113.5,42
192.168.1.150,18
10.0.0.55,9
```

Deliverables include:  
- `flagged_ips.txt` – Suspicious IPs in plain text  
- `flagged_ips.csv` – Suspicious IPs in CSV format  
- `flagged_attempts.json` – Suspicious attempts in JSON  
- `flagged_events.json` – All enriched login attempts  
- `ssh_attempts.db` – SQLite database of all attempts  
- `sql_top_ips.csv`, `sql_top_users.csv`, `sql_attempts_by_hour.csv` – Analytics reports  
- `totals.txt` – Total failed attempts count  

---

## Key Takeaways  

- Demonstrates practical log analysis skills applied to a real-world cybersecurity problem.  
- Automates the detection of brute-force attempts against SSH servers.  
- Proves ability to work with Python, Regex, SQLite, and multi-format data exports.  
- Bridges cybersecurity with IT operations — turning raw logs into clear, actionable insights.  
- Shows end-to-end thinking: raw data → enrichment → reporting → database storage.  

---

## Contact  

**Zayn Hussain**  
- [LinkedIn](https://www.linkedin.com/in/hussainzayn/)  
- [GitHub](https://github.com/zaynhussain)  

Project Link: [https://github.com/zaynhussain/Failed-SSH-Login-Detector](https://github.com/zaynhussain/Failed-SSH-Login-Detector)  
