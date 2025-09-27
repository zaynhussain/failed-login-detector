"""
Failed SSH Login Detector — polished single-file version
- Increment 1: TXT / CSV / JSON outputs (suspicious IPs by threshold)
- Increment 2: ts, user, ip + events JSON (all & suspicious-only)
- Increment 3: Analytics (top IPs/users, attempts by hour, total)
- Increment 4: SQLite integration (create table, insert events, run SQL reports)
"""

import argparse
import csv
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


USERNAME_RE = re.compile(r"Failed password for (?:invalid user )?(\S+)")
IP_RE = re.compile(r"from (\d+\.\d+\.\d+\.\d+)\b")  # anchored on 'from ' to avoid port numbers etc.


def normalize_ts_three_tokens(parts):
    if len(parts) < 3:
        return None, None
    mon = parts[0]
    day_raw = parts[1]
    time_str = parts[2]
    try:
        day = f"{int(day_raw):02d}"
    except ValueError:
        return None, None
    ts = f"{mon} {day} {time_str}"
    try:
        dt = datetime.strptime(ts, "%b %d %H:%M:%S")
        hour = f"{dt.hour:02d}"
    except Exception:
        hour = None
    return ts, hour


def parse_log(path):
    """
    Parse the log file, return:
      - events: list of dicts {"ts","user","ip"} for each Failed password line
      - failed_attempts: dict ip -> count
    """
    failed_attempts = defaultdict(int)
    events = []

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "Failed password" not in line:
                continue

            parts = line.split()
            ts, _ = normalize_ts_three_tokens(parts)
            if not ts:
                # keep a placeholder if we truly can't parse tokens
                ts = "UNKNOWN_TS"

            user_m = USERNAME_RE.search(line)
            user = user_m.group(1) if user_m else "UNKNOWN"

            ip_m = IP_RE.search(line)
            ip = ip_m.group(1) if ip_m else "UNKNOWN"

            failed_attempts[ip] += 1
            events.append({"ts": ts, "user": user, "ip": ip})

    return events, failed_attempts

"""Increment 1: TXT / CSV / JSON for suspicious IPs only."""
def write_suspicious_outputs(failed_attempts, threshold):
    
    # TXT
    with open("flagged_ips.txt", "w", encoding="utf-8") as f:
        for ip, count in failed_attempts.items():
            if count >= threshold:
                f.write(f"{ip} - {count} failed attempts\n")

    # CSV
    with open("flagged_ips.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["IP", "Count"])
        for ip, count in failed_attempts.items():
            if count >= threshold:
                w.writerow([ip, count])

    # JSON
    flagged = [
        {"ip": ip, "count": count}
        for ip, count in failed_attempts.items()
        if count >= threshold
    ]
    with open("flagged_attempts.json", "w", encoding="utf-8") as f:
        json.dump(flagged, f, indent=4)

"""Increment 2: save all events and suspicious-only events."""
def write_events_json(events, failed_attempts, threshold):
    
    with open("flagged_events.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=4)

    suspicious_events = [
        e for e in events if failed_attempts.get(e["ip"], 0) >= threshold
    ]
    with open("flagged_suspicious_events.json", "w", encoding="utf-8") as f:
        json.dump(suspicious_events, f, indent=4)

 #Increment 3: top IPs/users, attempts by hour, total
def analytics_python(events):
    # Top IPs (exclude UNKNOWN)
    ip_counts = Counter(e["ip"] for e in events if e["ip"] != "UNKNOWN")
    with open("top_ips.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["IP", "Count"])
        for ip, cnt in ip_counts.most_common():
            w.writerow([ip, cnt])

    # Top users (exclude UNKNOWN)
    user_counts = Counter(e["user"] for e in events if e["user"] != "UNKNOWN")
    with open("top_users.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["User", "Count"])
        for user, cnt in user_counts.most_common():
            w.writerow([user, cnt])

    # Attempts by hour
    hour_counts = Counter()
    for e in events:
        parts = e["ts"].split()
        if len(parts) >= 3:
            _, hour = normalize_ts_three_tokens(parts[:3])
            if hour is not None:
                hour_counts[hour] += 1
    with open("attempts_by_hour.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Hour", "Count"])
        for h in [f"{i:02d}" for i in range(24)]:
            w.writerow([h, hour_counts.get(h, 0)])

    with open("totals.txt", "w", encoding="utf-8") as f:
        f.write(f"Total failed attempts: {len(events)}\n")


def sqlite_setup_and_insert(db_path, events, reset=False):
    """Increment 4: create DB, table, indexes, and insert events."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS attempts (
            ts   TEXT,
            user TEXT,
            ip   TEXT
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_attempts_user ON attempts(user)")

    if reset:
        cur.execute("DELETE FROM attempts")

    rows = [(e["ts"], e["user"], e["ip"]) for e in events]
    cur.executemany("INSERT INTO attempts (ts, user, ip) VALUES (?, ?, ?)", rows)
    conn.commit()
    return conn, cur
def sqlite_reports(cur):
    """Increment 4: SQL reports written to csv files."""
    # Top 10 IPs
    cur.execute("""
        SELECT ip, COUNT(*) AS count
        FROM attempts
        WHERE ip <> 'UNKNOWN'
        GROUP BY ip
        ORDER BY count DESC
        LIMIT 10
    """)
    rows = cur.fetchall()
    with open("sql_top_ips.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["IP", "Count"])
        w.writerows(rows)

    # Top users
    cur.execute("""
        SELECT user, COUNT(*) AS count
        FROM attempts
        WHERE user <> 'UNKNOWN'
        GROUP BY user
        ORDER BY count DESC
    """)
    rows = cur.fetchall()
    with open("sql_top_users.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["User", "Count"])
        w.writerows(rows)

    # Attempts by hour
    cur.execute("""
        SELECT SUBSTR(ts, 8, 2) AS hour, COUNT(*) AS count
        FROM attempts
        GROUP BY hour
        ORDER BY hour
    """)
    rows = cur.fetchall()
    with open("sql_attempts_by_hour.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Hour", "Count"])
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description="Detect failed SSH logins")
    ap.add_argument("--file", required=True, help="Path to the log file")
    ap.add_argument("--threshold", type=int, default=3,
                    help="How many failed attempts before flagging an IP")
    ap.add_argument("--reset-db", action="store_true",
                    help="Delete existing rows before inserting")
    ap.add_argument("--db-path", default="ssh_attempts.db",
                    help="SQLite database filename (default: ssh_attempts.db)")
    args = ap.parse_args()

    log_path = Path(args.file)
    if not log_path.exists():
        raise SystemExit(f"Log file not found: {log_path}")

    events, failed_attempts = parse_log(log_path)

    # Console heads-up for suspicious IPs
    for ip, count in failed_attempts.items():
        if count >= args.threshold:
            print(f"Suspicious IP: {ip} ({count} failed attempts)")


    # Increment 1: Suspicious outputs
   
    write_suspicious_outputs(failed_attempts, args.threshold)

  
    # Increment 2: Events JSON 
    write_events_json(events, failed_attempts, args.threshold)

    # Increment 3: Python analytics
    analytics_python(events)

    # Increment 4: SQLite + SQL reports
    conn, cur = sqlite_setup_and_insert(args.db_path, events, reset=args.reset_db)
    try:
        sqlite_reports(cur)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
