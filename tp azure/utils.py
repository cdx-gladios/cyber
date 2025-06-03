import re
from collections import defaultdict
from datetime import datetime

APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) \S+'
)

def parse_apache_log_line(line):
    match = APACHE_LOG_PATTERN.match(line)
    if match:
        data = match.groupdict()
        data["datetime"] = datetime.strptime(data["datetime"].split()[0], "%d/%b/%Y:%H:%M:%S")
        return data
    return None

def detect_suspicious_activity(parsed_logs):
    brute_force_attempts = defaultdict(int)
    forbidden_access = []
    scans = defaultdict(int)

    for entry in parsed_logs:
        ip = entry["ip"]
        status = int(entry["status"])
        request = entry["request"]

        if status == 403:
            forbidden_access.append(entry)

        if status == 401 or "login" in request.lower():
            brute_force_attempts[ip] += 1

        if request.endswith("/phpmyadmin") or "/wp-" in request:
            scans[ip] += 1

    return {
        "brute_force": {ip: count for ip, count in brute_force_attempts.items() if count > 5},
        "forbidden": forbidden_access,
        "scans": {ip: count for ip, count in scans.items() if count > 2}
    }
