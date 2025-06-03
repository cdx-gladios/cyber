import re
from collections import defaultdict
from datetime import datetime

LOG_FILE = "logs/access.log"
REPORT_FILE = "report.txt"

# Regex pour les logs Apache communs
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) \S+'
)

def parse_log_line(line):
    match = LOG_PATTERN.match(line)
    if match:
        data = match.groupdict()
        try:
            data["datetime"] = datetime.strptime(data["datetime"].split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            return None
        return data
    return None

def detect_suspicious_activity(logs):
    brute_force = defaultdict(int)
    forbidden = []
    scans = defaultdict(int)

    for entry in logs:
        ip = entry["ip"]
        status = int(entry["status"])
        request = entry["request"].lower()

        if status == 403:
            forbidden.append(entry)

        if status == 401 or "login" in request:
            brute_force[ip] += 1

        if "/phpmyadmin" in request or "/wp-" in request or "/.env" in request:
            scans[ip] += 1

    return {
        "brute_force": {ip: count for ip, count in brute_force.items() if count > 5},
        "forbidden": forbidden,
        "scans": {ip: count for ip, count in scans.items() if count > 2}
    }

def generate_report(data):
    with open(REPORT_FILE, "w") as f:
        f.write("=== RAPPORT DE SÉCURITÉ ===\n\n")

        f.write("🔐 Brute-force détecté:\n")
        if data["brute_force"]:
            for ip, count in data["brute_force"].items():
                f.write(f" - {ip} : {count} tentatives\n")
        else:
            f.write(" Aucun comportement suspect détecté.\n")

        f.write("\n🚫 Accès interdits (403):\n")
        if data["forbidden"]:
            for entry in data["forbidden"]:
                f.write(f" - {entry['ip']} à {entry['datetime']} → {entry['request']}\n")
        else:
            f.write(" Aucun accès interdit trouvé.\n")

        f.write("\n🕵️ Scans suspects:\n")
        if data["scans"]:
            for ip, count in data["scans"].items():
                f.write(f" - {ip} : {count} requêtes suspectes\n")
        else:
            f.write(" Aucun scan détecté.\n")

def main():
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Fichier non trouvé: {LOG_FILE}")
        return

    parsed_logs = [parse_log_line(line) for line in lines]
    parsed_logs = [entry for entry in parsed_logs if entry is not None]

    suspicious_data = detect_suspicious_activity(parsed_logs)
    generate_report(suspicious_data)
    print(f"Rapport généré dans '{REPORT_FILE}'.")

if __name__ == "__main__":
    main()
