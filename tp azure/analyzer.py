from utils import parse_apache_log_line, detect_suspicious_activity

def read_log_file(filepath):
    with open(filepath, "r") as f:
        return [line.strip() for line in f.readlines()]

def generate_report(suspicious_data, output_file="report.txt"):
    with open(output_file, "w") as f:
        f.write("=== RAPPORT DE SÉCURITÉ ===\n\n")

        f.write("Brute-force détecté:\n")
        for ip, count in suspicious_data["brute_force"].items():
            f.write(f"- {ip} : {count} tentatives\n")

        f.write("\nAccès interdits (403):\n")
        for entry in suspicious_data["forbidden"]:
            f.write(f"- {entry['ip']} à {entry['datetime']} → {entry['request']}\n")

        f.write("\nScans potentiels:\n")
        for ip, count in suspicious_data["scans"].items():
            f.write(f"- {ip} : {count} requêtes suspectes\n")

def main():
    lines = read_log_file("logs/access.log")
    parsed_logs = [parse_apache_log_line(line) for line in lines if parse_apache_log_line(line)]
    suspicious_data = detect_suspicious_activity(parsed_logs)
    generate_report(suspicious_data)

if __name__ == "__main__":
    main()
