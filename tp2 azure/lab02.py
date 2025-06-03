from scapy.all import sniff, DNSQR, DNS, IP
from datetime import datetime
import re
import signal
import sys
import os

# === Chargement de la blacklist ===
BLACKLIST = set()
try:
    with open("blacklist.txt", "r") as f:
        BLACKLIST = {line.strip().lower() for line in f if line.strip()}
except FileNotFoundError:
    print("Fichier blacklist.txt introuvable. Aucune détection blacklist possible.")

# === TLD suspects ===
SUSPICIOUS_TLDS = {".ru", ".xyz", ".top"}

# === Variables globales ===
alerts = []
query_count = {}

# === Fonction de scoring ===
def score_domain(domain, src_ip):
    score = 0
    domain = domain.lower()

    if domain in BLACKLIST or any(domain.endswith(bl) for bl in BLACKLIST):
        score += 80

    if len(domain) > 50:
        score += 10

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 5

    if re.match(r"^[a-z0-9]{12,}\.(ru|xyz|top)$", domain):
        score += 15

    now = datetime.now()
    key = (src_ip, now.strftime("%Y-%m-%d %H:%M"))
    query_count[key] = query_count.get(key, 0) + 1

    if query_count[key] > 10:
        score += 10

    return min(score, 100)

# === Fonction de blocage (défense active) ===
def block_ip(ip):
    print(f"[DEFENSE] Blocage de l'IP : {ip}")
    os.system(f"iptables -A INPUT -s {ip} -j DROP")

# === Traitement des paquets DNS ===
def process_packet(packet):
    if packet.haslayer(DNSQR) and packet.haslayer(IP) and packet.haslayer(DNS):
        if packet[DNS].qr != 0:  # Ne traiter que les requêtes (pas les réponses)
            return

        domain = packet[DNSQR].qname.decode().strip(".")
        src_ip = packet[IP].src
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        score = score_domain(domain, src_ip)

        if score > 0:
            status = "INFO"
            if score >= 80:
                status = "CRITICAL"
                block_ip(src_ip)
            elif score >= 50:
                status = "WARNING"

            alert = f"[{timestamp}] ALERT - IP: {src_ip} - Domain: {domain} - Score: {score} - Status: {status}"
            alerts.append(alert)
            print(alert)

# === Sauvegarde des rapports ===
def save_reports():
    with open("dns_alerts.log", "w") as f_log:
        for alert in alerts:
            f_log.write(alert + "\n")

    unique_ips = set()
    domains_contacted = set()
    max_score = 0

    for alert in alerts:
        parts = alert.split(" - ")
        ip = parts[1].split(": ")[1]
        domain = parts[2].split(": ")[1]
        score = int(parts[3].split(": ")[1])
        unique_ips.add(ip)
        domains_contacted.add(domain)
        max_score = max(max_score, score)

    with open("summary_report.txt", "w") as f_summary:
        f_summary.write("===== Résumé du LAB-02 - Analyse DNS =====\n")
        f_summary.write(f"IPs suspectes : {', '.join(unique_ips)}\n")
        f_summary.write(f"Domaines contactés : {', '.join(domains_contacted)}\n")
        f_summary.write(f"Score de suspicion maximal : {max_score}\n")

        if max_score >= 80:
            f_summary.write("Recommandation : Blocage immédiat de l'IP source\n")
        elif max_score >= 50:
            f_summary.write("Recommandation : Surveillance accrue\n")
        else:
            f_summary.write("Recommandation : Aucune action urgente\n")

# === Gestion CTRL+C ===
def signal_handler(sig, frame):
    print("\n[!] Arrêt manuel détecté. Génération des rapports...")
    save_reports()
    sys.exit(0)

# === Point d'entrée ===
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    print("📡 Surveillance DNS en cours... (CTRL+C pour arrêter)")
    sniff(filter="udp port 53", prn=process_packet, store=0)
