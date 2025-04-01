import socket
import threading
import base64


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
                    results.append(f"[+] Port {port} ouvert – Service détecté : {encoded_banner}")
            except Exception as e:
                results.append(f"[+] Port {port} ouvert – Bannière non récupérable: {e}")

        sock.close()
    except Exception as e:
        print(f"[-] Erreur sur le port {port}: {e}")


def scan_ports(ip, start_port, end_port):
    threads = []
    results = []

    print(f"\n[***] Scan de {ip} sur les ports {start_port} à {end_port} [***]\n")

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=grab_banner, args=(ip, port, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    for result in results:
        print(result)

    with open("scan_results.txt", "w") as f:
        for result in results:
            f.write(result + "\n")


if __name__ == "__main__":
    target_ip = input("Entrez l'adresse IP à scanner : ")
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))
    scan_ports(target_ip, start_port, end_port)
