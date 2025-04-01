## Scanner de port

#Definir une fonction qui va tester un port specifique
import threading
from socket import socket


def scan_port(host, port):
    try:
        #creation d'un objet socket
        sock = socket(socket.AF_INET, socket.SOCK_STREAM)
        #Definir un delais pour eviter le TIMEOUT et blocage
        sock.settimeout(1)
        #Tentative de connexion sur le port (0 si la connexion a reussit)
        result = sock.connect_ex((host,port))
        #Si le port est ouvert (result == 0), on l'affiche
        if result == 0:
            print (f"[+] Port {port} ouvert")
        # On ferme le socket
        sock.close()
    except Exception as e:
        #Gestion des erreurs
        print(f"[-] Erreur sur le port {port}: {e}")
    # On demande a l'utilisateur l'adresse ip de la cible
target = input("Entrez l'ip a scanner")

#On demande la plage d'adresse a scanner
start_port = int(input("Port de debut"))
end_port = int(input("Port de fin"))
#on informe l'utilisateur qu'on commence le scan
print(f"\n[***] scan target {target} sur les ports {start_port} à {end_port} [***]\n")
for port in range (start_port, end_port +1):
    #on creer un thread (execution parallele) pour chaque port
    t = threading.Thread(target=scan_port, args=(target, port))
    t.start()