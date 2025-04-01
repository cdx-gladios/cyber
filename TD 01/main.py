#scan de ports
#Definir une fonction qui va tester un port spécifique
from socket import socket


def scan_port(host, port):
    try:
        #creation d'un objet socket
        sock = socket(socket.AF_INET, socket.SOCK_STREAM)
        #defninir un delai pour eviter le timeout et blocage
        sock.settimeout(1)
        #tentative de connexion sur le port (0 si la connexion à résuisse)
        result = sock.connect_ex((host, port))
        #si le port est ouvert (result == 0), on l'affiche
        if result == 0:
            print (f"[+] Port {port} ouvert")
        #on ferme le socket
        sock.close()
    except Exception as e:
        #gestion des erreurs
    print(f"[-] Erreur sur le port {port}: {e}")
    #on demande à l'utilisateur l'ip de la cible
target = input("Entrez l'ip à scanner")

#On demande la plage d'adresse a scanner
start_port = int(input("Port de début"))
end_port = int(input("Port de fin"))

#On informe l'utilisateur qu'on commence le scan
print(f"\n[***] scan target {target} sur les ports {start_port} à {end_port} [***]\n")
for port in range(start_port, end_port+1):
    #on créer un thread (exec parallele) pour chaque port
    t = threading.Thread(target=scan_port, args=(target, port))
    t.start()