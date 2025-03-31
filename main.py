import platform
import subprocess

# on demande ip à l'utilisateur de nous fournir l'ip
ip = input("entrez une adresse ip à ping : ")
# on detecte l'os pour adapter la commande
param = "-n" if platform.system().lower() == "windows" else "-c"
#construction du ping dans un list
commande = ["ping", param, "1", ip]

print("Ping en cours")
#on execute le ping
try:
    result = subprocess.run(commande, stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        print("La cible est en ligne")
    else:
        print("Aucune reponse")
except Exception as e:
    print(f"Erreur lors du ping {e}")