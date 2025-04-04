#!/usr/bin/env python3
# decrypt_total.py - Script de déchiffrement pédagogique

import os
import sys
from cryptography.fernet import Fernet


def decrypt_file(filepath, fernet):
    """Déchiffre un fichier en place"""
    try:
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        with open(filepath, 'wb') as f:
            f.write(decrypted_data)

        print(f"Fichier déchiffré: {filepath}")
        return True
    except Exception as e:
        print(f"Échec du déchiffrement de {filepath}: {str(e)}")
        return False


def decrypt_system(key):
    """Parcourt et déchiffre tous les fichiers accessibles"""
    fernet = Fernet(key)

    for root, dirs, files in os.walk('/'):
        for file in files:
            filepath = os.path.join(root, file)
            decrypt_file(filepath, fernet)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./decrypt_total.py <clé_de_déchiffrement>")
        sys.exit(1)

    key = sys.argv[1].encode()
    decrypt_system(key)
    print("Déchiffrement terminé.")