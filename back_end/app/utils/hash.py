import hashlib
import os
from typing import Optional

# Dictionnaire RAM qui conserve les hashs déjà calculés
# Clé = Chemin du fichier (ex: "C:\...\chrome.exe")
# Valeur = Empreinte SHA256 (ex: "a5f8e3...")
# la cle et la valeur sont des strings
_HASH_CACHE: dict[str, str] = {} 


def get_file_sha256(file_path: Optional[str]) -> Optional[str]:
    """
    Calcule l'empreinte SHA256 d'un fichier sur disque ou la récupère 
    depuis le cache RAM si elle a déjà été calculée.
    """
    # 1. Protection contre les chemins vides ou introuvables
    if not file_path or not os.path.exists(file_path):
        return None

    # 2. Vérification dans le cache RAM
    if file_path in _HASH_CACHE:
        return _HASH_CACHE[file_path]

    # 3. Calcul si première fois (Lecture du disque)
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        
        calculated_hash = sha256_hash.hexdigest()

        # Enregistrement dans le cache
        _HASH_CACHE[file_path] = calculated_hash
        return calculated_hash

    except (PermissionError, OSError):
        # En cas d'erreur d'accès de l'OS, on ne plante pas
        return None