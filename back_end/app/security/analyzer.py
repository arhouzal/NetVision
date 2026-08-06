import re
from app.schemas.connection import NetworkConnection

# --- 1. MOTIFS SUSPECTS DANS LA LIGNE DE COMMANDE (LOLBins & Obfuscation) ---
# Format : (regex_de_détection, points_de_pénalité, description_alerte)
SUSPICIOUS_CMD_PATTERNS = [
    (r"-windowstyle\s+hidden", 30, "Lancement invisible (-WindowStyle Hidden)"),
    (r"-executionpolicy\s+bypass", 25, "Contournement des règles de sécurité PowerShell"),
    (r"-encodedcommand|-enc", 40, "Commande obfusquée/masquée détectée (Base64)"),
    (r"urlcache\s+-split", 40, "Détournement d'outil système (certutil) pour téléchargement"),
    (r"downloadstring|downloadfile", 35, "Instruction de téléchargement distant dans la commande"),
    (r"-noprofile|-nop", 15, "Contournement du profil utilisateur"),
]

# --- 2. DOSSIERS SYSTÈME OFFICIELS ATTENDUS ---
VALID_SYSTEM_PATHS = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/"
]


def analyze_connection(connection: NetworkConnection) -> NetworkConnection:
    """
    Vérifie et analyse une connexion réseau.
    Calcule un score de risque (0 à 100) et génère une liste d'alertes explicites.
    """
    score = 0
    alerts: list[str] = []

    # Conversion en minuscules pour éviter les erreurs de casse (Windows ne fait pas la différence)
    cmdline_lower = (connection.cmdline or "").lower()
    path_lower = (connection.process_path or "").lower()
    process_name_lower = connection.process_name.lower()

    # ------------------------------------------------------------------
    # VÉRIFICATION 1 : Analyse des commandes cachées ou suspectes
    # ------------------------------------------------------------------
    if connection.cmdline:
        for pattern, points, description in SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmdline_lower):
                score += points
                alerts.append(f"CMDLINE SUSPECTE : {description}")

    # ------------------------------------------------------------------
    # VÉRIFICATION 2 : Usurpation d'identité / Emplacement anormal
    # ------------------------------------------------------------------
    # Outils sensibles du système qui doivent OBLIGATOIREMENT être dans System32
    sensitive_binaries = ["powershell.exe", "cmd.exe", "svchost.exe", "certutil.exe"]

    if process_name_lower in sensitive_binaries and connection.process_path:
        is_in_valid_path = any(path_lower.startswith(valid_path) for valid_path in VALID_SYSTEM_PATHS)
        if not is_in_valid_path:
            score += 45
            alerts.append(
                f"ANOMALIE D'EMPLACEMENT : {connection.process_name} s'exécute hors du dossier officiel ({connection.process_path})"
            )

    # ------------------------------------------------------------------
    # VÉRIFICATION 3 : Volume de trafic anormal (Ratio d'exfiltration)
    # ------------------------------------------------------------------
    # Exemple : Plus de 10 Mo envoyés pour très peu d'octets reçus
    if connection.bytes_sent > 10_000_000 and connection.bytes_recv < 100_000:
        score += 20
        alerts.append("TRAFIC ANORMAL : Envoi massif de données suspect (exfiltration potentielle)")

    # ------------------------------------------------------------------
    # AFFECTATION DU SCORE FINAL
    # ------------------------------------------------------------------
    # Le score final est plafonné à 100
    connection.risk_score = min(score, 100)
    connection.alerts = alerts

    return connection