import re
from app.schemas.connection import NetworkConnection

# --- 1. MOTIFS SUSPECTS DANS LA LIGNE DE COMMANDE (Windows + Linux) ---
# Format : (regex_de_détection, points_de_pénalité, description_alerte)
SUSPICIOUS_CMD_PATTERNS = [
    # ---------- Windows / PowerShell ----------
    (r"-windowstyle\s+hidden", 30, "Lancement invisible (-WindowStyle Hidden)"),
    (r"-executionpolicy\s+bypass", 25, "Contournement des règles de sécurité PowerShell"),
    (r"-encodedcommand|-enc\b", 40, "Commande obfusquée/masquée détectée (Base64)"),
    (r"urlcache\s+-split", 40, "Détournement d'outil système (certutil) pour téléchargement"),
    (r"downloadstring|downloadfile", 35, "Instruction de téléchargement distant dans la commande"),
    (r"-noprofile|-nop\b", 15, "Contournement du profil utilisateur"),

    # ---------- Linux / Unix ----------
    (r"/dev/tcp/|/dev/udp/", 45, "Reverse shell détecté via /dev/tcp (Bash)"),
    (r"\bnc\b[^|]*-e\s|\bncat\b[^|]*-e\s", 45, "Reverse shell détecté (netcat -e)"),
    (r"(curl|wget)[^|;]+\|\s*(bash|sh|python)", 40, "Téléchargement puis exécution directe (pipe vers un shell)"),
    (r"base64\s+(-d|--decode).*\|\s*(bash|sh)", 40, "Commande encodée en Base64 exécutée via un shell"),
    (r"chmod\s+(\+x|777)\s", 20, "Attribution de droits d'exécution suspecte"),
    (r"ld_preload=", 35, "Injection de bibliothèque via LD_PRELOAD"),
    (r"/tmp/[^\s]+\.(sh|py|elf|bin|out)\b", 20, "Exécution d'un script depuis /tmp (zone non persistante)"),
    (r"python[23]?\s+-c\s+.*(socket|subprocess|os\.system)", 35, "Reverse shell / exécution système via Python"),
]

# --- 2. DOSSIERS SYSTÈME OFFICIELS ATTENDUS (Windows + Linux) ---
VALID_SYSTEM_PATHS = [
    # Windows
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    # Linux / Unix
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/bin/",
    "/sbin/",
    "/snap/",
]

# Outils sensibles qui doivent OBLIGATOIREMENT provenir d'un dossier système officiel
SENSITIVE_BINARIES = [
    # Windows
    "powershell.exe", "cmd.exe", "svchost.exe", "certutil.exe",
    # Linux
    "bash", "sh", "dash", "nc", "ncat", "netcat", "python", "python3", "perl", "sshd",
]


def analyze_connection(connection: NetworkConnection) -> NetworkConnection:
    """
    Vérifie et analyse une connexion réseau (compatible Windows & Linux).
    Calcule un score de risque (0 à 100) et génère une liste d'alertes explicites.
    """
    score = 0
    alerts: list[str] = []

    cmdline_lower = (connection.cmdline or "").lower()
    path_lower = (connection.process_path or "").lower()
    process_name_lower = connection.process_name.lower()

    # VÉRIFICATION 1 : Analyse des commandes cachées ou suspectes
    if connection.cmdline:
        for pattern, points, description in SUSPICIOUS_CMD_PATTERNS:
            if re.search(pattern, cmdline_lower):
                score += points
                alerts.append(f"CMDLINE SUSPECTE : {description}")

    # VÉRIFICATION 2 : Usurpation d'identité / Emplacement anormal
    if process_name_lower in SENSITIVE_BINARIES and connection.process_path:
        is_in_valid_path = any(path_lower.startswith(valid_path) for valid_path in VALID_SYSTEM_PATHS)
        if not is_in_valid_path:
            score += 45
            alerts.append(
                f"ANOMALIE D'EMPLACEMENT : {connection.process_name} s'exécute hors du dossier officiel ({connection.process_path})"
            )

    # VÉRIFICATION 3 : Volume de trafic anormal (Ratio d'exfiltration)
    if connection.bytes_sent > 10_000_000 and connection.bytes_recv < 100_000:
        score += 20
        alerts.append("TRAFIC ANORMAL : Envoi massif de données suspect (exfiltration potentielle)")

    connection.risk_score = min(score, 100)
    connection.alerts = alerts

    return connection