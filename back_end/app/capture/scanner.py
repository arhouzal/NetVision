import psutil
from datetime import datetime
from app.schemas.connection import NetworkConnection
from app.utils.hash import get_file_sha256
from app.security.analyzer import analyze_connection


def get_active_connection() -> list[NetworkConnection]:

    # scanne les sockets du systemes et extrait les metadonnees resaux 
    # et processus.
    active_connections: list[NetworkConnection] = []

    # capture les connexions soit TCP ou UDP :
    raw_connection = psutil.net_connections(kind="inet")

    for conn in raw_connection:
        
        # --- NOUVELLE LOGIQUE DE FILTRAGE (TCP + UDP) ---
        # 1. Pour TCP (type 1) : on garde uniquement si le status est "ESTABLISHED"
        is_tcp_valid = (conn.type == 1 and conn.status == "ESTABLISHED")
        
        # 2. Pour UDP (type 2) : comme c'est un protocole sans connexion, il n'a 
        # pas d'état "ESTABLISHED". On l'accepte par défaut.
        is_udp_valid = (conn.type == 2)

        # on filtre seulement les connextion establishe (pour TCP) ou UDP avec une adresse distante.
        if (is_tcp_valid or is_udp_valid) and conn.raddr:
            # --- IP et Ports (Locaux et Distants) ---

            local_ip = conn.laddr.ip if conn.laddr else "127.0.0.1"
            local_port = conn.laddr.port if conn.laddr else 0
            
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            # --- Déduction du protocole (TCP / UDP) ---
            # SOCK_STREAM = TCP, SOCK_DGRAM = UDP
            protocol = "TCP" if conn.type == 1 else "UDP"

            # --- Inspection approfondie du processus ---
            pid = conn.pid
            proc_name = "Système / Inaccessible"
            proc_path = None
            username = None
            bytes_sent = 0
            bytes_recv = 0
            proc_hash = None
            
            # Initialisation par défaut pour éviter un crash si le PID est inaccessible
            cmdline = None 

            if pid:
                try:
                    proc = psutil.Process(pid) # renvoie un objet de classe Process représentant le processus identifié par le PID fourni. 
                    proc_name = proc.name()
                    proc_path = proc.exe()     # enplacement de binaire sur le disque
                    username = proc.username() # Ulitilisateur  proprietaire du pid

                    # --- EXTRACTION DES COMPTEURS DU VOLUME DE TRAFIC ---
                    # io_counters() renvoie la quantité de données lues et écrites par le processus

                    #Volumetrie
                    try:
                        io = proc.io_counters()
                        bytes_sent = io.write_bytes  # Données envoyées
                        bytes_recv = io.read_bytes   # Données reçues
                    except (NotImplementedError, psutil.AccessDenied):
                         pass  # io_counters indisponible pour ce processus sur ce système

                    
                    # ---- APPEL DU MODULE ISOLE POUR LE SHA256
                    proc_hash = get_file_sha256(proc_path)

                    # partie de la verification de la manierre avec la quel
                    # le programe est lancer en exploitant le champ cmdline
                    # de chaque processus . alors la fonction suivant ;
                    # psutil.Process(pid).cmdline() :
                    #Cette méthode interroge le système d'exploitation pour récupérer les arguments de lancement. 
                    # Elle renvoie une liste de chaînes de caractères (list[str]).
                    #Exemple renvoyé par l'OS : 
                    # ["chrome.exe", "--incognito", "[https://google.com](https://google.com)"]
                    # ------ 1 ------ : en recupetre la liste[str]:

                    cmd_line = proc.cmdline()
                    # ----- 2 ------ : converstion sous forme d une seule chaine de caractrere :
                    if cmd_line:
                        cmdline = " ".join(cmd_line)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        proc_name = "Accès Refusé"

            # Creation de l Object complet valide qui vat subire la 
            # verification par le pydantic avant d etre envoie :

            # AJOUT pour UDP : Le status UDP est souvent "NONE" ou vide. 
            # S'il est vide, on force "NONE" pour ne pas bloquer Pydantic.
            final_status = conn.status if conn.status else "NONE"

            connection_entry = NetworkConnection(
             pid=pid,                      # Obligatoire (int | None)
             process_name=proc_name,        # Obligatoire (str)
             process_path=proc_path,        # Optionnel (str | None)
             username=username,            # Optionnel (str | None)
             cmdline=cmdline,              # Optionnel (str | None)
             local_ip=local_ip,            # Obligatoire (str)
             local_port=local_port,        # Obligatoire (int)
             remote_ip=remote_ip,          # Obligatoire (str)
             remote_port=remote_port,      # Obligatoire (int)
             protocol=protocol,            # Obligatoire (str)
             status=final_status,          # Obligatoire (str)
             bytes_sent=bytes_sent,        # Obligatoire (int)
             bytes_recv=bytes_recv,        # Obligatoire (int)
             process_hash=proc_hash,        # Optionnel (str | None)
             timestamp=datetime.now()       # oblicatoire 
            )
                   
            analyzed_entry = analyze_connection(connection_entry)              
            active_connections.append(analyzed_entry)

    # notre scanner (fonction) renvois une liste des object qui est definie dans le fichier 
    # ./app/schemas/connection.py
    return active_connections

"""
[ SYSTÈME D'EXPLOITATION ]
                              │
                              ▼
        1. SONDE DE CAPTURE (psutil + hash SHA256)
                              │
                              ▼
        2. MOTEUR D'ANALYSE (analyzer.py)
           Calcul du risk_score + Génération des alerts
                              │
             ┌────────────────┴────────────────┐
             │                                 │
             ▼                                 ▼
   [ SI SCORE DE RISQUE >= 35 ]      [ TOUTES LES CONNEXIONS ]
             │                                 │
             ▼                                 ▼
  3. REPOSITORY (alert_repository)    4. SERVICE WEBSOCKET
             │                                 │
             ▼                                 ▼
    Base SQLite (netvision.db)       Diffusion Temps Réel (RAM)
             │                                 │
             ▼                                 ▼
   5. ROUTE API REST (/alerts)       6. WEBSOCKET (/ws/stream)
             │                                 │
             └────────────────┬────────────────┘
                              ▼
                 [ FRONTEND DASHBOARD REACT ]
                 - Graphe Neuronal (WebSocket)
                 - Journal des Événements (API REST BDD)
"""

"""--------- strucutre final de notre obejct apres avoir verifier exemple :
{
  "pid": 4812,
  "process_name": "powershell.exe",
  "process_path": "C:\\Users\\Public\\powershell.exe",
  "process_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "cmdline": "powershell.exe -windowstyle hidden -executionpolicy bypass",
  "username": "DESKTOP\\User",

  "local_ip": "192.168.1.35",
  "local_port": 52140,
  "remote_ip": "185.220.101.5",
  "remote_port": 4444,
  "protocol": "TCP",
  "status": "ESTABLISHED",

  "bytes_sent": 12500000,
  "bytes_recv": 45000,
  "timestamp": "2026-08-06T01:30:00.123456",

  "risk_score": 95,
  "alerts": [
    "CMDLINE SUSPECTE : Lancement invisible (-WindowStyle Hidden)",
    "CMDLINE SUSPECTE : Contournement des règles de sécurité PowerShell",
    "ANOMALIE D'EMPLACEMENT : powershell.exe s'exécute hors du dossier officiel (C:\\Users\\Public\\powershell.exe)",
    "TRAFIC ANORMAL : Envoi massif de données suspect (exfiltration potentielle)"
  ],

  "country": null,  #via api de geographie
  "domain_name": null, # via api de DNS inverse
  "virustotal_score": null # via api de Virustotal
}
"""