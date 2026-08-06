from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class NetworkConnection(BaseModel):
    """
    Schéma Pydantic complet et unifié pour NetVision.
    Il valide et structure toutes les métadonnées système, réseau,
    cryptographiques et de sécurité pour chaque connexion active.
    """

    # =========================================================================
    # 1. IDENTIFICATION DU PROCESSUS (Système d'Exploitation)
    # =========================================================================
    pid: Optional[int] = Field(
        default=None, 
        description="Identifiant unique du processus système (PID)"
    )
    process_name: str = Field(
        default="Inconnu", 
        description="Nom de l'exécutable à l'origine de la connexion (ex: chrome.exe)"
    )
    process_path: Optional[str] = Field(
        default=None, 
        description="Chemin d'accès absolu au fichier sur le disque dur"
    )
    process_hash: Optional[str] = Field(
        default=None, 
        description="Empreinte cryptographique SHA256 unique du fichier exécutable"
    )
    cmdline: Optional[str] = Field(
        default=None, 
        description="Ligne de commande textuelle complète (arguments d'exécution)"
    )
    username: Optional[str] = Field(
        default=None, 
        description="Nom du compte utilisateur (OS) qui a lancé le programme"
    )

    # =========================================================================
    # 2. INFORMATIONS RÉSEAU (Sockets)
    # =========================================================================
    local_ip: str = Field(
        ..., 
        description="Adresse IP locale de la machine (ex: 192.168.1.35)"
    )
    local_port: int = Field(
        ..., 
        description="Port réseau source local ouvert sur la machine"
    )
    remote_ip: str = Field(
        ..., 
        description="Adresse IP distante du serveur de destination"
    )
    remote_port: int = Field(
        ..., 
        description="Port réseau distant (ex: 443 pour HTTPS, 80 pour HTTP)"
    )
    protocol: str = Field(
        default="TCP", 
        description="Protocole de transport utilisé (TCP ou UDP)"
    )
    status: str = Field(
        ..., 
        description="État de la socket réseau (ex: ESTABLISHED, LISTEN)"
    )

    # =========================================================================
    # 3. VOLUMÉTRIE & TRAFIC (Pour les statistiques et l'IA)
    # =========================================================================
    bytes_sent: int = Field(
        default=0, 
        description="Volume total d'octets envoyés par ce processus"
    )
    bytes_recv: int = Field(
        default=0, 
        description="Volume total d'octets reçus par ce processus"
    )

    # =========================================================================
    # 4. HORODATAGE (Traçabilité Temporelle)
    # =========================================================================
    timestamp: datetime = Field(
        default_factory=datetime.now, 
        description="Date et heure exactes de la capture de la connexion"
    )

    # =========================================================================
    # 5. MOTEUR DE SÉCURITÉ & ANALYSE DE RISQUE (Règles & Détéction)
    # =========================================================================
    risk_score: int = Field(
        default=0, 
        ge=0, 
        le=100, 
        description="Score de dangerosité évalué automatiquement de 0 (Sain) à 100 (Critique)"
    )
    alerts: list[str] = Field(
        default_factory=list, 
        description="Liste explicite des alertes de sécurité déclenchées par l'analyseur"
    )

    # =========================================================================
    # 6. ENRICHISSEMENT FUTUR (Modules Externes : GeoIP, DNS, VirusTotal)
    # =========================================================================
    country: Optional[str] = Field(
        default=None, 
        description="Code ou nom du pays de destination de l'IP distante (Module GeoIP)"
    )
    domain_name: Optional[str] = Field(
        default=None, 
        description="Nom de domaine lié à l'IP distante résolu par DNS inverse"
    )
    virustotal_score: Optional[int] = Field(
        default=None, 
        description="Score de dangerosité retourné par l'API VirusTotal via le SHA256"
    )




    """"
    1. Section Processus OS (pid, process_name, process_path, process_hash, cmdline, username)
À quoi ça sert ? Identifier précisément qui communique sur l'ordinateur.

Le rôle clé du process_hash et de la cmdline :

Le process_hash (SHA256) permet de vérifier l'empreinte digitale du fichier pour s'assurer qu'il s'agit du vrai programme et non d'un virus renommé.

La cmdline enregistre les paramètres secrets et les ordres donnés au programme au moment de son lancement (pour repérer les lancements cachés ou les téléchargements furtifs).

2. Section Réseau (local_ip, local_port, remote_ip, remote_port, protocol, status)
À quoi ça sert ? Définir la trajectoire du flux de communication.

Notation Pydantic ... (Trois points) : Les trois points signifient que ces données sont obligatoires. Si le scanner oublie de fournir la remote_ip ou le remote_port, Pydantic bloquera immédiatement l'objet et renverra une erreur explicite.

3. Section Volumétrie (bytes_sent, bytes_recv)
À quoi ça sert ? Mesurer la quantité de données échangées (en octets).

Pourquoi c'est important ? Cette métrique permet d'identifier les fuites ou exfiltrations de données : si un programme inconnu envoie 50 Mo de données sur Internet alors qu'il n'a rien reçu, le système signale une anomalie.

4. Section Horodatage (timestamp)
À quoi ça sert ? Conserver la date et l'heure exactes de chaque événement.

L'option default_factory=datetime.now : Cela demande à Pydantic d'exécuter la fonction datetime.now() au moment exact de la création de l'objet pour enregistrer l'instant précis du scan.

5. Section Sécurité (risk_score, alerts)
À quoi ça sert ? Stocker le résultat généré par notre module app/security/analyzer.py.

Règles de validation (ge=0, le=100) : Greater than or Equal (ge) et Less than or Equal (le) obligent le score de risque à être un entier compris strictement entre 0 et 100. Cela évite toute valeur incohérente dans le tableau de bord.

6. Section Enrichissement Futur (country, domain_name, virustotal_score)
À quoi ça sert ? Préparer l'application pour les fonctionnalités à venir (GeoIP pour localiser les serveurs distants sur une carte du monde, et VirusTotal pour interroger la base de données de réputation).

Optional[...] = None : Ces champs sont optionnels. Quand la connexion est scannée au départ, ces valeurs valent None (vide). Elles seront complétées plus tard par des services d'enrichissement en arrière-plan sans casser le code existant.

Pourquoi cette architecture est robuste ?
Validation automatique : Pydantic rejette automatiquement les types de données incorrects (ex: si un port réseau est envoyé sous forme de texte au lieu d'un nombre).

Compatibilité JSON : Cet objet se transforme très facilement en JSON (connection.model_dump_json()) pour être transmis directement aux WebSockets et à l'interface Frontend.

Evolutivité : Le contrat contient l'intégralité des besoins actuels et futurs du projet. Tu n'auras plus besoin de réécrire la structure de tes modèles.

┌────────────────────────────────────────────────────────────────────────┐
 │ ÉTAPE 1 : Capture brute (OS / psutil)                                 │
 │ Extract des données brutes (IP, PID, ports) depuis le système.        │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ ÉTAPE 2 : Préparation des variables (scanner.py)                      │
 │ Gestion des cas d'erreur (try/except) et affectation des valeurs.    │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ ÉTAPE 3 : La Validation Pydantic (connection.py)                      │
 │ Instanciation : NetworkConnection(...)                                │
 │                                                                        │
 │  • Champ obligatoire manquant / mauvais type ? ──> 💥 ValidationError │
 │  • Champ optionnel (`None` ou valeur valide) ? ──> ✅ Objet créé       │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ ÉTAPE 4 : Analyse de Sécurité (analyzer.py)                           │
 │ L'objet validé reçoit son score de risque (risk_score).                │
 └──────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ ÉTAPE 5 : Emplacement final dans la Liste                             │
 │ active_connections.append(analyzed_entry)                              │
 └────────────────────────────────────────────────────────────────────────┘
    """