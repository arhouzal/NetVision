import asyncio
from typing import List
from fastapi import WebSocket
from sqlalchemy.orm import Session

# Importation des modules internes de l'application
from app.capture.scanner import get_active_connection
from app.repositories.alert_repository import AlertRepository
from app.repositories.whitelist_repository import WhitelistRepository
from app.schemas.connection import NetworkConnection
from app.database.session import get_connection


# =============================================================================
# 1. GESTIONNAIRE DE CONNEXIONS WEBSOCKET (ConnectionManager)
# =============================================================================
class ConnectionManager:
    """
    Cette classe gère le canal de communication en temps réel avec le Frontend.
    Elle garde en mémoire la liste de tous les navigateurs web (React) actuellement
    ouverts sur l'application et leur diffuse les données du réseau.
    """

    def __init__(self):
        # Liste contenant tous les sockets WebSockets actifs (les navigateurs connectés)
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """
        Accept la poignée de main (handshake) d'un nouveau navigateur
        et l'ajoute à la liste des destinataires actifs.
        """
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """
        Retire un navigateur de la liste lorsqu'il ferme l'onglet
        ou perd sa connexion réseau.
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, data: list):
        """
        Parcourt tous les navigateurs connectés et leur envoie
        le paquet de données réseau sous format JSON en simultané.
        """
        # On crée une copie de la liste pour éviter des erreurs si la liste change pendant l'envoi
        for connection in list(self.active_connections):
            try:
                # Envoi asynchrone des données au navigateur React
                await connection.send_json(data)
            except Exception:
                # Si l'envoi échoue (ex: déconnexion brutale du client),
                # on retire proprement le socket défectueux.
                self.disconnect(connection)


# Instance globale unique (Singleton) du gestionnaire WebSocket.
# Elle sera réutilisée par la route API WebSocket pour enregistrer les clients.
ws_manager = ConnectionManager()


# =============================================================================
# 2. BOUCLE D'ORCHESTRATION EN ARRIÈRE-PLAN (Background Loop)
# =============================================================================
async def run_monitoring_loop(db_session_factory):
    """
    C'est le cœur battant de NetVision.
    Cette fonction s'exécute en continu dans une boucle infinie (while True)
    exécutée en arrière-plan par FastAPI.

    Paramètre :
    - db_session_factory : La fabrique 'SessionLocal' issue de session.py.
      On passe la fabrique (et non une session unique) pour ouvrir et fermer
      proprement une session SQLite à CHAQUE SECOND. Cela évite les fuites de mémoire
      et garantit que les données restent toujours fraîches.
    """
    while True:
        try:
            # -----------------------------------------------------------------
            # ÉTAPE A : Ouverture d'un espace de travail BDD dédié à ce cycle
            # -----------------------------------------------------------------
            db: Session = db_session_factory()
            alert_repo = AlertRepository(db)
            whitelist_repo = WhitelistRepository(db)

            # -----------------------------------------------------------------
            # ÉTAPE B : Récupération des exceptions (Liste Blanche)
            # -----------------------------------------------------------------
            # On récupère le 'set' des IP et processus autorisés par l'utilisateur.
            # Recherche en complexité O(1) ultra-rapide.
            whitelisted_set = whitelist_repo.get_whitelisted_values_set()

            # -----------------------------------------------------------------
            # ÉTAPE C : Capture du trafic réseau direct (psutil + hash)
            # -----------------------------------------------------------------
            # Interroge l'OS pour récupérer toutes les connexions TCP/UDP actives
            # et applique le premier filtre via analyze_connection().
            connections: List[NetworkConnection] = get_active_connection()

            # Liste qui recevra les connexions converties pour la diffusion Web
            data_to_send = []

            # -----------------------------------------------------------------
            # ÉTAPE D : Traitement, Filtrage Liste Blanche & Sauvegarde SQLite
            # -----------------------------------------------------------------
            for conn in connections:
                # 1. Vérification si l'IP distante ou le processus est blanchi par l'utilisateur
                if conn.remote_ip in whitelisted_set or conn.process_name in whitelisted_set:
                    conn.risk_score = 0
                    conn.alerts = ["Autorisé par la liste blanche"]

                # 2. Condition de sauvegarde permanente sur le disque :
                # Seules les connexions suspectes ou anormales (score >= 35)
                # sont enregistrées dans la table 'alert_logs' de SQLite.
                if conn.risk_score >= 35:
                    alert_repo.save_alert_from_connection(conn)

                # 3. Sérialisation JSON :
                # Pydantic v2 convertit les objets datetime, int et str en un
                # dictionnaire Python compatible nativement avec la sérialisation JSON.
                data_to_send.append(conn.model_dump(mode="json"))

            # Fermeture propre de la session BDD pour ce cycle afin de libérer la RAM
            db.close()

            # -----------------------------------------------------------------
            # ÉTAPE E : Diffusion Temps Réel (WebSocket)
            # -----------------------------------------------------------------
            # Envoie l'intégralité du paquet réseau (sains + suspects)
            # à tous les onglets web connectés pour mettre à jour le graphe.
            await ws_manager.broadcast_json(data_to_send)

        except Exception as e:
            # En cas d'erreur inattendue (ex: problème de lecture système temporaire),
            # l'erreur est capturée ici pour empêcher le serveur backend de planter.
            print(f"⚠️ [MONITORING LOOP ERROR] : {e}")

        # ---------------------------------------------------------------------
        # ÉTAPE F : Pause Asynchrone (1 Seconde)
        # ---------------------------------------------------------------------
        # INDISPENSABLE : 'asyncio.sleep(1)' rend la main à la boucle d'événements de FastAPI.
        # Cela permet au serveur de traiter d'autres requêtes HTTP ou de nouveaux
        # clients WebSocket pendant ce temps de pause.
        await asyncio.sleep(1)

        r"""
        ┌──────────────────────────────────────────┐
               │  LANCEMENT DU SERVEUR FASTAPI            │
               │  (Démarre run_monitoring_loop en async)  │
               └────────────────────┬─────────────────────┘
                                    │
                                    ▼
                 ┌──────────────────────────────────────┐
                 │       BOUCLE INFINIE (while True)    │◄──────────────────────────────┐
                 └──────────────────┬───────────────────┘                               │
                                    │                                                   │
                                    ▼                                                   │
                 ┌──────────────────────────────────────┐                               │
                 │ 1. Ouverture Session SQLite          │                               │
                 │    Instanciation Repositories        │                               │
                 └──────────────────┬───────────────────┘                               │
                                    │                                                   │
                                    ▼                                                   │
                 ┌──────────────────────────────────────┐                               │
                 │ 2. Chargement de la Liste Blanche    │                               │
                 │    set = {IPs et Processus sûrs}     │                               │
                 └──────────────────┬───────────────────┘                               │
                                    │                                                   │
                                    ▼                                                   │
                 ┌──────────────────────────────────────┐                               │
                 │ 3. Scan & Analyse du Réseau          │                               │
                 │    connections = get_active_connection()                             │
                 └──────────────────┬───────────────────┘                               │
                                    │                                                   │
                                    ▼                                                   │
                  ┌───────────────────────────────────┐                                 │
                  │   POUR CHAQUE CONNEXION DÉTECTÉE  │                                 │
                  └─────────────────┬─────────────────┘                                 │
                                    │                                                   │
                                    ▼                                                   │
                    /───────────────────────────────\                                   │
                   /  IP ou Processus présent dans   \──── OUI ───► risk_score = 0      │
                   \   la Liste Blanche (set) ?      /              alert = "Autorisé"  │
                    \───────────────────────────────/                                   │
                                    │ NON                                               │
                                    ▼                                                   │
                    /───────────────────────────────\                                   │
                   /     Le risk_score est-il        \──── OUI ───► Sauvegarde SQL      │
                   \       superieur à >= 35 ?       /              dans alert_logs     │
                    \───────────────────────────────/                                   │
                                    │ NON                                               │
                                    ▼                                                   │
                 ┌──────────────────────────────────────┐                               │
                 │ Convertir la connexion en JSON       │                               │
                 │ Ajouter à la liste `data_to_send`    │                               │
                 └──────────────────┬───────────────────┘                               │
                                    │                                                   │
                                    ▼                                                   │
                 ┌──────────────────────────────────────┐                               │
                 │ 4. Fermeture propre Session SQLite   │                               │
                 └──────────────────┬───────────────────┘                               │
                                    │                                                   │
                                    ▼                                                   │
                 ┌──────────────────────────────────────┐                               │
                 │ 5. Diffusion WebSocket (Broadcast)   │                               │
                 │    Envoie JSON à tous les React UI   │                               │
                 └──────────────────┬───────────────────┘                               │
                                    │                                                   │
                                    ▼                                                   │
                 ┌──────────────────────────────────────┐                               │
                 │ 6. Pause Asynchrone (1 Seconde)      │                               │
                 │    asyncio.sleep(1)                  │───────────────────────────────┘
                 └──────────────────────────────────────┘"""