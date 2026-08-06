import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.session import engine, SessionLocal
from app.database.session import Base
from app.services.monitring_service import run_monitoring_loop

from app.api.v1.websocket import router as ws_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.whitelist import router as whitelist_router
from app.api.v1.process import router as process_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestionnaire de cycle de vie de l'application.
    Exécuté automatiquement au démarrage et à l'arrêt du serveur FastAPI.
    """
    # 1. Création automatique des tables SQLite si elles n'existent pas
    Base.metadata.create_all(bind=engine)
    
    # 2. Lancement de la boucle de scan réseau en tâche de fond (Background Task)
    monitoring_task = asyncio.create_task(run_monitoring_loop(SessionLocal))
    
    yield  # Le serveur tourne et traite les requêtes
    
    # 3. Arrêt propre de la tâche de fond à la fermeture du serveur
    monitoring_task.cancel()


# Initialisation de FastAPI avec le gestionnaire de cycle de vie
app = FastAPI(
    title="NetVision Security Engine API",
    version="1.0.0",
    lifespan=lifespan
)

# Configuration CORS (Indispensable pour autoriser React à contacter FastAPI)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, spécifier l'URL exacte du Frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enregistrement des routes dans l'application
app.include_router(ws_router)
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(whitelist_router, prefix="/api/v1")
app.include_router(process_router, prefix="/api/v1")

@app.get("/")
def health_check():
    """Vérification de l'état de santé de l'API."""
    return {"status": "online", "system": "NetVision Backend Core"}




