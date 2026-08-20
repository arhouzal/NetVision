import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.session import get_connection
from app.database.init_db import init_db
from app.services.monitring_service import run_monitoring_loop

from app.api.v1.websocket import router as ws_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.whitelist import router as whitelist_router
from app.api.v1.process import router as process_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Création automatique des tables SQLite si elles n'existent pas
    init_db()

    # 2. Lancement de la boucle de scan réseau (on lui passe la factory de connexion)
    monitoring_task = asyncio.create_task(run_monitoring_loop(get_connection))

    yield

    monitoring_task.cancel()


app = FastAPI(
    title="NetVision Security Engine API",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ws_router)
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(whitelist_router, prefix="/api/v1")
app.include_router(process_router, prefix="/api/v1")

@app.get("/")
def health_check():
    return {"status": "online", "system": "NetVision Backend Core"}