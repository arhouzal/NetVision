from fastapi import APIRouter, WebSocket,WebSocketDisconnect
from app.services.monitring_service import ws_manager


router = APIRouter()

@router.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    """
    Point d'entrée WebSocket. Le navigateur s'y connecte au chargement du tableau de bord.
    """
    await ws_manager.connect(websocket)
    try:
        # Maintient la connexion ouverte en attente d'événements
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)