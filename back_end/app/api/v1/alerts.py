from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.repositories.alert_repository import AlertRepository

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("/")
def get_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    protocol: str = Query(default="TOUS"),
    min_risk: int = Query(default=0, ge=0, le=100),
    db: Session = Depends(get_db)
):
    """
    Récupère les alertes sauvegardées dans SQLite avec filtres optionnels.
    """
    repo = AlertRepository(db)
    alerts = repo.get_recent_alerts(limit=limit, protocol=protocol, min_risk=min_risk)
    
    return [
        {
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat(),
            "level": alert.level,
            "message": alert.message,
            "protocol": alert.protocol,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "risk_score": alert.risk_score,
            "process_name": alert.process_name
        }
        for alert in alerts
    ]

@router.delete("/clear")
def clear_alerts(db: Session = Depends(get_db)):
    """
    Vide intégralement la table des alertes (Bouton 'EFFACER LOGS' dans l'UI).
    """
    repo = AlertRepository(db)
    deleted_count = repo.clear_all_alerts()
    return {"status": "success", "deleted_records": deleted_count}