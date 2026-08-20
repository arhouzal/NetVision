from fastapi import APIRouter, Depends, Query
from app.database.session import get_db
from app.repositories.alert_repository import AlertRepository

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("/")
def get_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    protocol: str = Query(default="TOUS"),
    min_risk: int = Query(default=0, ge=0, le=100),
    db=Depends(get_db)
):
    repo = AlertRepository(db)
    alerts = repo.get_recent_alerts(limit=limit, protocol=protocol, min_risk=min_risk)

    # NB: accès par clé "alert['champ']" au lieu de "alert.champ" (sqlite3.Row)
    # NB: le timestamp est déjà une string ISO, plus besoin de .isoformat()
    return [
        {
            "id": alert["id"],
            "timestamp": alert["timestamp"],
            "level": alert["level"],
            "message": alert["message"],
            "protocol": alert["protocol"],
            "source_ip": alert["source_ip"],
            "destination_ip": alert["destination_ip"],
            "risk_score": alert["risk_score"],
            "process_name": alert["process_name"]
        }
        for alert in alerts
    ]

@router.delete("/clear")
def clear_alerts(db=Depends(get_db)):
    repo = AlertRepository(db)
    deleted_count = repo.clear_all_alerts()
    return {"status": "success", "deleted_records": deleted_count}