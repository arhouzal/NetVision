from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.repositories.whitelist_repository import WhitelistRepository

router = APIRouter(prefix="/whitelist", tags=["Whitelist"])

# Schéma de validation pour l'ajout d'une règle
class WhitelistCreateSchema(BaseModel):
    rule_type: str  # "IP" ou "PROCESS"
    value: str      # Ex: "8.8.8.8" ou "chrome.exe"
    description: str = None

@router.get("/")
def get_whitelist_rules(db: Session = Depends(get_db)):
    """
    Renvoie toutes les règles d'exception enregistrées.
    """
    repo = WhitelistRepository(db)
    rules = repo.get_all_rules()
    return [
        {
            "id": rule.id,
            "rule_type": rule.rule_type,
            "value": rule.value,
            "description": rule.description,
            "created_at": rule.created_at.isoformat()
        }
        for rule in rules
    ]

@router.post("/", status_code=status.HTTP_201_CREATED)
def add_whitelist_rule(payload: WhitelistCreateSchema, db: Session = Depends(get_db)):
    """
    Ajoute une nouvelle règle de confiance (ex: ignorer une IP ou un programme).
    """
    repo = WhitelistRepository(db)
    new_rule = repo.add_rule(
        rule_type=payload.rule_type,
        value=payload.value,
        description=payload.description
    )
    return {"status": "success", "id": new_rule.id}

@router.delete("/{rule_id}")
def delete_whitelist_rule(rule_id: int, db: Session = Depends(get_db)):
    """
    Supprime une règle par son ID.
    """
    repo = WhitelistRepository(db)
    success = repo.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Règle introuvable")
    return {"status": "success", "message": f"Règle {rule_id} supprimée"}