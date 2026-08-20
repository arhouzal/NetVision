import sqlite3
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from app.database.session import get_db
from app.repositories.whitelist_repository import WhitelistRepository

router = APIRouter(prefix="/whitelist", tags=["Whitelist"])

class WhitelistCreateSchema(BaseModel):
    rule_type: str
    value: str
    description: str = None

@router.get("/")
def get_whitelist_rules(db=Depends(get_db)):
    repo = WhitelistRepository(db)
    rules = repo.get_all_rules()
    return [
        {
            "id": rule["id"],
            "rule_type": rule["rule_type"],
            "value": rule["value"],
            "description": rule["description"],
            "created_at": rule["created_at"]
        }
        for rule in rules
    ]

@router.post("/", status_code=status.HTTP_201_CREATED)
def add_whitelist_rule(payload: WhitelistCreateSchema, db=Depends(get_db)):
    repo = WhitelistRepository(db)
    try:
        new_id = repo.add_rule(
            rule_type=payload.rule_type,
            value=payload.value,
            description=payload.description
        )
    except sqlite3.IntegrityError:
        # value est UNIQUE dans la table -> doublon
        raise HTTPException(status_code=400, detail="Cette règle existe déjà.")
    return {"status": "success", "id": new_id}

@router.delete("/{rule_id}")
def delete_whitelist_rule(rule_id: int, db=Depends(get_db)):
    repo = WhitelistRepository(db)
    success = repo.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Règle introuvable")
    return {"status": "success", "message": f"Règle {rule_id} supprimée"}