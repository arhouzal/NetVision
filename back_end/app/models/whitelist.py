from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from app.database.session import Base

class WhitelistModel(Base):
    __tablename__ = "whitelist_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_type = Column(String)                      # "IP" ou "PROCESS"
    value = Column(String, unique=True, index=True)  # Ex: "8.8.8.8" ou "chrome.exe"
    description = Column(String, nullable=True)      # Ex: "Serveur DNS Google"
    created_at = Column(DateTime, default=datetime.now)

    #Rôle : Définir le plan de la table qui stockera 
    # les autorisations/exceptions (pour le menu Paramètres).
    #Pour enregistrer ce qui est sûr et autorisé par l'utilisateur (Gestion des exceptions dans Paramètres).