from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from app.database.session import Base

class AlertModel(Base):
    """Représentation de la table 'alert_logs' en base de données."""
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.now)
    level = Column(String, index=True)      # INFO, WARN, ALERT
    message = Column(String)                # Ex: "Flux UDP suspect"
    protocol = Column(String)               # TCP, UDP, DNS
    source_ip = Column(String)              # Ex: 192.168.1.10:55231
    destination_ip = Column(String)         # Ex: 185.220.101.5:443
    risk_score = Column(Integer)            # Note de 0 à 100
    process_name = Column(String)           # Ex: chrome.exe

    #Rôle : Définir le plan de la table qui va stocker le Journal des Événements (en bas du dashboard).