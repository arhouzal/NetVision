from sqlalchemy.orm import Session
from app.models.alert import AlertModel
from app.schemas.connection import NetworkConnection


class AlertRepository:
    """
    Gestionnaire des opérations de base de données pour le journal des alertes.
    Permet de sauvegarder les connexions suspectes et d'interroger l'historique SQL.
    """

    def __init__(self, db: Session):
        # Sauvegarde la session BDD SQLite active
        self.db = db

    def save_alert_from_connection(self, connection: NetworkConnection) -> AlertModel:
        """
        Transforme une NetworkConnection (Pydantic) en une ligne de BDD (AlertModel)
        et la sauvegarde dans la table 'alert_logs' de SQLite.
        """
        # 1. Détermination du niveau de gravité pour l'interface visuelle
        if connection.risk_score >= 70:
            level = "ALERT"
        elif connection.risk_score >= 35:
            level = "WARN"
        else:
            level = "INFO"

        # 2. Concaténation des messages d'alertes générés par l'analyseur
        message_str = " | ".join(connection.alerts) if connection.alerts else "Activité réseau enregistrée"

        # 3. Création de l'objet de base de données SQLAlchemy
        db_alert = AlertModel(
            level=level,
            message=message_str,
            protocol=connection.protocol,
            source_ip=f"{connection.local_ip}:{connection.local_port}",
            destination_ip=f"{connection.remote_ip}:{connection.remote_port}",
            risk_score=connection.risk_score,
            process_name=connection.process_name,
        )

        # 4. Écriture dans SQLite et validation
        self.db.add(db_alert)
        self.db.commit()
        self.db.refresh(db_alert)
        return db_alert

    def get_recent_alerts(
        self, limit: int = 50, protocol: str = None, min_risk: int = None
    ) -> list[AlertModel]:
        """
        Récupère les dernières alertes enregistrées pour alimenter
        le tableau 'Journal des événements' de l'interface React.
        """
        query = self.db.query(AlertModel)

        # Filtre optionnel par protocole (TCP ou UDP)
        if protocol and protocol.upper() != "TOUS":
            query = query.filter(AlertModel.protocol == protocol.upper())

        # Filtre optionnel par niveau de risque minimal
        if min_risk is not None:
            query = query.filter(AlertModel.risk_score >= min_risk)

        # Tri des plus récentes aux plus anciennes avec limite du nombre de lignes
        return query.order_by(AlertModel.timestamp.desc()).limit(limit).all()

    def clear_all_alerts(self) -> int:
        """Vide le journal d'alertes en BDD (Action du bouton 'EFFACER' du dashboard)."""
        deleted_count = self.db.query(AlertModel).delete()
        self.db.commit()
        return deleted_count