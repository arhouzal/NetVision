import sqlite3
from app.schemas.connection import NetworkConnection


class AlertRepository:
    """
    Gestionnaire des opérations SQLite pour le journal des alertes,
    en SQL brut (plus de couche ORM).
    """

    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def save_alert_from_connection(self, connection: NetworkConnection) -> int:
        if connection.risk_score >= 70:
            level = "ALERT"
        elif connection.risk_score >= 35:
            level = "WARN"
        else:
            level = "INFO"

        message_str = " | ".join(connection.alerts) if connection.alerts else "Activité réseau enregistrée"

        cursor = self.db.cursor()
        cursor.execute(
            """
            INSERT INTO alert_logs
                (timestamp, level, message, protocol, source_ip, destination_ip, risk_score, process_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                connection.timestamp.isoformat(),
                level,
                message_str,
                connection.protocol,
                f"{connection.local_ip}:{connection.local_port}",
                f"{connection.remote_ip}:{connection.remote_port}",
                connection.risk_score,
                connection.process_name,
            ),
        )
        self.db.commit()
        return cursor.lastrowid

    def get_recent_alerts(self, limit: int = 50, protocol: str = None, min_risk: int = None):
        query = "SELECT * FROM alert_logs WHERE 1=1"
        params = []

        if protocol and protocol.upper() != "TOUS":
            query += " AND protocol = ?"
            params.append(protocol.upper())

        if min_risk is not None:
            query += " AND risk_score >= ?"
            params.append(min_risk)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor = self.db.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()  # liste de sqlite3.Row

    def clear_all_alerts(self) -> int:
        cursor = self.db.cursor()
        cursor.execute("SELECT COUNT(*) FROM alert_logs")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM alert_logs")
        self.db.commit()
        return count