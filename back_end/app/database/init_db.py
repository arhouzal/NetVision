from app.database.session import get_connection


def init_db():
    """
    Crée les tables SQLite si elles n'existent pas encore.
    Remplace Base.metadata.create_all() de SQLAlchemy.
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT,
            message TEXT,
            protocol TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            risk_score INTEGER,
            process_name TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_level ON alert_logs(level)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alert_logs(timestamp)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT,
            value TEXT UNIQUE,
            description TEXT,
            created_at TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_whitelist_value ON whitelist_rules(value)")

    conn.commit()
    conn.close()
    print("✅ Le fichier 'netvision.db' et les tables ont été créés avec succès !")


if __name__ == "__main__":
    init_db()