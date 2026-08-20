import sqlite3
from datetime import datetime


class WhitelistRepository:
    """Gestionnaire des règles de liste blanche en SQL brut."""

    def __init__(self, db: sqlite3.Connection):
        self.db = db

    def get_all_rules(self):
        cursor = self.db.cursor()
        cursor.execute("SELECT * FROM whitelist_rules ORDER BY id DESC")
        return cursor.fetchall()

    def get_whitelisted_values_set(self) -> set[str]:
        cursor = self.db.cursor()
        cursor.execute("SELECT value FROM whitelist_rules")
        return {row["value"] for row in cursor.fetchall()}

    def add_rule(self, rule_type: str, value: str, description: str = None) -> int:
        cursor = self.db.cursor()
        cursor.execute(
            """
            INSERT INTO whitelist_rules (rule_type, value, description, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (rule_type.upper(), value, description, datetime.now().isoformat()),
        )
        self.db.commit()
        return cursor.lastrowid

    def delete_rule(self, rule_id: int) -> bool:
        cursor = self.db.cursor()
        cursor.execute("SELECT id FROM whitelist_rules WHERE id = ?", (rule_id,))
        if cursor.fetchone() is None:
            return False
        cursor.execute("DELETE FROM whitelist_rules WHERE id = ?", (rule_id,))
        self.db.commit()
        return True