import sqlite3

# Emplacement du fichier SQLite local
DATABASE_PATH = "netvision.db"


def get_connection() -> sqlite3.Connection:
    """
    Crée une connexion SQLite brute avec les réglages de performance
    (équivalent des anciens event listeners SQLAlchemy).
    """
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)

    # Permet d'accéder aux colonnes par leur nom (ex: row["message"])
    # au lieu de leur position (row[0]) -> équivalent du confort de l'ORM
    conn.row_factory = sqlite3.Row

    # Mode WAL (Write-Ahead Logging) pour des accès concurrents rapides
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    return conn


def get_db():
    """
    Dépendance FastAPI : ouvre une connexion SQLite et la ferme
    proprement après la requête (remplace l'ancienne SessionLocal).
    """
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()