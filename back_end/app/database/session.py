from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

# Emplacement du fichier SQLite local
DATABASE_URL = "sqlite:///./netvision.db"

# 1. Moteur SQLAlchemy
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# 2. Activation du mode WAL (Write-Ahead Logging) pour des accès simultanés ultra-rapides
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

# 3. Fabrique de sessions pour interagir avec la BDD
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 4. Classe parente pour la déclaration des modèles
Base = declarative_base()

def get_db():
    """Dépendance FastAPI : Ouvre une session BDD et la ferme proprement après la requête."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --------------- l equivalence en etulisant des requete SQL simple avec le moteur sqlite3 

"""import sqlite3

DATABASE_PATH = "netvision.db"

def get_db_connection():
    Ouvre une connexion directe au fichier SQLite.
    # Connexion au fichier SQLite
    conn = sqlite3.connect(DATABASE_PATH)
    
    # Permet d'accéder aux colonnes par leur nom (ex: row['message']) au lieu de leur index (row[0])
    conn.row_factory = sqlite3.Row
    
    # Activation du mode WAL pour la vitesse
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    
    return conn"""