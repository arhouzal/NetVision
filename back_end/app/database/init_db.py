from app.database.session import engine, Base
from app.models.alert import AlertModel
from app.models.whitelist import WhitelistModel

def init_db():
    # Lit les fichiers models/ et crée les tables dans le fichier netvision.db
    Base.metadata.create_all(bind=engine)
    print("✅ Le fichier 'netvision.db' et les tables ont été créés avec succès !")

if __name__ == "__main__":
    init_db()