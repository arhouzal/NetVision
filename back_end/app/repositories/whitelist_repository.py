""" 
Ce fichier applique ce qu'on appelle le Repository Pattern (Patron de Conception Dépôt).

Son rôle est de centraliser toutes les requêtes SQL liées à la liste blanche (table whitelist_rules). 
Plutôt que d'écrire des requêtes SQLAlchemy dispersées partout dans le projet,
on regroupe toutes les opérations (Ajouter, Lire, Supprimer une règle) dans une seule classe propre.
"""

from sqlalchemy.orm import Session # importe session pour indiquer a python que l'objet qu'on va manipuler est une session active de base de données

from app.models.whitelist import WhitelistModel # importer la classe qui represente la table whitelist_rules dans la base sqlite

class WhitelistRepository:
    """Gestionnaire des règles de liste blanche (exceptions) en base de données."""

    def __init__(self, db: Session):
        self.db = db

    def get_all_rules(self) -> list[WhitelistModel]:
        """Récupère l'ensemble des règles enregistrées."""
        return self.db.query(WhitelistModel).all()

    def get_whitelisted_values_set(self) -> set[str]:
        """
        Retourne un ensemble (set) contenant toutes les IPs et processus autorisés.
        Permet une recherche ultra-rapide O(1) dans l'analyseur.
        """
        rules = self.db.query(WhitelistModel.value).all()
        return {r[0] for r in rules}

    def add_rule(self, rule_type: str, value: str, description: str = None) -> WhitelistModel:
        """Ajoute une nouvelle règle de confiance (ex: rule_type='IP', value='8.8.8.8')."""
        rule = WhitelistModel(
            rule_type=rule_type.upper(),
            value=value,
            description=description
        )
        self.db.add(rule)
        self.db.commit()
        self.db.refresh(rule)
        return rule

    def delete_rule(self, rule_id: int) -> bool:
        """Supprime une règle par son ID."""
        rule = self.db.query(WhitelistModel).filter(WhitelistModel.id == rule_id).first()
        if rule:
            self.db.delete(rule)
            self.db.commit()
            return True
        return False
