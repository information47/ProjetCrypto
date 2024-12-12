from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base
from services.crypto_utils import hash_password
import os
from models.password_entry import PasswordEntry


class Coffre(Base):
    """
    Représente un coffre-fort dans la base de données, associé à un utilisateur et contenant plusieurs entrées de mots de passe.

    Attributs :
        Id_coffre (int) : Identifiant unique du coffre (clé primaire).
        nom_coffre (str) : Nom du coffre.
        password_coffre (str) : Mot de passe du coffre, haché et sécurisé.
        salt (str) : Sel utilisé pour sécuriser le hachage du mot de passe.
        id_user (int) : Identifiant de l'utilisateur propriétaire du coffre (clé étrangère).
        user (User) : Relation avec l'utilisateur propriétaire.
        password_entries (list[PasswordEntry]) : Liste des entrées de mots de passe associées à ce coffre.
    """

    __tablename__ = "coffre"

    Id_coffre = Column(Integer, primary_key=True, autoincrement=True)
    nom_coffre = Column(String(255), nullable=False)
    password_coffre = Column(String(128), nullable=False)
    salt = Column(String(32), nullable=False)
    id_user = Column(Integer, ForeignKey("user.Id_user", ondelete="CASCADE"))
    user = relationship("User", back_populates="coffres")
    password_entries = relationship(
        "PasswordEntry", back_populates="coffre", cascade="all, delete"
    )

    def __init__(self, nom_coffre, password_coffre, user):
        self.nom_coffre = nom_coffre
        self.salt = os.urandom(16).hex()
        self.password_coffre = hash_password(
            password_coffre, bytes.fromhex(self.salt)
        ).hex()
        self.user = user

    def verify_password(self, password):
        """
        Vérifie si un mot de passe donné correspond au mot de passe haché du coffre.

        Args :
            password (str) : Le mot de passe en clair à vérifier.

        Returns :
            bool : True si le mot de passe correspond, False sinon.
        """
        return (
            self.password_coffre
            == hash_password(password, bytes.fromhex(self.salt)).hex()
        )
