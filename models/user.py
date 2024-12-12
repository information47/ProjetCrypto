from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from database.base import Base
from services.crypto_utils import hash_password, encrypt_password, decrypt_password
import os


class User(Base):
    """
    Représente un utilisateur dans l'application

    Attributs :
        Id_user (int) : Identifiant unique de l'utilisateur (clé primaire).
        email (str) : Adresse email unique de l'utilisateur.
        password (str) : Mot de passe haché de l'utilisateur.
        salt (str) : Sel unique utilisé pour sécuriser le hachage du mot de passe.
        coffres (list) : Relation dynamique avec les coffres appartenant à l'utilisateur.
    """

    __tablename__ = "user"
    Id_user = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, unique=True)
    password = Column(String(128), nullable=False)
    salt = Column(String(32), nullable=False)
    coffres = relationship(
        "Coffre", back_populates="user", cascade="all, delete", lazy="dynamic"
    )

    def __init__(self, email, password):
        self.email = email
        self.salt = os.urandom(16).hex()
        self.password = hash_password(password, bytes.fromhex(self.salt)).hex()

    def verify_password(self, password):
        """
        Vérifie si un mot de passe correspond au mot de passe haché stocké.

        Args :
            password (str) : Le mot de passe en clair à vérifier.

        Returns :
            bool : True si le mot de passe est correct, False sinon.
        """
        return self.password == hash_password(password, bytes.fromhex(self.salt)).hex()
