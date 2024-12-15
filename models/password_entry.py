import os

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

from database.base import Base
from services.crypto_utils import encrypt_password


class PasswordEntry(Base):
    """
    Représente une entrée de mot de passe stockée dans un coffre-fort.

    Attributs :
        Id_PasswordEntry (int) : Identifiant unique de l'entrée (clé primaire).
        login (str) : Identifiant associé à l'entrée (par exemple, un nom d'utilisateur).
        password (str) : Mot de passe chiffré.
        url (str) : URL ou ressource associée à l'entrée.
        name (str) : Nom ou étiquette de l'entrée.
        salt (str) : Sel utilisé pour générer la clé de chiffrement.
        id_coffre (int) : Identifiant du coffre auquel appartient cette entrée (clé étrangère).
        coffre (Coffre) : Relation avec le coffre propriétaire.
    """

    __tablename__ = "passwordentry"

    Id_PasswordEntry = Column(Integer, primary_key=True, autoincrement=True)
    login = Column(String(255), nullable=False)
    password = Column(String(128), nullable=False)
    url = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    salt = Column(String(32), nullable=False)
    id_coffre = Column(Integer, ForeignKey("coffre.Id_coffre", ondelete="CASCADE"))
    coffre = relationship("Coffre", back_populates="password_entries")

    def __init__(self, login, password, url, name, coffre, salt=None):
        self.login = login
        self.url = url
        self.name = name
        self.salt = salt or os.urandom(16).hex()
        key = bytes.fromhex(self.salt)
        self.password = encrypt_password(password, key)
        self.coffre = coffre
