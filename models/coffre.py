from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base
from services.crypto_utils import encrypt_password, decrypt_password
import os


class Coffre(Base):
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
        key = bytes.fromhex(self.salt)
        self.password_coffre = encrypt_password(password_coffre, key)
        self.user = user
        