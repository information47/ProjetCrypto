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

    def verify_password_coffre(self, password_coffre):
        key = bytes.fromhex(self.salt)
        decrypted_password = decrypt_password(self.password_coffre, key)
        return decrypted_password == password_coffre

    def add_password_entry(self, password_entry):
        self.password_entries.append(password_entry)

    def unlock_coffre(self, password_coffre):
        if not self.verify_password_coffre(password_coffre):
            raise ValueError("Mot de passe du coffre incorrect")

        decrypted_entries = []

        for entry in self.password_entries:
            try:
                entry_key = bytes.fromhex(entry.salt)
                decrypted_password = decrypt_password(entry.password, entry_key)
                decrypted_entries.append(
                    {
                        "login": entry.login,
                        "password": decrypted_password,
                        "url": entry.url,
                        "name": entry.name,
                    }
                )
            except Exception as e:
                print(f"Erreur lors du déchiffrement de l'entrée {entry.name} :", e)

        return decrypted_entries