from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from database.base import Base
from services.crypto_utils import encrypt_password, decrypt_password
import os


class PasswordEntry(Base):
    __tablename__ = "passwordentry"

    Id_PasswordEntry = Column(Integer, primary_key=True, autoincrement=True)
    login = Column(String(255), nullable=False)
    password = Column(String(128), nullable=False)
    url = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    salt = Column(String(32), nullable=False)
    id_coffre = Column(Integer, ForeignKey("coffre.Id_coffre", ondelete="CASCADE"))
    coffre = relationship("Coffre", back_populates="password_entries")

    def __init__(self, login, password, url, name, coffre):
        self.login = login
        self.url = url
        self.name = name
        self.salt = os.urandom(16).hex()
        key = bytes.fromhex(self.salt)
        self.password = encrypt_password(password, key)
        self.coffre = coffre
