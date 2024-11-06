from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from database.base import Base
from services.crypto_utils import hash_password, encrypt_password, decrypt_password
import os


class User(Base):
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
        return self.password == hash_password(password, bytes.fromhex(self.salt)).hex()
