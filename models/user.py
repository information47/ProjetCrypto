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
    coffres = relationship("Coffre", back_populates="user", cascade="all, delete")

    def __init__(self, email, password):
        self.email = email
        self.salt = os.urandom(16).hex()
        key = hash_password(password, bytes.fromhex(self.salt))
        self.password = encrypt_password(password, key)

    def verify_password(self, password):
        key = hash_password(password, bytes.fromhex(self.salt))
        decrypted_password = decrypt_password(self.password, key)
        return decrypted_password == password
