from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from src.database.database import Base

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    coffres = relationship("Coffre", back_populates="user")

class Coffre(Base):
    __tablename__ = 'coffres'
    id = Column(Integer, primary_key=True)
    nom_coffre = Column(String, nullable=False)
    password_coffre = Column(String, nullable=False)  # Haché avec PBKDF2
    id_user = Column(Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="coffres")
    entries = relationship("PasswordEntry", back_populates="coffre")

class PasswordEntry(Base):
    __tablename__ = 'password_entries'
    id = Column(Integer, primary_key=True)
    login = Column(String)
    password = Column(String)  # Chiffré avec AES
    url = Column(String)
    name = Column(String)
    id_coffre = Column(Integer, ForeignKey('coffres.id'))
    coffre = relationship("Coffre", back_populates="entries")