from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import relationship, sessionmaker, declarative_base
import os
from dotenv import load_dotenv
import mysql.connector

load_dotenv()

try:
    db_host = os.getenv("DB_HOST")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME")
    connection = mysql.connector.connect(
        host=db_host, 
        user=db_user, 
        password=db_password, 
        database=db_name
    )
    print("Connexion réussie à la bdd")
    connection.close()
except mysql.connector.Error as err:
    print("Erreur", err)
    exit(1)

Base = declarative_base()


class User(Base):
    __tablename__ = "User"
    Id_user = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), nullable=False, unique=True)
    password = Column(String(128), nullable=False)
    coffres = relationship("Coffre", back_populates="user", cascade="all, delete")


class Coffre(Base):
    __tablename__ = "Coffre"
    Id_coffre = Column(Integer, primary_key=True, autoincrement=True)
    nom_coffre = Column(String(255), nullable=False)
    password_coffre = Column(String(128))
    id_user = Column(Integer, ForeignKey("User.Id_user", ondelete="CASCADE"))
    user = relationship("User", back_populates="coffres")
    password_entries = relationship(
        "PasswordEntry", back_populates="coffre", cascade="all, delete"
    )


class PasswordEntry(Base):
    __tablename__ = "PasswordEntry"
    Id_PasswordEntry = Column(Integer, primary_key=True, autoincrement=True)
    login = Column(String(255))
    password = Column(String(128))
    url = Column(String(255))
    name = Column(String(255))
    id_coffre = Column(Integer, ForeignKey("Coffre.Id_coffre", ondelete="CASCADE"))
    coffre = relationship("Coffre", back_populates="password_entries")


engine = create_engine(
    f"mysql+mysqlconnector://{db_user}:{db_password}@{db_host}/{db_name}", echo=True
)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()
