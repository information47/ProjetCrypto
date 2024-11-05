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
        host=db_host, user=db_user, password=db_password, database=db_name
    )
    print("Connexion réussie à la bdd")
    connection.close()
except mysql.connector.Error as err:
    print("Erreur", err)
    exit(1)

Base = declarative_base()

engine = create_engine(
    f"mysql+mysqlconnector://{db_user}:{db_password}@{db_host}/{db_name}", echo=True
)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()
