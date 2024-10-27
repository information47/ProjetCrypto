from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Déclaration de la base pour les modèles
Base = declarative_base()

# Configuration de l'URL de la base de données
DATABASE_URL = "sqlite:///./app.db"  # Pour SQLite en local, changez-le pour votre SGBD (PostgreSQL, MySQL, etc.)

# Création de l'engine SQLAlchemy
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Création d'une session pour interagir avec la base de données
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """
    Initialise la base de données et crée toutes les tables définies dans les modèles.
    """
    # Crée les tables dans la base de données
    Base.metadata.create_all(bind=engine)
