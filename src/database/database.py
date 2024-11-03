from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./test.db"  # ou votre URL de base de données de production

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    """
    Initialise la base de données et crée toutes les tables définies dans les modèles.
    """
    # Crée les tables dans la base de données
    Base.metadata.create_all(bind=engine)
