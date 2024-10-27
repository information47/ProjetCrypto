import os

class Config:
    SECRET_KEY = os.urandom(24)  # Pour la sécurité des sessions Flask
    SQLALCHEMY_DATABASE_URI = 'sqlite:///password_manager.db'  # Base de données SQLite pour le développement
    SQLALCHEMY_TRACK_MODIFICATIONS = False
