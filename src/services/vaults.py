from Cryptodome.Protocol.KDF import PBKDF2
import os
from src.models.models import Coffre
from src.database.database import SessionLocal


# Fonction permettant de créer un coffre
def create_coffre(user_id, nom_coffre, password_coffre, db_session=None):
    session = db_session or SessionLocal()
    try:
        # Hachage du mot de passe du coffre avant de le stocker
        salt = os.urandom(16)  # Utiliser un salt unique et sécurisé
        hashed_password = PBKDF2(password_coffre, salt, dkLen=32)

        # Création du coffre dans la BDD
        new_coffre = Coffre(
            nom_coffre=nom_coffre,
            password_coffre=hashed_password.hex(),  # Stocker en format hexadécimal
            id_user=user_id,
            salt=salt.hex()  # Stocker le salt en format hexadécimal
        )

        session.add(new_coffre)
        session.commit()

        return new_coffre
    except Exception as e:
        print(f"Une erreur est survenue : {e}")
        session.rollback()
        raise
    finally:
        if db_session is None:  # Ne fermez pas la session si elle est injectée
            session.close()
