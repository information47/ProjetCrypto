from crypto.Protocol.KDF import PBKDF2
from src.models.models import Coffre
from src.database.database import SessionLocal

#Fonction permettant de créer un coffre
def create_coffre(user_id, nom_coffre, password_coffre):
    # Hachage du mot de passe du coffre avant de le stocker
    salt = b'unique_salt'  # Utiliser un salt unique pour chaque utilisateur/coffre en production
    hashed_password = PBKDF2(password_coffre, salt, dkLen=32)

    # Création du coffre dans la BDD
    new_coffre = Coffre(
        nom_coffre=nom_coffre,
        password_coffre=hashed_password,
        id_user=user_id
    )

    session = SessionLocal()
    session.add(new_coffre)
    session.commit()
    session.close()
    return new_coffre
