from database.base import session, Base, engine
from models.user import User
from models.coffre import Coffre
from models.password_entry import PasswordEntry
from services.vaults import VaultController
import os
from dotenv import load_dotenv

Base.metadata.create_all(engine)

print("=== Première partie : Création des données avec la première SECRET_KEY ===")


os.environ["SECRET_KEY"]
load_dotenv()


user1 = User(email="test@et.esiea.fr", password="mdp_user")
coffre1 = Coffre(nom_coffre="coffre1", password_coffre="mdp_coffre1", user=user1)


password_entry1 = PasswordEntry(
    login="login1",
    password="mdp_entry1",
    url="http://esiea.fr",
    name="école",
    coffre=coffre1,
)

password_entry2 = PasswordEntry(
    login="login2",
    password="mdp_entry2",
    url="http://esiea.fr",
    name="perso",
    coffre=coffre1,
)


vault_manager = VaultController(coffre1)
vault_manager.add_password_entry(password_entry1)
vault_manager.add_password_entry(password_entry2)


user1.coffres.append(coffre1)
session.add(user1)

try:
    session.commit()
    print("Utilisateur, coffres et mdp ajoutés")
except Exception as e:
    session.rollback()
    print("Erreur lors de l'ajout des données :", e)


try:
    decrypt_coffre1 = vault_manager.unlock_coffre("mdp_coffre1")
    print("Coffre1 déverrouillé avec la clé de base :", decrypt_coffre1)
except ValueError as ve:
    print("Erreur lors du déverrouillage de coffre1 :", ve)


os.environ["SECRET_KEY"] = "key2"
load_dotenv()


print("Valeur de la SECRET_KEY :", os.getenv("SECRET_KEY"))

print(
    "\n=== Deuxième partie : Test de déverrouillage de coffre1 avec la nouvelle SECRET_KEY ==="
)

try:
    decrypt_coffre1_with_new_key = vault_manager.unlock_coffre("mdp_coffre1")

    print(
        "Coffre1 déverrouillé avec la nouvelle SECRET_KEY :",
        decrypt_coffre1_with_new_key,
    )
except Exception as e:
    print(
        "Erreur lors du déverrouillage de coffre1 avec la nouvelle SECRET_KEY :", str(e)
    )