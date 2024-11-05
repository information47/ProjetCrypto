from database.base import session, Base, engine
from models.user import User
from models.coffre import Coffre
from models.password_entry import PasswordEntry
from services.vaults import VaultController
from services.passwordEntry import PasswordEntryController
import os
from dotenv import load_dotenv

Base.metadata.create_all(engine)

print("=== Première partie : Création des données avec la première SECRET_KEY ===")

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

print(
    "Vérif des mots de passe de user1 avec la première SECRET_KEY :",
    user1.verify_password("mdp_user"),
)


try:
    decrypt_coffre1 = vault_manager.unlock_coffre("mdp_coffre1")  
    print("Coffre1 déverrouillé avec la clé de base :", decrypt_coffre1)
except ValueError as ve:
    print("Erreur lors du déverrouillage de coffre1 :", ve)


os.environ["SECRET_KEY"] = "nouvelle_secret_key"
load_dotenv()

print("\n=== Deuxième partie : Test de déverrouillage du nouveau coffre ===")

new_coffre1 = Coffre(nom_coffre="coffre2", password_coffre="mdp_coffre2", user=user1)
session.add(new_coffre1)

try:
    session.commit()
    print("Nouveau coffre ajouté avec la nouvelle SECRET_KEY")
except Exception as e:
    session.rollback()
    print("Erreur lors de l'ajout du nouveau coffre :", e)


try:
    decrypt_coffre2 = vault_manager.unlock_coffre("mdp_coffre2")  
    print("Coffre2 déverrouillé avec la nouvelle SECRET_KEY :", decrypt_coffre2)
except ValueError as ve:
    print("Erreur lors du déverrouillage de coffre2 :", ve)
