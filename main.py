from database.base import session, Base, engine
from models.user import User
from models.coffre import Coffre
from models.password_entry import PasswordEntry

Base.metadata.create_all(engine)

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

coffre1.add_password_entry(password_entry1)
coffre1.add_password_entry(password_entry2)
user1.coffres.append(coffre1)

session.add(user1)

try:
    session.commit()
    print("Utilisateur, coffres et mdp ajoutés")
except Exception as e:
    session.rollback()
    print("Erreur lors de l'ajout des données :", e)

print("Vérif des mots de passe de user1 :", user1.verify_password("mdp_user"))

try:
    decrypted_entries = coffre1.unlock_coffre("mdp_coffre1")
    print("Coffre déverrouillé :", decrypted_entries)
except ValueError as ve:
    print("Erreur :", ve)
