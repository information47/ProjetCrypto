from base import session, User, Coffre, PasswordEntry

existing_user = session.query(User).filter_by(email="test@et.esiea.fr").first()
if existing_user:
    raise ValueError("L'utilisateurex existe déjà")

user = User(email="test@et.esiea.fr", password="mdp")


existing_coffre = (
    session.query(Coffre).filter_by(nom_coffre="coffre", id_user=user.Id_user).first()
)
if existing_coffre:
    raise ValueError("Le coffre existe déjà pour cet utilisateur.")


coffre = Coffre(nom_coffre="coffre", password_coffre="coffre1", user=user)
user.coffres.append(coffre)


existing_password_entry = (
    session.query(PasswordEntry)
    .filter_by(login="mdp1", id_coffre=coffre.Id_coffre)
    .first()
)
if existing_password_entry:
    raise ValueError("L'entrée de mot de passe existe déjà dans ce coffre.")


password_entry = PasswordEntry(
    login="mdp1", password="mdp1", url="http://esiea.fr", name="école", coffre=coffre
)
coffre.password_entries.append(password_entry)


session.add(user)

try:
    session.commit()
    print("Données insérées")
except Exception as e:
    session.rollback()
    print("Erreur ")

print(user)
print(coffre)
print(password_entry)
