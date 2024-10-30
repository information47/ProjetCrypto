from crypto.Cipher import AES
from crypto.Protocol.KDF import PBKDF2
from src.models.models import PasswordEntry
from src.database.database import SessionLocal


#Ajout d'un passwordEntry dans un coffre
def add_password_entry(coffre, login, password, url="", name=""):
    # Chiffrement du mot de passe
    key = PBKDF2(coffre.password_coffre, b'unique_salt_for_aes', dkLen=32)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())

    # Stockage de l'entrée dans la BDD
    new_entry = PasswordEntry(
        login=login,
        password=ciphertext,  # Le mot de passe chiffré
        url=url,
        name=name,
        id_coffre=coffre.id
    )

    session = SessionLocal()
    session.add(new_entry)
    session.commit()
    session.close()
    return new_entry
